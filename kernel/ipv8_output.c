// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ipv8_output.c - IPv8 packet transmit path
 *
 * Provides ipv8_output(), which accepts a fully-built sk_buff whose
 * skb->data points at the IPv8 header, resolves the next-hop via
 * neighbour lookup (ARP/NDP), and hands the frame to the device queue.
 *
 * In this PoC the routing table is minimal: a v4-compat destination is
 * sent via the IPv4 routing table (after XLATE8); all other packets are
 * sent as raw Ethernet frames on the first non-loopback device that has
 * a matching route entry in the ipv8_route table (configurable via
 * /proc/net/ipv8_route – future).
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/neighbour.h>
#include <net/net_namespace.h>
#include <net/arp.h>

#include "ipv8.h"

/* ------------------------------------------------------------------ *
 * Simple static route table
 * ------------------------------------------------------------------ */

/**
 * struct ipv8_route - one entry in the static route table
 * @asn_prefix: destination ASN prefix this route covers
 * @gateway:    IPv4 next-hop address to use for ARP/neighbour lookup
 * @dev_name:   output interface name
 * @node:       list linkage
 */
struct ipv8_route {
    struct in8_addr  prefix;
    __be32           gateway;       /* IPv4 gateway for neighbour lookup */
    char             dev_name[IFNAMSIZ];
    struct list_head node;
    struct rcu_head  rcu;
};

static LIST_HEAD(ipv8_route_list);
static DEFINE_SPINLOCK(ipv8_route_lock);

/* Statistics */
static atomic_long_t stat_tx_packets;
static atomic_long_t stat_tx_dropped;

/* ------------------------------------------------------------------ *
 * Route lookup
 * ------------------------------------------------------------------ */

/**
 * ipv8_route_lookup - find the best static route for a destination
 *
 * Returns the matching route entry under RCU read lock (caller must hold
 * rcu_read_lock()), or NULL if none found.
 *
 * For a PoC we do a simple linear search; a trie or longest-prefix-match
 * structure would be used in production.
 */
static struct ipv8_route *ipv8_route_lookup(const struct in8_addr *dst)
{
    struct ipv8_route *rt;

    list_for_each_entry_rcu(rt, &ipv8_route_list, node) {
        if (rt->prefix.asn == dst->asn)
            return rt;
    }
    return NULL;
}

/* ------------------------------------------------------------------ *
 * Neighbour (ARP) resolution
 * ------------------------------------------------------------------ */

static int ipv8_neigh_output(struct sk_buff *skb, struct net_device *dev,
                              __be32 nexthop_v4)
{
    struct rtable *rt;
    struct flowi4 fl4;
    struct neighbour *neigh;
    int err;

    /* Obtain an IPv4 route just for the ARP/neighbour entry */
    memset(&fl4, 0, sizeof(fl4));
    fl4.daddr = nexthop_v4;
    fl4.flowi4_oif = dev->ifindex;

    rt = ip_route_output_key(dev_net(dev), &fl4);
    if (IS_ERR(rt))
        return PTR_ERR(rt);

    neigh = dst_neigh_lookup(&rt->dst, &nexthop_v4);
    ip_rt_put(rt);

    if (!neigh)
        return -EHOSTUNREACH;

    /* Hand the skb to the neighbour output handler; it will prepend the
     * Ethernet header using the resolved MAC address. */
    skb->dev      = dev;
    skb->protocol = htons(ETH_P_IPV8);

    err = neigh_output(neigh, skb, false);
    neigh_release(neigh);
    return err;
}

/* ------------------------------------------------------------------ *
 * Main output entry point
 * ------------------------------------------------------------------ */

/**
 * ipv8_output - transmit an IPv8 packet
 * @net: network namespace
 * @sk:  originating socket (may be NULL for forwarded packets)
 * @skb: packet with IPv8 header at skb->data
 *
 * Returns 0 on success, negative errno on failure.
 */
int ipv8_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct ipv8hdr *hdr = (struct ipv8hdr *)skb->data;
    struct ipv8_route *rt;
    struct net_device *dev;
    __be32 nexthop;
    int err = -EHOSTUNREACH;

    atomic_long_inc(&stat_tx_packets);

    /* v4-compat target: strip IPv8 header and hand off to IPv4 stack */
    if (in8_is_v4compat(&hdr->daddr)) {
        err = ipv8_xlate_8to4(skb);
        if (err)
            goto drop;
        netif_rx(skb);
        return 0;
    }

    /* Look up a static IPv8 route */
    rcu_read_lock();
    rt = ipv8_route_lookup(&hdr->daddr);
    if (!rt) {
        rcu_read_unlock();
        pr_debug_ratelimited("no route to %pI4.%pI4\n",
                             &hdr->daddr.asn, &hdr->daddr.host);
        goto drop;
    }

    nexthop = rt->gateway;         /* save before rcu_read_unlock */
    dev = dev_get_by_name_rcu(net, rt->dev_name);
    if (!dev) {
        rcu_read_unlock();
        goto drop;
    }
    dev_hold(dev);
    rcu_read_unlock();

    /* Resolve next-hop and transmit.
     * neigh_output always consumes the skb; do not kfree on error. */
    err = ipv8_neigh_output(skb, dev, nexthop);
    dev_put(dev);

    if (err)
        atomic_long_inc(&stat_tx_dropped);

    return err;

drop:
    atomic_long_inc(&stat_tx_dropped);
    kfree_skb(skb);
    return err;
}

/* ------------------------------------------------------------------ *
 * Route management – used by ipv8_zone and sysfs (future)
 * ------------------------------------------------------------------ */

/**
 * ipv8_route_add - insert a static route
 *
 * Replaces any existing route for the same ASN prefix.
 * Safe to call from process context.
 */
int ipv8_route_add(const struct in8_addr *prefix, __be32 gateway,
                   const char *dev_name)
{
    struct ipv8_route *rt, *old = NULL;

    rt = kzalloc(sizeof(*rt), GFP_KERNEL);
    if (!rt)
        return -ENOMEM;

    rt->prefix  = *prefix;
    rt->gateway = gateway;
    strscpy(rt->dev_name, dev_name, IFNAMSIZ);
    INIT_LIST_HEAD(&rt->node);

    spin_lock(&ipv8_route_lock);
    list_for_each_entry(old, &ipv8_route_list, node) {
        if (old->prefix.asn == prefix->asn) {
            list_replace_rcu(&old->node, &rt->node);
            spin_unlock(&ipv8_route_lock);
            kfree_rcu(old, rcu);
            return 0;
        }
    }
    list_add_rcu(&rt->node, &ipv8_route_list);
    spin_unlock(&ipv8_route_lock);
    return 0;
}

/**
 * ipv8_route_flush - remove all static routes
 */
static void ipv8_route_flush(void)
{
    struct ipv8_route *rt, *tmp;

    spin_lock(&ipv8_route_lock);
    list_for_each_entry_safe(rt, tmp, &ipv8_route_list, node) {
        list_del_rcu(&rt->node);
        kfree_rcu(rt, rcu);
    }
    spin_unlock(&ipv8_route_lock);
    synchronize_rcu();
}

/* ------------------------------------------------------------------ *
 * Subsystem lifecycle
 * ------------------------------------------------------------------ */

int __init ipv8_output_init(void)
{
    atomic_long_set(&stat_tx_packets, 0);
    atomic_long_set(&stat_tx_dropped, 0);
    pr_info("output: initialized\n");
    return 0;
}

void ipv8_output_exit(void)
{
    ipv8_route_flush();
    pr_info("output: tx=%ld dropped=%ld\n",
            atomic_long_read(&stat_tx_packets),
            atomic_long_read(&stat_tx_dropped));
}
