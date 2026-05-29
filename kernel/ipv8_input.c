// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ipv8_input.c - EtherType 0x0888 receive handler and packet validation
 *
 * Registered with dev_add_pack() so every Ethernet frame carrying
 * EtherType ETH_P_IPV8 is delivered here.  After header validation and
 * checksum verification the packet is either:
 *   – Delivered to a matching AF_INET8 socket, or
 *   – Forwarded via the routing subsystem (future), or
 *   – Passed to XLATE8 for IPv4 translation if daddr is v4-compat.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <net/net_namespace.h>

#include "ipv8.h"

/* Statistics visible under /proc/net/dev_snmp6 analog (future) */
static atomic_long_t stat_rx_packets;
static atomic_long_t stat_rx_dropped;
static atomic_long_t stat_rx_v4compat;

/* ------------------------------------------------------------------ *
 * Header validation
 * ------------------------------------------------------------------ */

/**
 * ipv8_hdr_ok - validate a received IPv8 header
 *
 * Returns true if the header is internally consistent.  Does NOT verify
 * the packet against routing policy – that is the forwarder's job.
 */
static bool ipv8_hdr_ok(const struct ipv8hdr *hdr, unsigned int pkt_len)
{
    unsigned int hlen;
    __sum16 orig_check, computed;

    if (ipv8_version(hdr) != IPV8_VERSION) {
        pr_debug_ratelimited("bad version %u\n", ipv8_version(hdr));
        return false;
    }

    hlen = ipv8_hdrlen(hdr);
    if (hlen < IPV8_HDRLEN) {
        pr_debug_ratelimited("IHL too small: %u\n", hlen);
        return false;
    }

    if (ntohs(hdr->tot_len) < hlen || ntohs(hdr->tot_len) > pkt_len) {
        pr_debug_ratelimited("tot_len mismatch: %u vs pkt %u\n",
                             ntohs(hdr->tot_len), pkt_len);
        return false;
    }

    /* Verify header checksum over hlen bytes */
    orig_check  = hdr->check;
    /* ip_compute_csum treats the bytes as a 1s-complement sum; when the
     * check field is included the result should be 0xffff (== ~0). */
    computed = ip_compute_csum(hdr, hlen);
    if (computed != 0xffff) {
        pr_debug_ratelimited("checksum error\n");
        return false;
    }
    (void)orig_check;

    return true;
}

/* ------------------------------------------------------------------ *
 * Socket demux
 * ------------------------------------------------------------------ */

/*
 * Find an AF_INET8 socket bound to daddr:dport.
 * Returns the sock with its reference count bumped, or NULL.
 *
 * NOTE: A production implementation would use a full hash table indexed
 * by (saddr, daddr, sport, dport) as IPv4 does.  This linear walk of
 * the proto slab suffices for a PoC.
 */
static struct sock *ipv8_demux(struct net *net, const struct ipv8hdr *hdr,
                               __be16 dport)
{
    struct sock *sk;

    /* Walk all sockets registered under ipv8_prot */
    sk_for_each_from(sk) {
        struct ipv8_sock *i8;

        if (sk->sk_family != PF_INET8)
            continue;
        if (!net_eq(sock_net(sk), net))
            continue;

        i8 = ipv8_sk(sk);
        if (i8->dport && i8->dport != dport)
            continue;
        if (i8->saddr.asn || i8->saddr.host) {
            if (!in8_equal(&i8->saddr, &hdr->daddr))
                continue;
        }

        sock_hold(sk);
        return sk;
    }
    return NULL;
}

/* ------------------------------------------------------------------ *
 * Main receive entry point
 * ------------------------------------------------------------------ */

/**
 * ipv8_rcv - EtherType ETH_P_IPV8 packet handler
 *
 * Called by the core packet dispatcher for every frame whose EtherType
 * matches ETH_P_IPV8 (0x0888).
 */
int ipv8_rcv(struct sk_buff *skb, struct net_device *dev,
             struct packet_type *pt, struct net_device *orig_dev)
{
    struct net *net = dev_net(dev);
    struct ipv8hdr *hdr;
    unsigned int hlen;

    atomic_long_inc(&stat_rx_packets);

    /* Ensure the minimum header is in the linear data area */
    if (!pskb_may_pull(skb, IPV8_HDRLEN))
        goto drop;

    hdr  = (struct ipv8hdr *)skb->data;

    if (!ipv8_hdr_ok(hdr, skb->len))
        goto drop;

    hlen = ipv8_hdrlen(hdr);

    /* Truncate any Ethernet padding to the declared packet length */
    if (pskb_trim_rcsum(skb, ntohs(hdr->tot_len)))
        goto drop;

    /* Pull header into skb->data so transport layers see their payload */
    if (!pskb_may_pull(skb, hlen))
        goto drop;

    hdr = (struct ipv8hdr *)skb->data;   /* re-fetch after pull */

    /* v4-compat destination → hand to XLATE8 for IPv4 delivery */
    if (in8_is_v4compat(&hdr->daddr)) {
        atomic_long_inc(&stat_rx_v4compat);
        if (ipv8_xlate_8to4(skb) == 0)
            return NET_RX_SUCCESS;
        goto drop;
    }

    /* Move past IPv8 header so socket read() returns the payload */
    skb_pull(skb, hlen);
    skb_reset_transport_header(skb);

    /*
     * For a PoC we deliver to any SOCK_RAW AF_INET8 listener.
     * A real implementation would demux on protocol + port tuple.
     */
    {
        struct sock *sk = ipv8_demux(net, hdr, 0);

        if (sk) {
            if (sock_queue_rcv_skb(sk, skb) < 0)
                kfree_skb(skb);
            sock_put(sk);
            return NET_RX_SUCCESS;
        }
    }

    /* No socket – discard (future: ICMP8 "port unreachable") */
drop:
    atomic_long_inc(&stat_rx_dropped);
    kfree_skb(skb);
    return NET_RX_DROP;
}

/* ------------------------------------------------------------------ *
 * EtherType registration
 * ------------------------------------------------------------------ */

static struct packet_type ipv8_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_IPV8),
    .func = ipv8_rcv,
};

int __init ipv8_input_init(void)
{
    atomic_long_set(&stat_rx_packets, 0);
    atomic_long_set(&stat_rx_dropped, 0);
    atomic_long_set(&stat_rx_v4compat, 0);

    dev_add_pack(&ipv8_packet_type);
    pr_info("input: registered EtherType 0x%04x\n", ETH_P_IPV8);
    return 0;
}

void ipv8_input_exit(void)
{
    dev_remove_pack(&ipv8_packet_type);
    pr_info("input: rx=%ld dropped=%ld v4compat=%ld\n",
            atomic_long_read(&stat_rx_packets),
            atomic_long_read(&stat_rx_dropped),
            atomic_long_read(&stat_rx_v4compat));
}
