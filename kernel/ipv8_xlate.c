// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ipv8_xlate.c - XLATE8: stateless IPv4 ↔ IPv8 header translation
 *
 * XLATE8 is the translation sub-service of the Zone Server
 * (draft-thain-zoneserver-00 §7).  This kernel-side implementation hooks
 * into Netfilter so that:
 *
 *   PREROUTING (IPv4): incoming IPv4 packets addressed to a registered
 *     XLATE8 prefix are rewritten to IPv8 and re-injected.
 *
 *   POSTROUTING (IPv4): outgoing IPv4 packets from an IPv8-capable host
 *     are wrapped with an IPv8 header when the peer is known.
 *
 * Stateless mapping rule (draft-thain-ipv8 §5.3):
 *   IPv8 address = <local_asn> . <IPv4_address>
 *   e.g. 65001.0 . 203.0.113.7  →  IPv4 203.0.113.7
 *        203.0.113.7             ←  IPv4 203.0.113.7 (v4-compat)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_tables.h>

#include "ipv8.h"

/* ------------------------------------------------------------------ *
 * Configuration
 * ------------------------------------------------------------------ */

/* Local ASN assigned to this node (writable via /proc/net/ipv8_config).
 * Hosts in this ASN are reachable as <local_asn>.<host_ipv4>. */
static __be32 local_asn __read_mostly;    /* 0 == XLATE8 disabled */

/* IPv4 prefix that triggers 4→8 translation on PREROUTING */
static __be32 xlate_prefix __read_mostly;
static __be32 xlate_mask   __read_mostly;

static DEFINE_SPINLOCK(xlate_cfg_lock);

static void ipv8_xlate_set_asn(__be32 asn)
{
    spin_lock(&xlate_cfg_lock);
    local_asn = asn;
    spin_unlock(&xlate_cfg_lock);
    pr_info("xlate: local ASN set to %pI4\n", &asn);
}

static void ipv8_xlate_set_prefix(__be32 prefix, __be32 mask)
{
    spin_lock(&xlate_cfg_lock);
    xlate_prefix = prefix & mask;
    xlate_mask   = mask;
    spin_unlock(&xlate_cfg_lock);
    pr_info("xlate: 4→8 prefix set to %pI4/%pI4\n", &prefix, &mask);
}

/* ------------------------------------------------------------------ *
 * Statistics
 * ------------------------------------------------------------------ */

static atomic_long_t stat_xlate_4to8;
static atomic_long_t stat_xlate_8to4;
static atomic_long_t stat_xlate_err;

/* ------------------------------------------------------------------ *
 * Header rewrite helpers
 * ------------------------------------------------------------------ */

/*
 * ipv8_checksum_update - recompute the IPv8 header checksum in place
 *
 * Because the header is just a byte block, the same 1s-complement sum
 * algorithm that IPv4 uses works here unchanged.
 */
static void ipv8_checksum_update(struct ipv8hdr *h8)
{
    unsigned int hlen = ipv8_hdrlen(h8);

    h8->check = 0;
    h8->check = ip_compute_csum(h8, hlen);
}

/*
 * ipv8_xlate_4to8 - rewrite an IPv4 packet as an IPv8 packet
 * @skb:  buffer whose skb->data points at the IPv4 header
 * @dst8: destination IPv8 address to use
 *
 * Grows the skb by the extra 8 bytes the wider address fields require
 * and rewrites the header fields in place.  The payload and transport
 * checksums are unaffected because IPv4 pseudo-header already carries
 * the full addresses – those must be patched by the caller if needed.
 *
 * Returns 0 on success.
 */
int ipv8_xlate_4to8(struct sk_buff *skb, const struct in8_addr *dst8)
{
    struct iphdr *iph4;
    struct ipv8hdr *iph8;
    __be32 src4, dst4;
    __be32 asn;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return -EINVAL;

    iph4 = ip_hdr(skb);
    src4 = iph4->saddr;
    dst4 = iph4->daddr;

    /* Grow the head to accommodate the extra 8 bytes */
    if (skb_cow_head(skb, IPV8_HDRLEN - sizeof(struct iphdr)))
        return -ENOMEM;

    /* Make room: push 8 bytes of headroom */
    skb_push(skb, IPV8_HDRLEN - sizeof(struct iphdr));
    skb_reset_network_header(skb);

    /* Copy IPv4 fixed fields verbatim, then overwrite addresses */
    iph8 = (struct ipv8hdr *)skb->data;
    memmove(iph8, (u8 *)iph8 + (IPV8_HDRLEN - sizeof(struct iphdr)),
            sizeof(struct iphdr));

    asn = READ_ONCE(local_asn);

    iph8->version_ihl = (IPV8_VERSION << 4) | (IPV8_HDRLEN >> 2);
    iph8->tot_len     = htons(ntohs(iph8->tot_len) +
                              (IPV8_HDRLEN - sizeof(struct iphdr)));

    /* Source: this node's ASN + original IPv4 source */
    iph8->saddr.asn  = asn;
    iph8->saddr.host = src4;

    /* Destination: as provided (may already be a full IPv8 addr) */
    if (dst8) {
        iph8->daddr = *dst8;
    } else {
        iph8->daddr.asn  = 0;   /* v4-compat */
        iph8->daddr.host = dst4;
    }

    ipv8_checksum_update(iph8);

    skb->protocol = htons(ETH_P_IPV8);
    atomic_long_inc(&stat_xlate_4to8);
    return 0;
}

/*
 * ipv8_xlate_8to4 - rewrite an IPv8 packet as an IPv4 packet
 * @skb: buffer whose skb->data points at the IPv8 header
 *
 * Shrinks the skb by 8 bytes and rebuilds an IPv4 header.  The source
 * and destination host fields become the IPv4 addresses.  Only valid
 * when both source and destination are v4-compat (ASN == 0).
 *
 * Returns 0 on success.
 */
int ipv8_xlate_8to4(struct sk_buff *skb)
{
    struct ipv8hdr *iph8;
    struct iphdr *iph4;
    __be32 src4, dst4;
    u8 tos, ttl, proto;
    __be16 id, frag_off, tot_len;

    if (!pskb_may_pull(skb, IPV8_HDRLEN))
        return -EINVAL;

    iph8 = (struct ipv8hdr *)skb->data;

    src4     = iph8->saddr.host;
    dst4     = iph8->daddr.host;
    tos      = iph8->tos;
    ttl      = iph8->ttl;
    proto    = iph8->protocol;
    id       = iph8->id;
    frag_off = iph8->frag_off;
    tot_len  = htons(ntohs(iph8->tot_len) -
                     (IPV8_HDRLEN - sizeof(struct iphdr)));

    /* Shrink header: advance data pointer by the address size difference */
    skb_pull(skb, IPV8_HDRLEN - sizeof(struct iphdr));
    skb_reset_network_header(skb);

    iph4 = (struct iphdr *)skb->data;

    iph4->version  = 4;
    iph4->ihl      = sizeof(struct iphdr) >> 2;
    iph4->tos      = tos;
    iph4->tot_len  = tot_len;
    iph4->id       = id;
    iph4->frag_off = frag_off;
    iph4->ttl      = ttl;
    iph4->protocol = proto;
    iph4->saddr    = src4;
    iph4->daddr    = dst4;
    iph4->check    = 0;
    iph4->check    = ip_fast_csum(iph4, iph4->ihl);

    skb->protocol = htons(ETH_P_IP);
    atomic_long_inc(&stat_xlate_8to4);
    return 0;
}

/* ------------------------------------------------------------------ *
 * Netfilter hooks
 * ------------------------------------------------------------------ */

/*
 * Hook: NF_INET_PRE_ROUTING (IPv4)
 *
 * Intercepts incoming IPv4 packets addressed to the configured XLATE8
 * prefix and rewrites them as IPv8 packets for local delivery.
 */
static unsigned int ipv8_xlate_prerouting(void *priv,
                                          struct sk_buff *skb,
                                          const struct nf_hook_state *state)
{
    struct iphdr *iph;
    __be32 prefix, mask, asn;

    prefix = READ_ONCE(xlate_prefix);
    mask   = READ_ONCE(xlate_mask);
    asn    = READ_ONCE(local_asn);

    if (!asn || !mask)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if ((iph->daddr & mask) != prefix)
        return NF_ACCEPT;

    /* Save the IPv4 destination before the skb data moves on rewrite */
    {
        struct in8_addr local_dst;
        local_dst.asn  = asn;
        local_dst.host = iph->daddr;

        if (ipv8_xlate_4to8(skb, &local_dst) != 0) {
            atomic_long_inc(&stat_xlate_err);
            return NF_DROP;
        }
    }

    /* Re-inject into the IPv8 receive path */
    ipv8_rcv(skb, skb->dev, NULL, skb->dev);
    return NF_STOLEN;
}

/*
 * Hook: NF_INET_POST_ROUTING (IPv4)
 *
 * Wraps outgoing IPv4 packets with an IPv8 header when the destination
 * is known to the zone cache as an IPv8 host.
 */
static unsigned int ipv8_xlate_postrouting(void *priv,
                                           struct sk_buff *skb,
                                           const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct in8_addr dst8;
    char dst_str[16];
    __be32 asn;
    int err;

    asn = READ_ONCE(local_asn);
    if (!asn)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);

    /* Ask zone cache if we know an IPv8 address for this IPv4 dest */
    snprintf(dst_str, sizeof(dst_str), "%pI4", &iph->daddr);
    err = ipv8_zone_lookup(dev_net(skb->dev), dst_str, &dst8);
    if (err)
        return NF_ACCEPT;   /* no IPv8 mapping known → plain IPv4 */

    if (ipv8_xlate_4to8(skb, &dst8) != 0) {
        atomic_long_inc(&stat_xlate_err);
        return NF_DROP;
    }

    /* Route the now-IPv8 packet; ipv8_output always consumes the skb */
    skb_reset_network_header(skb);
    ipv8_output(dev_net(state->out), NULL, skb);
    return NF_STOLEN;
}

static const struct nf_hook_ops ipv8_nf_ops[] = {
    {
        .hook     = ipv8_xlate_prerouting,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_MANGLE + 1,
    },
    {
        .hook     = ipv8_xlate_postrouting,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_MANGLE + 1,
    },
};

/* ------------------------------------------------------------------ *
 * Subsystem lifecycle
 * ------------------------------------------------------------------ */

int __init ipv8_xlate_init(void)
{
    int err;

    atomic_long_set(&stat_xlate_4to8, 0);
    atomic_long_set(&stat_xlate_8to4, 0);
    atomic_long_set(&stat_xlate_err,  0);

    err = nf_register_net_hooks(&init_net, ipv8_nf_ops,
                                ARRAY_SIZE(ipv8_nf_ops));
    if (err) {
        pr_err("xlate: nf_register_net_hooks failed: %d\n", err);
        return err;
    }

    pr_info("xlate: XLATE8 netfilter hooks registered (PREROUTING + POSTROUTING)\n");
    return 0;
}

void ipv8_xlate_exit(void)
{
    nf_unregister_net_hooks(&init_net, ipv8_nf_ops,
                            ARRAY_SIZE(ipv8_nf_ops));
    synchronize_net();
    pr_info("xlate: 4→8=%ld 8→4=%ld errors=%ld\n",
            atomic_long_read(&stat_xlate_4to8),
            atomic_long_read(&stat_xlate_8to4),
            atomic_long_read(&stat_xlate_err));
}
