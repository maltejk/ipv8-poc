/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ipv8.h - Shared types and declarations for the IPv8 kernel module
 *
 * Implements draft-thain-ipv8 (Internet Protocol Version 8), an IETF
 * individual submission that extends IPv4 with 64-bit addresses composed
 * of a 32-bit ASN routing prefix and a 32-bit host number.
 *
 * References
 *   draft-thain-ipv8-02       – Core protocol
 *   draft-thain-zoneserver-00 – Zone Server architecture
 *   draft-thain-routing-protocols-00 – BGP8 / OSPF8
 */

#ifndef _NET_IPV8_H
#define _NET_IPV8_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <net/sock.h>
#include <net/net_namespace.h>

/* ------------------------------------------------------------------ *
 * Protocol constants
 * ------------------------------------------------------------------ */

/* Provisional Ethernet frame type.  No IANA assignment exists yet.
 * 0x0888 is unallocated and unlikely to collide in a lab environment. */
#define ETH_P_IPV8      0x0888

/* IP version number written into version_ihl.version */
#define IPV8_VERSION    8

/* Minimum header length: IPv4 (20 B) + 2 × 4 extra bytes for wider addrs */
#define IPV8_HDRLEN     28      /* bytes; IHL field value == 7 */

/*
 * Address family number.  Linux 6.x defines AF_MAX == 46 (AF_MCTP == 45).
 * We claim 47; adjust if your kernel already uses it.
 */
#ifndef AF_INET8
#define AF_INET8        47
#endif
#define PF_INET8        AF_INET8

/* Provisional Zone Server UDP/TCP port (no IANA assignment) */
#define IPV8_ZONE_PORT  8538

/* Hash table order for the zone cache (2^6 == 64 buckets) */
#define IPV8_ZONE_HTABLE_BITS  6

/* Maximum name length stored in a zone cache entry */
#define IPV8_ZONE_NAME_MAX     64

/* Zone entry TTL if the server does not specify one (seconds) */
#define IPV8_ZONE_DEFAULT_TTL  300

/* ------------------------------------------------------------------ *
 * Address type  (draft-thain-ipv8 §3)
 * ------------------------------------------------------------------ */

/**
 * struct in8_addr - 64-bit IPv8 address
 * @asn:  32-bit Autonomous System Number prefix  (r.r.r.r)
 * @host: 32-bit host number within the ASN       (n.n.n.n)
 *
 * An address with asn == 0 is a backward-compatible IPv4 address; the
 * host field carries the IPv4 address unchanged.
 */
struct in8_addr {
    __be32 asn;
    __be32 host;
} __packed;

static inline bool in8_is_v4compat(const struct in8_addr *a)
{
    return a->asn == 0;
}

static inline void in8_from_v4(__be32 v4, struct in8_addr *out)
{
    out->asn  = 0;
    out->host = v4;
}

static inline bool in8_equal(const struct in8_addr *a, const struct in8_addr *b)
{
    return a->asn == b->asn && a->host == b->host;
}

/* ------------------------------------------------------------------ *
 * On-wire header  (draft-thain-ipv8 §4)
 * ------------------------------------------------------------------ */

/**
 * struct ipv8hdr - IPv8 packet header
 *
 * Layout mirrors IPv4 exactly; the only structural change is that each
 * address field is 8 bytes instead of 4.  All other semantic rules
 * (checksum covers the header, TTL is decremented per hop, etc.) are
 * inherited from IPv4.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver=8| IHL=7   |     ToS       |          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|    Fragment Offset      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      TTL      |   Protocol    |        Header Checksum        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Source ASN prefix  (r.r.r.r)                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Source Host address (n.n.n.n)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination ASN prefix  (r.r.r.r)              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination Host address (n.n.n.n)             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ipv8hdr {
    __u8            version_ihl;    /* ver (bits 7:4) + IHL (bits 3:0) */
    __u8            tos;
    __be16          tot_len;
    __be16          id;
    __be16          frag_off;       /* flags (bits 15:13) + offset (12:0) */
    __u8            ttl;
    __u8            protocol;       /* same namespace as IPv4 protocol numbers */
    __sum16         check;
    struct in8_addr saddr;
    struct in8_addr daddr;
} __packed;

static_assert(sizeof(struct ipv8hdr) == IPV8_HDRLEN, "ipv8hdr size mismatch");

static inline u8 ipv8_version(const struct ipv8hdr *h)
{
    return h->version_ihl >> 4;
}

static inline unsigned int ipv8_hdrlen(const struct ipv8hdr *h)
{
    return (h->version_ihl & 0x0f) << 2;   /* IHL field → bytes */
}

/* Flags stored in the high bits of frag_off (same as IPv4) */
#define IPV8_DF     htons(0x4000)   /* Don't Fragment */
#define IPV8_MF     htons(0x2000)   /* More Fragments */

/* ------------------------------------------------------------------ *
 * Userspace socket address
 * ------------------------------------------------------------------ */

struct sockaddr_in8 {
    __kernel_sa_family_t sin8_family;   /* AF_INET8 */
    __be16               sin8_port;
    struct in8_addr      sin8_addr;
    u8                   __pad[6];      /* sizeof(sockaddr) == 16 */
};

/* ------------------------------------------------------------------ *
 * Per-socket IPv8 state
 * ------------------------------------------------------------------ */

/**
 * struct ipv8_sock - IPv8 socket private data
 *
 * Must be the first member so that ipv8_sk() casts are safe.
 */
struct ipv8_sock {
    struct sock     sk;
    struct in8_addr saddr;
    struct in8_addr daddr;
    __be16          sport;
    __be16          dport;
    u8              ttl;
    u8              tos;
    bool            hdrincl;   /* raw socket: caller provides the IPv8 header */
};

static inline struct ipv8_sock *ipv8_sk(struct sock *sk)
{
    return (struct ipv8_sock *)sk;
}

/* ------------------------------------------------------------------ *
 * Zone cache entry  (draft-thain-zoneserver-00 §5)
 * ------------------------------------------------------------------ */

/**
 * struct ipv8_zone_entry - one resolved name-to-address mapping
 *
 * Caches responses from DHCP8, DNS8, and OAuth8 sub-services exposed
 * by the Zone Server.
 */
struct ipv8_zone_entry {
    struct hlist_node    hnode;
    char                 name[IPV8_ZONE_NAME_MAX];
    struct in8_addr      addr;
    unsigned long        expires;   /* jiffies when entry becomes stale */
    struct rcu_head      rcu;
};

/* ------------------------------------------------------------------ *
 * Cross-file declarations
 * ------------------------------------------------------------------ */

extern struct proto           ipv8_prot;
extern const struct proto_ops ipv8_dgram_ops;

/* Subsystem lifecycle */
int  ipv8_input_init(void);
void ipv8_input_exit(void);
int  ipv8_output_init(void);
void ipv8_output_exit(void);
int  ipv8_xlate_init(void);
void ipv8_xlate_exit(void);
int  ipv8_zone_init(void);
void ipv8_zone_exit(void);

/* Receive path */
int ipv8_rcv(struct sk_buff *skb, struct net_device *dev,
             struct packet_type *pt, struct net_device *orig_dev);

/* Transmit path */
int ipv8_output(struct net *net, struct sock *sk, struct sk_buff *skb);

/* XLATE8: stateless IPv4 ↔ IPv8 header rewriting */
int ipv8_xlate_4to8(struct sk_buff *skb, const struct in8_addr *dst8);
int ipv8_xlate_8to4(struct sk_buff *skb);

/* Zone cache */
int  ipv8_zone_lookup(struct net *net, const char *name,
                      struct in8_addr *out);
void ipv8_zone_update(struct net *net, const char *name,
                      const struct in8_addr *addr, u32 ttl_sec);

#endif /* _NET_IPV8_H */
