/*
 * ipv8_tools.h – userspace definitions mirroring kernel/ipv8.h
 *
 * Shared by ping8, ipv8_echod, and any other userspace tools.
 * Not part of the kernel module; no kernel headers required.
 */

#ifndef _IPV8_TOOLS_H
#define _IPV8_TOOLS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* ------------------------------------------------------------------ *
 * Protocol constants (must match kernel/ipv8.h)
 * ------------------------------------------------------------------ */

#define ETH_P_IPV8      0x0888
#define AF_INET8        47
#define PF_INET8        47
#define IPV8_VERSION    8
#define IPV8_HDRLEN     28
#define IPPROTO_ICMP8   1       /* reuses ICMP protocol number */

/* ------------------------------------------------------------------ *
 * Address type
 * ------------------------------------------------------------------ */

struct in8_addr {
    uint32_t asn;    /* network byte order – ASN prefix r.r.r.r */
    uint32_t host;   /* network byte order – host n.n.n.n        */
};

struct sockaddr_in8 {
    sa_family_t     sin8_family;    /* AF_INET8 */
    uint16_t        sin8_port;
    struct in8_addr sin8_addr;
    uint8_t         __pad[6];
};

/* ------------------------------------------------------------------ *
 * On-wire header
 * ------------------------------------------------------------------ */

struct ipv8hdr {
    uint8_t         version_ihl;
    uint8_t         tos;
    uint16_t        tot_len;
    uint16_t        id;
    uint16_t        frag_off;
    uint8_t         ttl;
    uint8_t         protocol;
    uint16_t        check;
    struct in8_addr saddr;
    struct in8_addr daddr;
} __attribute__((packed));

/* ------------------------------------------------------------------ *
 * Address helpers
 * ------------------------------------------------------------------ */

static inline bool in8_equal(const struct in8_addr *a,
                              const struct in8_addr *b)
{
    return a->asn == b->asn && a->host == b->host;
}

static inline bool in8_is_v4compat(const struct in8_addr *a)
{
    return a->asn == 0;
}

/*
 * in8_ntoa – format an IPv8 address as "asn:host" (static buffer).
 *
 * Returns a pointer to a thread-local static string; not reentrant.
 */
static inline const char *in8_ntoa(const struct in8_addr *a)
{
    static char buf[48];
    char asn_s[INET_ADDRSTRLEN], host_s[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &a->asn,  asn_s,  sizeof(asn_s));
    inet_ntop(AF_INET, &a->host, host_s, sizeof(host_s));

    if (in8_is_v4compat(a))
        snprintf(buf, sizeof(buf), "%s", host_s);
    else
        snprintf(buf, sizeof(buf), "%s:%s", asn_s, host_s);

    return buf;
}

/*
 * in8_parse – parse an IPv8 address string into struct in8_addr.
 *
 * Accepted formats:
 *   "65001.0.0.1:203.0.113.7"  – full IPv8 (ASN:host)
 *   "203.0.113.7"              – v4-compat (ASN = 0.0.0.0)
 *
 * Returns true on success, false on parse error.
 */
static inline bool in8_parse(const char *s, struct in8_addr *out)
{
    char buf[48];
    char *colon;

    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    colon = strchr(buf, ':');
    if (colon) {
        *colon = '\0';
        if (inet_pton(AF_INET, buf,      &out->asn)  != 1) return false;
        if (inet_pton(AF_INET, colon + 1, &out->host) != 1) return false;
    } else {
        out->asn = 0;
        if (inet_pton(AF_INET, buf, &out->host) != 1) return false;
    }
    return true;
}

/*
 * in8_zone_lookup – find a name in /proc/net/ipv8_zone.
 *
 * Returns true and fills *out on a cache hit (unexpired entry).
 * Returns false if the name is not found or the entry has expired.
 */
static inline bool in8_zone_lookup(const char *name, struct in8_addr *out)
{
    FILE *f = fopen("/proc/net/ipv8_zone", "r");
    char line[256], entry_name[64], asn_s[20], host_s[20];
    long ttl;
    bool found = false;

    if (!f)
        return false;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;
        if (sscanf(line, "%63s %19s %19s %ld",
                   entry_name, asn_s, host_s, &ttl) < 3)
            continue;
        if (strcmp(entry_name, name) != 0) continue;
        if (ttl <= 0) break;    /* expired */

        if (inet_pton(AF_INET, asn_s,  &out->asn)  == 1 &&
            inet_pton(AF_INET, host_s, &out->host) == 1)
            found = true;
        break;
    }
    fclose(f);
    return found;
}

/*
 * in8_resolve – resolve a target string to an in8_addr.
 *
 * Tries in order:
 *   1. Direct "asn:host" or plain IPv4 address parse
 *   2. Zone cache lookup (/proc/net/ipv8_zone)
 *
 * Returns true on success.
 */
static inline bool in8_resolve(const char *target, struct in8_addr *out)
{
    if (in8_parse(target, out))
        return true;
    if (in8_zone_lookup(target, out))
        return true;
    return false;
}

/* ------------------------------------------------------------------ *
 * ICMP helpers (reuses standard ICMP type codes)
 * ------------------------------------------------------------------ */

#define ICMP8_ECHO_REQUEST  8
#define ICMP8_ECHO_REPLY    0

struct icmp8hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} __attribute__((packed));

/*
 * icmp8_checksum – 1s-complement checksum over len bytes of data.
 *
 * Pass the ICMP header + payload with checksum field zeroed.
 */
static inline uint16_t icmp8_checksum(const void *data, size_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len)
        sum += *(const uint8_t *)p;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

#endif /* _IPV8_TOOLS_H */
