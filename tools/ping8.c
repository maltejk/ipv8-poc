/*
 * ping8 – ICMP Echo client for IPv8 (draft-thain-ipv8)
 *
 * Sends ICMP Echo Requests over AF_INET8 and reports round-trip time
 * statistics, in the style of the standard ping(8) utility.
 *
 * Requires:
 *   - Root (CAP_NET_RAW)
 *   - The ipv8 kernel module loaded (insmod kernel/ipv8.ko)
 *   - A route to the destination (or use a v4-compat address)
 *
 * Usage:
 *   ping8 [options] <target>
 *
 * Target formats:
 *   65001.0.0.1:10.0.0.2   full IPv8 address (ASN:host)
 *   127.0.0.1              v4-compat (ASN = 0.0.0.0)
 *   peer.example.com       name looked up in /proc/net/ipv8_zone
 *
 * Options:
 *   -c <n>    stop after n packets (default: unlimited)
 *   -i <ms>   interval between packets in milliseconds (default: 1000)
 *   -t <ttl>  IPv8 TTL (default: 64)
 *   -W <ms>   reply wait timeout in milliseconds (default: 2000)
 *   -s <n>    payload size in bytes beyond ICMP header (default: 56)
 *   -v        verbose: print every received packet
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/ip_icmp.h>

#include "ipv8_tools.h"

/* ------------------------------------------------------------------ *
 * Globals set from signal handler
 * ------------------------------------------------------------------ */

static volatile sig_atomic_t g_stop;

static void sigint_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* ------------------------------------------------------------------ *
 * Time helpers
 * ------------------------------------------------------------------ */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

/* ------------------------------------------------------------------ *
 * Statistics
 * ------------------------------------------------------------------ */

struct ping_stats {
    uint32_t sent;
    uint32_t received;
    double   rtt_min;
    double   rtt_max;
    double   rtt_sum;
    double   rtt_sum2;  /* for stddev */
};

static void stats_update(struct ping_stats *s, double rtt_ms)
{
    s->received++;
    if (rtt_ms < s->rtt_min || s->received == 1) s->rtt_min = rtt_ms;
    if (rtt_ms > s->rtt_max)                     s->rtt_max = rtt_ms;
    s->rtt_sum  += rtt_ms;
    s->rtt_sum2 += rtt_ms * rtt_ms;
}

static void stats_print(const struct ping_stats *s, const char *target)
{
    double avg, stddev = 0.0;
    int loss;

    printf("\n--- %s ping8 statistics ---\n", target);
    loss = s->sent ? (int)(100.0 * (s->sent - s->received) / s->sent) : 0;
    printf("%u packets transmitted, %u received, %d%% packet loss\n",
           s->sent, s->received, loss);

    if (s->received == 0)
        return;

    avg = s->rtt_sum / s->received;
    if (s->received > 1) {
        double var = s->rtt_sum2 / s->received - avg * avg;
        stddev = var > 0.0 ? __builtin_sqrt(var) : 0.0;
    }
    printf("rtt min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
           s->rtt_min, avg, s->rtt_max, stddev);
}

/* ------------------------------------------------------------------ *
 * Packet build / parse
 * ------------------------------------------------------------------ */

#define PING8_MAGIC  0xA8  /* first payload byte; identifies ping8 frames */

static size_t build_echo_request(uint8_t *buf, size_t buf_sz,
                                 uint16_t id, uint16_t seq,
                                 size_t payload_sz, double send_ts)
{
    struct icmp8hdr *ih = (struct icmp8hdr *)buf;
    uint8_t *payload    = buf + sizeof(*ih);
    size_t total        = sizeof(*ih) + payload_sz;

    if (total > buf_sz)
        total = buf_sz;

    memset(buf, 0, total);
    ih->type = ICMP8_ECHO_REQUEST;
    ih->code = 0;
    ih->id   = htons(id);
    ih->seq  = htons(seq);

    /* Payload: magic byte + send timestamp + filler */
    payload[0] = PING8_MAGIC;
    if (payload_sz >= sizeof(double) + 1)
        memcpy(payload + 1, &send_ts, sizeof(double));
    for (size_t i = 1 + sizeof(double); i < payload_sz; i++)
        payload[i] = (uint8_t)(i & 0xff);

    ih->checksum = icmp8_checksum(buf, total);
    return total;
}

static bool parse_echo_reply(const uint8_t *buf, size_t len,
                             uint16_t expect_id, uint16_t expect_seq,
                             double *rtt_ms_out)
{
    const struct icmp8hdr *ih = (const struct icmp8hdr *)buf;
    const uint8_t *payload    = buf + sizeof(*ih);
    double send_ts;

    if (len < sizeof(*ih))
        return false;
    if (ih->type != ICMP8_ECHO_REPLY || ih->code != 0)
        return false;
    if (ntohs(ih->id) != expect_id)
        return false;
    if (ntohs(ih->seq) != expect_seq)
        return false;
    if (len < sizeof(*ih) + 1 || payload[0] != PING8_MAGIC)
        return false;

    if (len >= sizeof(*ih) + 1 + sizeof(double)) {
        memcpy(&send_ts, payload + 1, sizeof(double));
        *rtt_ms_out = now_ms() - send_ts;
    } else {
        *rtt_ms_out = 0.0;
    }
    return true;
}

/* ------------------------------------------------------------------ *
 * Main loop
 * ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    /* Defaults */
    int          count       = 0;           /* 0 = unlimited */
    int          interval_ms = 1000;
    int          ttl         = 64;
    int          timeout_ms  = 2000;
    size_t       payload_sz  = 56;
    bool         verbose     = false;

    int opt;
    while ((opt = getopt(argc, argv, "c:i:t:W:s:vh")) != -1) {
        switch (opt) {
        case 'c': count       = atoi(optarg); break;
        case 'i': interval_ms = atoi(optarg); break;
        case 't': ttl         = atoi(optarg); break;
        case 'W': timeout_ms  = atoi(optarg); break;
        case 's': payload_sz  = (size_t)atoi(optarg); break;
        case 'v': verbose     = true; break;
        case 'h':
            printf("Usage: %s [-c count] [-i interval_ms] [-t ttl] "
                   "[-W timeout_ms] [-s payload_sz] [-v] <target>\n",
                   argv[0]);
            printf("Target: 'asn:host' | 'host' | 'name-in-zone-cache'\n");
            return 0;
        default:
            fprintf(stderr, "Try '%s -h' for usage.\n", argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "ping8: missing target\n");
        return 1;
    }
    const char *target_str = argv[optind];

    /* Resolve target */
    struct in8_addr dst;
    if (!in8_resolve(target_str, &dst)) {
        fprintf(stderr, "ping8: cannot resolve '%s': "
                "not a valid IPv8 address and not found in "
                "/proc/net/ipv8_zone\n", target_str);
        return 1;
    }
    printf("PING8 %s (%s): %zu data bytes, id=0x%04x\n",
           target_str, in8_ntoa(&dst),
           payload_sz, (unsigned)getpid() & 0xffffu);

    /* Open AF_INET8 raw socket */
    int fd = socket(AF_INET8, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        if (errno == EAFNOSUPPORT)
            fprintf(stderr, "ping8: AF_INET8 not available – "
                    "is the ipv8 module loaded?\n");
        else if (errno == EPERM)
            fprintf(stderr, "ping8: permission denied – run as root\n");
        else
            perror("ping8: socket");
        return 1;
    }

    /* TTL */
    /* best-effort TTL hint; the module reads ttl from ipv8_sock directly */
    (void)setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &ttl, sizeof(ttl));

    /* Receive timeout */
    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Connect so send() sends to dst and recvfrom() filters by peer */
    struct sockaddr_in8 peer = {
        .sin8_family = AF_INET8,
        .sin8_addr   = dst,
    };
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
        if (errno != EOPNOTSUPP) {   /* PoC: connect is a stub */
            perror("ping8: connect");
            close(fd);
            return 1;
        }
    }

    signal(SIGINT, sigint_handler);

    uint16_t id  = (uint16_t)(getpid() & 0xffff);
    uint16_t seq = 0;
    struct ping_stats stats = { .rtt_min = 1e9 };

    uint8_t pkt[1500];
    struct sockaddr_in8 from;
    socklen_t from_len;
    double rtt;

    while (!g_stop && (count == 0 || stats.sent < (uint32_t)count)) {
        double send_ts = now_ms();
        size_t pkt_len = build_echo_request(pkt, sizeof(pkt),
                                            id, seq, payload_sz, send_ts);
        ssize_t sent = send(fd, pkt, pkt_len, 0);
        if (sent < 0) {
            perror("ping8: send");
            break;
        }
        stats.sent++;

        /* Wait for reply */
        from_len = sizeof(from);
        ssize_t n = recvfrom(fd, pkt, sizeof(pkt), 0,
                             (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                printf("Request timeout for seq %u\n", seq);
            else
                perror("ping8: recvfrom");
        } else if (parse_echo_reply(pkt, (size_t)n, id, seq, &rtt)) {
            stats_update(&stats, rtt);
            printf("%zd bytes from %s: icmp8_seq=%u ttl=%d time=%.3f ms\n",
                   n, in8_ntoa(&from.sin8_addr), seq, ttl, rtt);
        } else if (verbose) {
            printf("Unexpected packet: %zd bytes type=%u code=%u\n",
                   n, pkt[0], pkt[1]);
        }

        seq++;

        /* Sleep until next interval, unless this is the last packet */
        if (!g_stop && (count == 0 || stats.sent < (uint32_t)count)) {
            struct timespec delay = {
                .tv_sec  =  interval_ms / 1000,
                .tv_nsec = (interval_ms % 1000) * 1000000L,
            };
            nanosleep(&delay, NULL);
        }
    }

    stats_print(&stats, target_str);
    close(fd);
    return stats.received > 0 ? 0 : 1;
}
