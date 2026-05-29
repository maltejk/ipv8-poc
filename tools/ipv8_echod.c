/*
 * ipv8_echod – ICMP Echo Server for IPv8 (draft-thain-ipv8)
 *
 * Listens on AF_INET8 for incoming ICMP Echo Requests and replies
 * with ICMP Echo Replies, swapping source and destination addresses.
 * Intended as a minimal test peer so ping8 can be exercised on a
 * single machine or between two hosts.
 *
 * Requires:
 *   - Root (CAP_NET_RAW)
 *   - The ipv8 kernel module loaded (insmod kernel/ipv8.ko)
 *
 * Usage:
 *   ipv8_echod [-v] [-b <bind-addr>]
 *
 * Options:
 *   -b <addr>  bind to this IPv8 address (default: any)
 *   -v         verbose: log every request
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

#include "ipv8_tools.h"

/* ------------------------------------------------------------------ *
 * Globals
 * ------------------------------------------------------------------ */

static volatile sig_atomic_t g_stop;
static uint64_t g_requests;
static uint64_t g_replies;

static void sigint_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* ------------------------------------------------------------------ *
 * Echo logic
 * ------------------------------------------------------------------ */

/*
 * handle_request – validate an ICMP Echo Request and send the reply.
 *
 * Reuses the received buffer: flip src/dst in msg_name, change type
 * to ICMP_ECHOREPLY, recompute checksum, send.
 */
static void handle_request(int fd, uint8_t *buf, size_t len,
                            const struct sockaddr_in8 *from,
                            bool verbose)
{
    struct icmp8hdr *ih = (struct icmp8hdr *)buf;

    if (len < sizeof(*ih))
        return;
    if (ih->type != ICMP8_ECHO_REQUEST)
        return;

    g_requests++;

    if (verbose)
        printf("echo request  from %s seq=%u id=%u len=%zu\n",
               in8_ntoa(&from->sin8_addr),
               ntohs(ih->seq), ntohs(ih->id), len);

    /* Build reply: same payload, flipped type */
    ih->type     = ICMP8_ECHO_REPLY;
    ih->checksum = 0;
    ih->checksum = icmp8_checksum(buf, len);

    /* Send back to sender */
    ssize_t sent = sendto(fd, buf, len, 0,
                          (const struct sockaddr *)from, sizeof(*from));
    if (sent < 0) {
        perror("ipv8_echod: sendto");
        return;
    }

    g_replies++;

    if (verbose)
        printf("echo reply    to   %s seq=%u id=%u len=%zd\n",
               in8_ntoa(&from->sin8_addr),
               ntohs(ih->seq), ntohs(ih->id), sent);
}

/* ------------------------------------------------------------------ *
 * Main
 * ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    bool verbose = false;
    const char *bind_str = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "b:vh")) != -1) {
        switch (opt) {
        case 'b': bind_str = optarg; break;
        case 'v': verbose  = true;   break;
        case 'h':
            printf("Usage: %s [-v] [-b bind-addr]\n", argv[0]);
            printf("  -b <addr>  IPv8 address to bind (default: any)\n");
            printf("  -v         verbose output\n");
            return 0;
        default:
            fprintf(stderr, "Try '%s -h' for usage.\n", argv[0]);
            return 1;
        }
    }

    /* Open AF_INET8 raw socket */
    int fd = socket(AF_INET8, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        if (errno == EAFNOSUPPORT)
            fprintf(stderr, "ipv8_echod: AF_INET8 not available – "
                    "is the ipv8 module loaded?\n");
        else if (errno == EPERM)
            fprintf(stderr, "ipv8_echod: permission denied – run as root\n");
        else
            perror("ipv8_echod: socket");
        return 1;
    }

    /* Optional bind */
    if (bind_str) {
        struct sockaddr_in8 sa = { .sin8_family = AF_INET8 };
        if (!in8_parse(bind_str, &sa.sin8_addr)) {
            fprintf(stderr, "ipv8_echod: invalid bind address '%s'\n",
                    bind_str);
            close(fd);
            return 1;
        }
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 &&
            errno != EOPNOTSUPP) {
            perror("ipv8_echod: bind");
            close(fd);
            return 1;
        }
        printf("ipv8_echod: bound to %s\n", in8_ntoa(&sa.sin8_addr));
    }

    signal(SIGINT,  sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("ipv8_echod: listening on AF_INET8 (IPPROTO_ICMP)\n");
    printf("ipv8_echod: press Ctrl-C to stop\n");

    uint8_t buf[1500];
    struct sockaddr_in8 from;
    socklen_t from_len;

    while (!g_stop) {
        from_len = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR)
                break;
            perror("ipv8_echod: recvfrom");
            continue;
        }
        handle_request(fd, buf, (size_t)n, &from, verbose);
    }

    printf("\nipv8_echod: requests=%llu replies=%llu\n",
           (unsigned long long)g_requests,
           (unsigned long long)g_replies);

    close(fd);
    return 0;
}
