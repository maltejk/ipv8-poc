// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ipv8_main.c - Module entry point and AF_INET8 address family registration
 *
 * Registers the PF_INET8 protocol family with the kernel, wires together
 * the input, output, XLATE8, and Zone subsystems, and exposes raw and
 * datagram socket types to userspace.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/net_namespace.h>

#include "ipv8.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IPv8 PoC contributors");
MODULE_DESCRIPTION("Linux proof-of-concept for draft-thain-ipv8 "
                   "(Internet Protocol Version 8)");
MODULE_VERSION("0.1.0-poc");
MODULE_ALIAS_NETPROTO(PF_INET8);

/* ------------------------------------------------------------------ *
 * Socket registry – used by ipv8_input to demux received packets
 * ------------------------------------------------------------------ */

static HLIST_HEAD(ipv8_sklist);
static DEFINE_SPINLOCK(ipv8_sklist_lock);

void ipv8_register_sock(struct sock *sk)
{
    spin_lock_bh(&ipv8_sklist_lock);
    sk_add_node(sk, &ipv8_sklist);
    spin_unlock_bh(&ipv8_sklist_lock);
}

void ipv8_unregister_sock(struct sock *sk)
{
    spin_lock_bh(&ipv8_sklist_lock);
    sk_del_node_init(sk);
    spin_unlock_bh(&ipv8_sklist_lock);
}

struct sock *ipv8_find_sock(struct net *net, const struct in8_addr *daddr,
                            __be16 dport)
{
    struct sock *sk;

    spin_lock(&ipv8_sklist_lock);
    hlist_for_each_entry(sk, &ipv8_sklist, sk_node) {
        struct ipv8_sock *i8;

        if (sk->sk_family != PF_INET8)
            continue;
        if (!net_eq(sock_net(sk), net))
            continue;

        i8 = ipv8_sk(sk);
        if (i8->dport && i8->dport != dport)
            continue;
        if (i8->saddr.asn || i8->saddr.host) {
            if (!in8_equal(&i8->saddr, daddr))
                continue;
        }

        sock_hold(sk);
        spin_unlock(&ipv8_sklist_lock);
        return sk;
    }
    spin_unlock(&ipv8_sklist_lock);
    return NULL;
}

/* ------------------------------------------------------------------ *
 * Socket operations
 * ------------------------------------------------------------------ */

static int ipv8_release(struct socket *sock)
{
    struct sock *sk = sock->sk;

    if (!sk)
        return 0;

    ipv8_unregister_sock(sk);
    sock_orphan(sk);
    sock->sk = NULL;
    sock_put(sk);
    return 0;
}

static int ipv8_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sockaddr_in8 *addr = (struct sockaddr_in8 *)uaddr;
    struct ipv8_sock *i8sk   = ipv8_sk(sock->sk);

    if (addr_len < (int)sizeof(struct sockaddr_in8))
        return -EINVAL;
    if (addr->sin8_family != AF_INET8)
        return -EAFNOSUPPORT;

    i8sk->saddr = addr->sin8_addr;
    i8sk->sport = addr->sin8_port;

    return 0;
}

static int ipv8_connect(struct socket *sock, struct sockaddr *uaddr,
                        int addr_len, int flags)
{
    struct sockaddr_in8 *addr = (struct sockaddr_in8 *)uaddr;
    struct ipv8_sock *i8sk   = ipv8_sk(sock->sk);

    if (addr_len < (int)sizeof(struct sockaddr_in8))
        return -EINVAL;
    if (addr->sin8_family != AF_INET8)
        return -EAFNOSUPPORT;

    i8sk->daddr = addr->sin8_addr;
    i8sk->dport = addr->sin8_port;

    sock->state = SS_CONNECTED;
    return 0;
}

static int ipv8_getname(struct socket *sock, struct sockaddr *uaddr,
                        int peer)
{
    struct ipv8_sock *i8sk  = ipv8_sk(sock->sk);
    struct sockaddr_in8 *sa = (struct sockaddr_in8 *)uaddr;

    memset(sa, 0, sizeof(*sa));
    sa->sin8_family = AF_INET8;

    if (peer) {
        sa->sin8_addr = i8sk->daddr;
        sa->sin8_port = i8sk->dport;
    } else {
        sa->sin8_addr = i8sk->saddr;
        sa->sin8_port = i8sk->sport;
    }

    return sizeof(*sa);
}

static int ipv8_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct sock *sk       = sock->sk;
    struct ipv8_sock *i8  = ipv8_sk(sk);
    struct net *net       = sock_net(sk);
    struct sk_buff *skb;
    struct ipv8hdr *hdr;
    int err;

    /* Build a minimal skb carrying the IPv8 header + payload */
    skb = sock_alloc_send_skb(sk, IPV8_HDRLEN + len + 64, 0, &err);
    if (!skb)
        return err;

    skb_reserve(skb, 64);   /* headroom for lower-layer headers */

    /* Write payload */
    skb_put(skb, len);
    if (copy_from_iter(skb->data, len, &msg->msg_iter) != len) {
        kfree_skb(skb);
        return -EFAULT;
    }

    /* Push IPv8 header */
    hdr = (struct ipv8hdr *)skb_push(skb, IPV8_HDRLEN);
    memset(hdr, 0, IPV8_HDRLEN);

    hdr->version_ihl = (IPV8_VERSION << 4) | (IPV8_HDRLEN >> 2);
    hdr->tos         = i8->tos;
    hdr->tot_len     = htons(IPV8_HDRLEN + len);
    hdr->id          = 0;
    hdr->frag_off    = IPV8_DF;
    hdr->ttl         = i8->ttl ? i8->ttl : 64;
    hdr->protocol    = sk->sk_protocol;
    hdr->saddr       = i8->saddr;
    hdr->daddr       = i8->daddr;
    hdr->check       = 0;
    hdr->check       = ip_compute_csum(hdr, IPV8_HDRLEN);

    skb->protocol    = htons(ETH_P_IPV8);

    return ipv8_output(net, sk, skb);
}

static int ipv8_recvmsg(struct socket *sock, struct msghdr *msg,
                        size_t len, int flags)
{
    struct sock *sk    = sock->sk;
    struct sk_buff *skb;
    size_t copied;
    int err;

    skb = skb_recv_datagram(sk, flags, &err);
    if (!skb)
        return err;

    /* Return source address via recvfrom() / msg_name.
     * skb->network_header still points at the IPv8 header even after
     * ipv8_rcv stripped it from skb->data with skb_pull(). */
    if (msg->msg_name) {
        const struct ipv8hdr *net_hdr =
            (const struct ipv8hdr *)skb_network_header(skb);
        struct sockaddr_in8 *sin8 = msg->msg_name;

        memset(sin8, 0, sizeof(*sin8));
        sin8->sin8_family = AF_INET8;
        sin8->sin8_addr   = net_hdr->saddr;
        msg->msg_namelen  = sizeof(*sin8);
    }

    copied = min_t(size_t, len, skb->len);
    err = skb_copy_datagram_msg(skb, 0, msg, copied);
    if (!err) {
        if (flags & MSG_TRUNC)
            err = skb->len;
        else
            err = copied;
    }

    skb_free_datagram(sk, skb);
    return err;
}

static int ipv8_ioctl(struct socket *sock, unsigned int cmd,
                      unsigned long arg)
{
    switch (cmd) {
    case SIOCGIFADDR:
    case SIOCSIFADDR:
        /* Future: expose IPv8 interface addresses */
        return -EOPNOTSUPP;
    default:
        return -ENOIOCTLCMD;
    }
}

const struct proto_ops ipv8_dgram_ops = {
    .family     = PF_INET8,
    .owner      = THIS_MODULE,
    .release    = ipv8_release,
    .bind       = ipv8_bind,
    .connect    = ipv8_connect,
    .socketpair = sock_no_socketpair,
    .accept     = sock_no_accept,
    .getname    = ipv8_getname,
    .poll       = datagram_poll,
    .ioctl      = ipv8_ioctl,
    .listen     = sock_no_listen,
    .shutdown   = sock_no_shutdown,
    .sendmsg    = ipv8_sendmsg,
    .recvmsg    = ipv8_recvmsg,
    .mmap       = sock_no_mmap,
};

struct proto ipv8_prot = {
    .name     = "IPV8",
    .owner    = THIS_MODULE,
    .obj_size = sizeof(struct ipv8_sock),
};

/* ------------------------------------------------------------------ *
 * Address family – socket creation
 * ------------------------------------------------------------------ */

static int ipv8_sock_create(struct net *net, struct socket *sock,
                            int protocol, int kern)
{
    struct sock *sk;
    struct ipv8_sock *i8sk;

    if (sock->type != SOCK_DGRAM && sock->type != SOCK_RAW)
        return -ESOCKTNOSUPPORT;

    if (!ns_capable(net->user_ns, CAP_NET_RAW))
        return -EPERM;

    sk = sk_alloc(net, PF_INET8, GFP_KERNEL, &ipv8_prot, kern);
    if (!sk)
        return -ENOMEM;

    i8sk          = ipv8_sk(sk);
    i8sk->ttl     = 64;
    i8sk->tos     = 0;
    i8sk->hdrincl = (sock->type == SOCK_RAW);

    sock_init_data(sock, sk);
    ipv8_register_sock(sk);
    sk->sk_family   = PF_INET8;
    sk->sk_protocol = protocol;

    sock->ops   = &ipv8_dgram_ops;
    sock->state = SS_UNCONNECTED;

    return 0;
}

static const struct net_proto_family ipv8_family_ops = {
    .family = PF_INET8,
    .create = ipv8_sock_create,
    .owner  = THIS_MODULE,
};

/* ------------------------------------------------------------------ *
 * Module lifecycle
 * ------------------------------------------------------------------ */

static int __init ipv8_init(void)
{
    int err;

    pr_info("loading – draft-thain-ipv8 proof of concept\n");
    pr_info("  AF_INET8  = %d\n", AF_INET8);
    pr_info("  ETH_P_IPV8 = 0x%04x (provisional)\n", ETH_P_IPV8);
    pr_info("  Zone port  = %d  (provisional)\n", IPV8_ZONE_PORT);

    err = proto_register(&ipv8_prot, 1 /* alloc slab */);
    if (err) {
        pr_err("proto_register failed: %d\n", err);
        return err;
    }

    err = sock_register(&ipv8_family_ops);
    if (err) {
        pr_err("sock_register failed: %d\n", err);
        goto err_proto;
    }

    err = ipv8_input_init();
    if (err) {
        pr_err("input subsystem init failed: %d\n", err);
        goto err_sock;
    }

    err = ipv8_output_init();
    if (err) {
        pr_err("output subsystem init failed: %d\n", err);
        goto err_input;
    }

    err = ipv8_xlate_init();
    if (err) {
        pr_err("XLATE8 subsystem init failed: %d\n", err);
        goto err_output;
    }

    err = ipv8_zone_init();
    if (err) {
        pr_err("zone subsystem init failed: %d\n", err);
        goto err_xlate;
    }

    pr_info("loaded successfully\n");
    return 0;

err_xlate:
    ipv8_xlate_exit();
err_output:
    ipv8_output_exit();
err_input:
    ipv8_input_exit();
err_sock:
    sock_unregister(PF_INET8);
err_proto:
    proto_unregister(&ipv8_prot);
    return err;
}

static void __exit ipv8_exit(void)
{
    ipv8_zone_exit();
    ipv8_xlate_exit();
    ipv8_output_exit();
    ipv8_input_exit();
    sock_unregister(PF_INET8);
    proto_unregister(&ipv8_prot);
    pr_info("unloaded\n");
}

module_init(ipv8_init);
module_exit(ipv8_exit);
