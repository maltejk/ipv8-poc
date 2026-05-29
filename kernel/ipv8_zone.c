// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ipv8_zone.c - Zone Server client and address cache
 *
 * The Zone Server (draft-thain-zoneserver-00) is the single management
 * plane for an IPv8 network segment.  It answers queries for DHCP8,
 * DNS8, NTP8, OAuth8, ACL8, and XLATE8.  This module provides:
 *
 *   1. An in-kernel RCU-protected cache keyed by host name or IPv4
 *      address string → struct in8_addr.
 *
 *   2. A procfs read interface at /proc/net/ipv8_zone showing current
 *      cache contents.
 *
 *   3. A procfs write interface at /proc/net/ipv8_config for setting
 *      the Zone Server address and the local ASN.
 *
 * Cache population in this PoC is manual (write to /proc/net/ipv8_zone)
 * or via ipv8_zone_update() called from the XLATE8 layer.  A full
 * implementation would send UDP queries to the Zone Server on port
 * IPV8_ZONE_PORT and parse the binary TLV response.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <net/net_namespace.h>

#include "ipv8.h"

/* ------------------------------------------------------------------ *
 * Cache storage
 * ------------------------------------------------------------------ */

static DEFINE_HASHTABLE(zone_cache, IPV8_ZONE_HTABLE_BITS);
static DEFINE_SPINLOCK(zone_lock);

static unsigned int zone_entry_count;

/* ------------------------------------------------------------------ *
 * Zone Server address (set from /proc/net/ipv8_config)
 * ------------------------------------------------------------------ */

static struct in8_addr zone_server_addr __read_mostly;   /* 0 == unconfigured */

/* ------------------------------------------------------------------ *
 * Internal helpers
 * ------------------------------------------------------------------ */

static u32 zone_hash(const char *name)
{
    return jhash(name, strlen(name), 0x9e3779b9u);
}

static void zone_entry_free_rcu(struct rcu_head *head)
{
    struct ipv8_zone_entry *e =
        container_of(head, struct ipv8_zone_entry, rcu);
    kfree(e);
}

/*
 * __zone_find - look up a name while holding zone_lock or under rcu_read_lock
 *
 * Returns the entry or NULL.  Does not take any lock itself.
 */
static struct ipv8_zone_entry *__zone_find(const char *name)
{
    struct ipv8_zone_entry *e;
    u32 key = zone_hash(name);

    hash_for_each_possible_rcu(zone_cache, e, hnode, key) {
        if (strncmp(e->name, name, IPV8_ZONE_NAME_MAX) == 0)
            return e;
    }
    return NULL;
}

/* ------------------------------------------------------------------ *
 * Public API
 * ------------------------------------------------------------------ */

/**
 * ipv8_zone_lookup - look up a name in the zone cache
 * @net:  network namespace (reserved for future per-ns caches)
 * @name: host name or IPv4 address string to resolve
 * @out:  on success, receives the resolved IPv8 address
 *
 * Returns 0 on a cache hit, -ENOENT if unknown or expired.
 */
int ipv8_zone_lookup(struct net *net, const char *name, struct in8_addr *out)
{
    struct ipv8_zone_entry *e;
    int ret = -ENOENT;

    rcu_read_lock();
    e = __zone_find(name);
    if (e) {
        if (time_before(jiffies, e->expires)) {
            *out = e->addr;
            ret  = 0;
        }
        /* Expired entries stay until evicted by ipv8_zone_update */
    }
    rcu_read_unlock();
    return ret;
}

/**
 * ipv8_zone_update - insert or refresh a cache entry
 * @net:     network namespace
 * @name:    key (host name or stringified IPv4 address)
 * @addr:    IPv8 address to store
 * @ttl_sec: time-to-live in seconds (0 → use default)
 */
void ipv8_zone_update(struct net *net, const char *name,
                      const struct in8_addr *addr, u32 ttl_sec)
{
    struct ipv8_zone_entry *e, *old = NULL;
    u32 key;

    if (!ttl_sec)
        ttl_sec = IPV8_ZONE_DEFAULT_TTL;

    /* Check for existing entry without the write lock first */
    rcu_read_lock();
    old = __zone_find(name);
    rcu_read_unlock();

    if (old) {
        /* Update in place; no need to reallocate */
        spin_lock(&zone_lock);
        old = __zone_find(name);   /* re-check under lock */
        if (old) {
            old->addr    = *addr;
            old->expires = jiffies + ttl_sec * HZ;
            spin_unlock(&zone_lock);
            return;
        }
        spin_unlock(&zone_lock);
    }

    e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e)
        return;

    strlcpy(e->name, name, IPV8_ZONE_NAME_MAX);
    e->addr    = *addr;
    e->expires = jiffies + ttl_sec * HZ;
    key        = zone_hash(name);

    spin_lock(&zone_lock);
    /* Evict any now-stale entry for the same name */
    old = __zone_find(name);
    if (old) {
        hash_del_rcu(&old->hnode);
        zone_entry_count--;
        call_rcu(&old->rcu, zone_entry_free_rcu);
    }
    hash_add_rcu(zone_cache, &e->hnode, key);
    zone_entry_count++;
    spin_unlock(&zone_lock);
}

/* ------------------------------------------------------------------ *
 * Procfs: /proc/net/ipv8_zone  (cache dump + manual insertion)
 * ------------------------------------------------------------------ */

static int zone_seq_show(struct seq_file *m, void *v)
{
    struct ipv8_zone_entry *e;
    int bkt;
    long rem;

    seq_puts(m, "# NAME                            ASN          HOST         TTL(s)\n");

    rcu_read_lock();
    hash_for_each_rcu(zone_cache, bkt, e, hnode) {
        rem = (long)(e->expires - jiffies) / HZ;
        seq_printf(m, "%-32s %pI4 %pI4 %ld\n",
                   e->name,
                   &e->addr.asn,
                   &e->addr.host,
                   rem > 0 ? rem : 0L);
    }
    rcu_read_unlock();
    return 0;
}

/*
 * Write format: "name <asn> <host> [ttl]\n"
 * Example:       "host.example.com 65001.0.0.1 203.0.113.7 300\n"
 *
 * For simplicity the ASN and host are written as dotted-decimal IPv4
 * representations of the 32-bit values.
 */
static ssize_t zone_proc_write(struct file *file, const char __user *ubuf,
                               size_t count, loff_t *ppos)
{
    char buf[128];
    char name[IPV8_ZONE_NAME_MAX];
    char asn_str[16], host_str[16];
    struct in8_addr addr;
    u32 ttl = 0;
    int n;

    if (count >= sizeof(buf))
        return -EINVAL;

    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;

    buf[count] = '\0';

    n = sscanf(buf, "%63s %15s %15s %u", name, asn_str, host_str, &ttl);
    if (n < 3)
        return -EINVAL;

    if (!in4_pton(asn_str, -1, (u8 *)&addr.asn, -1, NULL))
        return -EINVAL;
    if (!in4_pton(host_str, -1, (u8 *)&addr.host, -1, NULL))
        return -EINVAL;

    ipv8_zone_update(NULL, name, &addr, ttl);
    return count;
}

static int zone_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, zone_seq_show, NULL);
}

static const struct proc_ops zone_proc_ops = {
    .proc_open    = zone_proc_open,
    .proc_read    = seq_read,
    .proc_write   = zone_proc_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ------------------------------------------------------------------ *
 * Procfs: /proc/net/ipv8_config
 * ------------------------------------------------------------------ */

static int config_seq_show(struct seq_file *m, void *v)
{
    __be32 asn  = zone_server_addr.asn;
    __be32 host = zone_server_addr.host;

    seq_printf(m, "zone_server  %pI4 %pI4\n", &asn, &host);
    seq_printf(m, "zone_port    %u\n", IPV8_ZONE_PORT);
    seq_printf(m, "cache_entries %u\n", zone_entry_count);
    return 0;
}

/*
 * Write format: "zone_server <asn> <host>\n"
 * Example:       "zone_server 65001.0.0.1 10.0.0.1\n"
 */
static ssize_t config_proc_write(struct file *file, const char __user *ubuf,
                                 size_t count, loff_t *ppos)
{
    char buf[64], key[32], asn_str[16], host_str[16];
    struct in8_addr addr;

    if (count >= sizeof(buf))
        return -EINVAL;
    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;

    buf[count] = '\0';

    if (sscanf(buf, "%31s %15s %15s", key, asn_str, host_str) != 3)
        return -EINVAL;

    if (strcmp(key, "zone_server") != 0)
        return -EINVAL;

    if (!in4_pton(asn_str,  -1, (u8 *)&addr.asn,  -1, NULL) ||
        !in4_pton(host_str, -1, (u8 *)&addr.host, -1, NULL))
        return -EINVAL;

    WRITE_ONCE(zone_server_addr.asn,  addr.asn);
    WRITE_ONCE(zone_server_addr.host, addr.host);

    pr_info("zone: server set to %pI4.%pI4\n", &addr.asn, &addr.host);
    return count;
}

static int config_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, config_seq_show, NULL);
}

static const struct proc_ops config_proc_ops = {
    .proc_open    = config_proc_open,
    .proc_read    = seq_read,
    .proc_write   = config_proc_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ------------------------------------------------------------------ *
 * Expiry sweeper (runs on modunload only; production would use a timer)
 * ------------------------------------------------------------------ */

static void zone_flush_all(void)
{
    struct ipv8_zone_entry *e;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&zone_lock);
    hash_for_each_safe(zone_cache, bkt, tmp, e, hnode) {
        hash_del(&e->hnode);
        kfree(e);
    }
    zone_entry_count = 0;
    spin_unlock(&zone_lock);
}

/* ------------------------------------------------------------------ *
 * Subsystem lifecycle
 * ------------------------------------------------------------------ */

int __init ipv8_zone_init(void)
{
    hash_init(zone_cache);

    if (!proc_create("ipv8_zone",   0644, init_net.proc_net, &zone_proc_ops)   ||
        !proc_create("ipv8_config", 0644, init_net.proc_net, &config_proc_ops)) {
        pr_err("zone: failed to create /proc/net entries\n");
        remove_proc_entry("ipv8_zone",   init_net.proc_net);
        remove_proc_entry("ipv8_config", init_net.proc_net);
        return -ENOMEM;
    }

    pr_info("zone: cache ready; "
            "configure via /proc/net/ipv8_zone and /proc/net/ipv8_config\n");
    return 0;
}

void ipv8_zone_exit(void)
{
    remove_proc_entry("ipv8_zone",   init_net.proc_net);
    remove_proc_entry("ipv8_config", init_net.proc_net);
    zone_flush_all();
    pr_info("zone: flushed %u entries\n", zone_entry_count);
}
