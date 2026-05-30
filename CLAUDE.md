# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build commands

```bash
# Kernel module (requires kernel headers for the running kernel)
cd kernel && make              # builds kernel/ipv8.ko
cd kernel && make clean

# Userspace tools (no extra dependencies)
cd tools && make               # builds tools/ping8 and tools/ipv8_echod
cd tools && make clean

# Tests
cd tests && make               # builds tests/sock_test
cd tests && make run           # builds everything, runs all tests (requires root)
cd tests && make run-shell     # shell smoke tests only (requires root)
cd tests && make run-sock      # C socket tests only (requires root + module loaded)
```

Kernel headers are **not available** in the agent sandbox — you cannot run `make` in `kernel/`. Run the static audit below instead of a live build.

## Pre-commit audit (mandatory before every kernel change)

**1. No missing prototypes** — every non-`static` function in a `.c` file must have a declaration in `kernel/ipv8.h`:
```bash
grep -hEo '^(int|void|struct [a-z_]+ \*|__sum16|bool|u[0-9]+) [a-z_][a-z0-9_]+\(' \
  kernel/*.c | grep -v '^static' | sed 's/[( ].*//; s/.* //' | sort -u \
| while read fn; do grep -q "$fn" kernel/ipv8.h || echo "MISSING: $fn"; done
```

**2. No stale kernel APIs** — these are removed and must not appear:
```bash
grep -rn "strlcpy\|strlcat\|SK_DEFAULT_SNDBUF" kernel/
```
Replacements: `strlcpy` → `strscpy`, `SK_DEFAULT_SNDBUF` → remove (already set by `sock_init_data`).

**3. No missing `#include`s** — common omissions: `<linux/jhash.h>` for `jhash`, `<linux/string.h>` for `strscpy`, `<linux/rcupdate.h>` for `synchronize_rcu`/`call_rcu`/`rcu_barrier`.

## Architecture

The module is split into five compilation units linked into a single `ipv8.ko`:

| File | Role |
|---|---|
| `ipv8_main.c` | Module init/exit; `AF_INET8` socket family and `proto_ops`; socket registry |
| `ipv8_input.c` | `dev_add_pack` handler for EtherType `0x0888`; header validation; socket demux |
| `ipv8_output.c` | `ipv8_output()` entry point; static route table (RCU list); ARP/neighbour resolution |
| `ipv8_xlate.c` | Netfilter hooks for stateless IPv4↔IPv8 header rewriting (PREROUTING + POSTROUTING) |
| `ipv8_zone.c` | RCU hashtable name→address cache; `/proc/net/ipv8_zone` and `/proc/net/ipv8_config` |

`kernel/ipv8.h` is the single shared header — all cross-file types, constants, and declarations live there.

### Critical constraints

**AF number**: `AF_INET8 = 19`. Linux 6.x sets `AF_MAX = NPROTO = 46`; anything ≥ 46 is rejected by `sock_register()`. Slot 19 (`AF_ECONET`) has been vacant since Linux 3.5. The number appears in four files — keep them in sync: `kernel/ipv8.h`, `tools/ipv8_tools.h`, `tests/sock_test.c`, `README.md`.

**Checksum semantics**: `ip_compute_csum()` with the checksum field included returns `0x0000` for a valid header (csum_fold applies `~sum`). Check `!= 0`, not `!= 0xffff`.

**Socket registry**: `ipv8_main.c` maintains `ipv8_sklist` (an hlist) protected by `ipv8_sklist_lock` (spinlock). Process-context callers use `spin_lock_bh`; softirq callers (`ipv8_find_sock` from `ipv8_rcv`) use plain `spin_lock`.

**neigh_output ownership**: `neigh_output()` always consumes the skb regardless of return value. Never call `kfree_skb` after it returns an error.

**RCU discipline**: route entries use `list_del_rcu` + `kfree_rcu`; zone entries use `hash_del_rcu` + `call_rcu`. Always call `rcu_barrier()` before freeing all entries during module unload.

**ASN address format**: ASNs must be valid dotted-quad (each octet 0-255). `in4_pton` and `inet_pton` both enforce this. AS65001 = `0x0000FDE9` = `0.0.253.233`, **not** `65001.0.0.1`.

### Packet flow

**Receive**: NIC → `ipv8_rcv` (EtherType hook) → `ipv8_hdr_ok` (validate + checksum) → v4-compat? → `ipv8_xlate_8to4` + `netif_rx` : `ipv8_find_sock` + `sock_queue_rcv_skb`.

**Transmit**: `ipv8_sendmsg` → `ipv8_output` → v4-compat? → `ipv8_xlate_8to4` + `netif_rx` : route lookup (RCU) → `ipv8_neigh_output` (ARP → device queue).

**XLATE8 PREROUTING**: incoming IPv4 with dest in configured prefix → `ipv8_xlate_4to8(skb, &local_dst)` (save `iph->daddr` before skb data moves) → `ipv8_rcv`.

**XLATE8 POSTROUTING**: outgoing IPv4 with zone cache hit → `ipv8_xlate_4to8(skb, &dst8)` → `skb_reset_network_header` → `ipv8_output` → `NF_STOLEN`.

### Procfs interface

`/proc/net/ipv8_config` accepts three write commands:
```
zone_server <asn> <host>          # e.g. zone_server 0.0.253.233 10.0.0.1
local_asn <asn>                   # e.g. local_asn 0.0.253.233
xlate_prefix <prefix> <mask>      # e.g. xlate_prefix 203.0.113.0 255.255.255.0
```

`/proc/net/ipv8_zone` accepts entries in the format:
```
<name> <asn> <host> [ttl-seconds]
```

## Known sharp edges

| Symptom | Cause |
|---|---|
| `sock_register failed: -105` | `AF_INET8 ≥ NPROTO`; must be 19 |
| `module verification failed / taints kernel` | Expected on Debian/Ubuntu; harmless for PoC |
| proc write returns `-EINVAL` for zone/config | ASN component > 255 (e.g. `65001.0.0.1`); use proper dotted-quad |
| `dmesg \| grep ipv8 \| tail -5` misses ETH_P_IPV8 line | Module emits ~11 ipv8 lines; use `tail -20` |
