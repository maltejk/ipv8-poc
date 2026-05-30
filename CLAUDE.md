# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **AI agents**: read `AGENTS.md` before making any changes — it contains the mandatory pre-commit checklist, build constraints, repo conventions, and known sharp edges that are not repeated here.

---

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

---

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

### Packet flow

**Receive**: NIC → `ipv8_rcv` (EtherType hook) → `ipv8_hdr_ok` (validate + checksum) → v4-compat? → `ipv8_xlate_8to4` + `netif_rx` : `ipv8_find_sock` + `sock_queue_rcv_skb`.

**Transmit**: `ipv8_sendmsg` → `ipv8_output` → v4-compat? → `ipv8_xlate_8to4` + `netif_rx` : route lookup (RCU) → `ipv8_neigh_output` (ARP → device queue).

**XLATE8 PREROUTING**: incoming IPv4 with dest in configured prefix → `ipv8_xlate_4to8(skb, &local_dst)` (save `iph->daddr` before skb data moves) → `ipv8_rcv`.

**XLATE8 POSTROUTING**: outgoing IPv4 with zone cache hit → `ipv8_xlate_4to8(skb, &dst8)` → `skb_reset_network_header` → `ipv8_output` → `NF_STOLEN`.

### Procfs interface

`/proc/net/ipv8_config` accepts three write commands:
```
zone_server <asn> <host>             # e.g. zone_server 0.0.253.233 10.0.0.1
local_asn <asn>                      # e.g. local_asn 0.0.253.233
xlate_prefix <prefix> <mask>         # e.g. xlate_prefix 203.0.113.0 255.255.255.0
```

`/proc/net/ipv8_zone` accepts entries in the format:
```
<name> <asn> <host> [ttl-seconds]
```
