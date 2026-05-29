# ipv8-poc

A Linux kernel module implementing **Internet Protocol Version 8 (IPv8)**,
as described in [draft-thain-ipv8](https://datatracker.ietf.org/doc/draft-thain-ipv8/) — an IETF individual submission
that extends IPv4 with 64-bit addresses, an embedded ASN routing prefix,
and a unified Zone Server management plane.

> **Status**: proof-of-concept — no production use.  
> The draft expires October 2026 unless renewed.

---

## Table of contents

1. [What is IPv8?](#what-is-ipv8)
2. [Repository layout](#repository-layout)
3. [QUICKSTART](#quickstart)
4. [Dependencies](#dependencies)
5. [Build](#build)
6. [Load & configure](#load--configure)
7. [Running the tests](#running-the-tests)
8. [Testing with ping8](#testing-with-ping8)
9. [Key constants](#key-constants)
10. [Architecture overview](#architecture-overview)
11. [Limitations](#limitations)
12. [References](#references)

---

## What is IPv8?

IPv8 solves IPv4 address exhaustion without requiring a dual-stack migration.
Its 64-bit address is split into two 32-bit halves:

```
 <ASN prefix r.r.r.r> . <host n.n.n.n>
```

Every Autonomous System Number (ASN) holder receives 2³² host addresses.
An address with `asn == 0.0.0.0` is a backward-compatible IPv4 address,
so legacy stacks need no changes.

A **Zone Server** co-locates the services a network segment needs: address
assignment (DHCP8), name resolution (DNS8), time sync (NTP8), authentication
(OAuth8), access control (ACL8), and IPv4↔IPv8 translation (XLATE8).

---

## Repository layout

```
ipv8-poc/
├── kernel/              Linux kernel module (GPL-2.0-or-later)
│   ├── Makefile
│   ├── ipv8.h           On-wire types, constants, cross-file declarations
│   ├── ipv8_main.c      AF_INET8 address family, socket operations
│   ├── ipv8_input.c     EtherType 0x0888 receive handler
│   ├── ipv8_output.c    Static route table, neighbour/ARP resolution
│   ├── ipv8_xlate.c     XLATE8: Netfilter-based IPv4↔IPv8 translation
│   └── ipv8_zone.c      Zone Server cache + /proc/net interfaces
├── tools/               Userspace tools (no extra dependencies)
│   ├── Makefile
│   ├── ipv8_tools.h     Shared header: address types, ICMP helpers, zone lookup
│   ├── ping8.c          ICMP Echo client (ping over IPv8)
│   └── ipv8_echod.c     ICMP Echo server (test peer / loopback daemon)
└── tests/
    ├── Makefile
    ├── smoke.sh         Shell smoke tests (TAP, 17 cases, requires root)
    └── sock_test.c      Userspace socket API tests (TAP, 10 cases)
```

---

## QUICKSTART

> The full dependency list is in the [Dependencies](#dependencies) section.
> These commands assume a Debian/Ubuntu host; adapt package names for your
> distribution.

```bash
# 1. Install build dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    gcc \
    make \
    perl            # for prove(1) – optional

# 2. Clone the repo (if you haven't already)
git clone https://github.com/maltejk/ipv8-poc.git
cd ipv8-poc

# 3. Build the kernel module and userspace tools
cd kernel && make && cd ..
cd tools  && make && cd ..

# 4. Load the module
sudo insmod kernel/ipv8.ko
dmesg | grep ipv8    # should print "loaded successfully"

# 5. Set the local ASN and Zone Server address
echo 'zone_server 65001.0.0.1 10.0.0.1' | sudo tee /proc/net/ipv8_config

# 6. Add a zone cache entry manually
#    Format: <name> <asn> <host> [ttl-seconds]
echo 'peer.example.com 65001.0.0.1 203.0.113.7 300' | sudo tee /proc/net/ipv8_zone

# 7. Ping a v4-compat address (loopback self-test, no second machine needed)
sudo tools/ping8 -c 4 127.0.0.1

# 8. Run the smoke tests
cd tests && make run   # requires root; runs both shell and C suites

# 9. Unload the module when done
sudo rmmod ipv8
```

---

## Dependencies

### Build-time

| Dependency | Minimum version | Notes |
|---|---|---|
| Linux kernel headers | 5.10 | Must match the running kernel (`uname -r`) |
| GCC | 9.0 | C11 support required |
| GNU Make | 4.0 | |
| `linux-headers-$(uname -r)` | matching kernel | Debian/Ubuntu package name |

On **Fedora / RHEL**:
```bash
sudo dnf install kernel-devel-$(uname -r) gcc make
```

On **Arch Linux**:
```bash
sudo pacman -S linux-headers base-devel
```

### Run-time

| Requirement | Why |
|---|---|
| Linux kernel ≥ 5.10 | `static_assert`, `proc_ops`, `nf_register_net_hooks` API |
| `CAP_NET_ADMIN` + `CAP_NET_RAW` | `insmod`, socket creation, Netfilter hooks |
| IPv4 networking enabled | XLATE8 hooks attach to the IPv4 Netfilter chain |
| `CONFIG_NETFILTER=y` | Required by `ipv8_xlate.c` |
| `CONFIG_PROC_FS=y` | Required by `ipv8_zone.c` |

Verify your kernel has the required options:
```bash
grep -E 'CONFIG_NETFILTER|CONFIG_PROC_FS' /boot/config-$(uname -r)
```

### Tools (`tools/`)

| Dependency | Why |
|---|---|
| GCC | Compile `ping8` and `ipv8_echod` |
| glibc (standard) | No extra libraries; `-lm` for `sqrt` in ping8 stats |

### Test-time (optional)

| Dependency | Why |
|---|---|
| GCC | Compile `tests/sock_test.c` |
| `perl` / `prove` | TAP test harness (optional; tests print TAP without it) |

---

## Build

```bash
# Kernel module
cd kernel
make                         # build against the running kernel (default)
make KDIR=/path/to/linux-build   # build against a specific kernel tree
make clean
cd ..

# Userspace tools
cd tools
make          # produces ./ping8 and ./ipv8_echod
make clean
cd ..
```

A successful kernel build produces `kernel/ipv8.ko`.

---

## Load & configure

```bash
# Load
sudo insmod kernel/ipv8.ko

# Confirm
lsmod | grep ipv8
dmesg | grep ipv8

# Set the local ASN (r.r.r.r notation for a 32-bit value)
# and the Zone Server's IPv8 address
echo 'zone_server <asn> <host>' | sudo tee /proc/net/ipv8_config

# Populate the zone cache manually
# Format: <name> <asn> <host> [ttl-seconds]
echo 'myhost 65001.0.0.1 192.0.2.1 600' | sudo tee /proc/net/ipv8_zone

# Read the cache
cat /proc/net/ipv8_zone

# Unload
sudo rmmod ipv8
```

---

## Running the tests

Both test programs output [TAP version 13](https://testanything.org/) and
can be driven by `prove(1)` or the kernel kselftest harness.

```bash
cd tests

# Build the C binary
make

# Run everything (builds the module too, then loads/unloads it automatically)
make run

# Run only the shell smoke tests
make run-shell

# Run only the C socket tests (module must already be loaded)
make run-sock

# Or drive directly with prove
sudo prove -e bash smoke.sh
sudo prove sock_test
```

Expected output summary:

```
=== Running shell smoke tests ===
TAP version 13
1..17
ok 1 - module not loaded before test begins
...
ok 17 - /proc/net entries removed after rmmod
# Passed: 17 / 17

=== Running userspace socket tests ===
TAP version 13
1..10
ok 1 - socket(AF_INET8, SOCK_STREAM) → ESOCKTNOSUPPORT
...
ok 10 - 64 sockets created and closed without error
# Result: 10/10 passed
```

---

## Testing with ping8

The `tools/` directory provides two programs for exercising the full
packet path end-to-end:

| Tool | Role |
|---|---|
| `ping8` | Sends ICMP Echo Requests over `AF_INET8`; reports RTT and loss |
| `ipv8_echod` | Listens for ICMP Echo Requests and replies; acts as the remote peer |

Both require root and the ipv8 kernel module to be loaded.

### Build the tools

```bash
cd tools
make          # produces ./ping8 and ./ipv8_echod
```

### Scenario 1 — v4-compat loopback (single machine)

IPv8 addresses with ASN `0.0.0.0` are backward-compatible IPv4 addresses.
XLATE8 translates them to IPv4 and back, so you can exercise the full
module stack without a second host.

```bash
# Terminal 1: start the echo daemon (handles the ICMP replies)
sudo tools/ipv8_echod -v

# Terminal 2: ping the loopback address (plain host, ASN = 0.0.0.0)
sudo tools/ping8 -c 4 127.0.0.1
```

Expected output (Terminal 2):

```
PING8 127.0.0.1 (127.0.0.1): 56 data bytes, id=0x1a2b
64 bytes from 127.0.0.1: icmp8_seq=0 ttl=64 time=0.312 ms
64 bytes from 127.0.0.1: icmp8_seq=1 ttl=64 time=0.271 ms
64 bytes from 127.0.0.1: icmp8_seq=2 ttl=64 time=0.289 ms
64 bytes from 127.0.0.1: icmp8_seq=3 ttl=64 time=0.304 ms

--- 127.0.0.1 ping8 statistics ---
4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max/stddev = 0.271/0.294/0.312/0.015 ms
```

### Scenario 2 — two hosts on the same LAN

Run the module on both machines.  Replace the addresses below with your
actual ASN and host allocations.

```bash
# On host B (10.0.0.2) – start the echo daemon
sudo insmod kernel/ipv8.ko
echo 'zone_server 65001.0.0.1 10.0.0.2' | sudo tee /proc/net/ipv8_config
sudo tools/ipv8_echod -v -b 65001.0.0.1:10.0.0.2

# On host A (10.0.0.1) – ping host B by full IPv8 address
sudo insmod kernel/ipv8.ko
echo 'zone_server 65001.0.0.1 10.0.0.1' | sudo tee /proc/net/ipv8_config
sudo tools/ping8 65001.0.0.1:10.0.0.2
```

Expected output (host A):

```
PING8 65001.0.0.1:10.0.0.2 (65001.0.0.1:10.0.0.2): 56 data bytes, id=0x3c7f
64 bytes from 65001.0.0.1:10.0.0.2: icmp8_seq=0 ttl=64 time=1.042 ms
64 bytes from 65001.0.0.1:10.0.0.2: icmp8_seq=1 ttl=64 time=0.998 ms
^C
--- 65001.0.0.1:10.0.0.2 ping8 statistics ---
2 packets transmitted, 2 received, 0% packet loss
rtt min/avg/max/stddev = 0.998/1.020/1.042/0.022 ms
```

### Scenario 3 — ping by name via zone cache

The zone cache (`/proc/net/ipv8_zone`) acts as a local DNS8 resolver.
Register a name, then use it as the ping8 target.

```bash
# Register the peer under a friendly name (TTL = 600 seconds)
echo 'db.internal 65001.0.0.1 10.0.0.3 600' | sudo tee /proc/net/ipv8_zone

# Confirm the entry is visible
cat /proc/net/ipv8_zone
# NAME                             ASN          HOST         TTL(s)
# db.internal                      65001.0.0.1  10.0.0.3     600

# Ping by name
sudo tools/ping8 -c 3 db.internal
```

### ping8 reference

```
Usage: ping8 [options] <target>

Target:
  65001.0.0.1:10.0.0.2   full IPv8 address (ASN:host, dotted-decimal)
  10.0.0.1               v4-compat address (ASN = 0.0.0.0)
  db.internal            name looked up in /proc/net/ipv8_zone

Options:
  -c <n>    stop after n packets          (default: unlimited)
  -i <ms>   interval between packets      (default: 1000 ms)
  -t <ttl>  IPv8 TTL field value          (default: 64)
  -W <ms>   reply wait timeout            (default: 2000 ms)
  -s <n>    extra payload bytes           (default: 56)
  -v        verbose: print unexpected packets
  -h        show this help
```

### ipv8_echod reference

```
Usage: ipv8_echod [options]

Options:
  -b <addr>  IPv8 address to bind (default: any)
             Format: 'asn:host' or 'host' (v4-compat)
  -v         verbose: log every request and reply
  -h         show this help
```

---

## Key constants

| Constant | Value | Notes |
|---|---|---|
| `ETH_P_IPV8` | `0x0888` | Provisional EtherType (no IANA assignment) |
| `AF_INET8` / `PF_INET8` | `47` | Above Linux 6.x `AF_MAX=46`; adjust if needed |
| `IPV8_HDRLEN` | `28` bytes | IPv4 (20 B) + 2 × 4 extra bytes for wider addresses |
| `IPV8_VERSION` | `8` | Value written to the header's version field |
| `IPV8_ZONE_PORT` | `8538` | Provisional Zone Server UDP port (no IANA assignment) |

---

## Architecture overview

```
Userspace
  │  socket(AF_INET8, SOCK_DGRAM, 0)
  │  bind / connect / sendmsg / recvmsg
  ▼
┌─────────────────────────────────────────────────────────────┐
│ ipv8_main.c  – AF_INET8 address family & proto_ops          │
└──────┬──────────────────────────────┬───────────────────────┘
       │ Transmit                     │ Receive
       ▼                              ▼
┌─────────────────┐         ┌──────────────────────┐
│ ipv8_output.c   │         │ ipv8_input.c          │
│ Route lookup    │         │ EtherType 0x0888 hook │
│ ARP/neighbour   │         │ Header validation     │
│ resolution      │         │ Checksum verify       │
└────────┬────────┘         └──────────┬───────────┘
         │                             │
         ▼                             ▼
┌──────────────────────────────────────────────────┐
│ ipv8_xlate.c  – XLATE8                           │
│ NF_INET_PRE_ROUTING  : IPv4→IPv8 rewrite         │
│ NF_INET_POST_ROUTING : IPv4→IPv8 wrap (zone hit) │
│ ipv8_xlate_8to4()    : IPv8→IPv4 unwrap          │
└──────────────────────┬───────────────────────────┘
                       │ name lookup
                       ▼
┌──────────────────────────────────────────────────┐
│ ipv8_zone.c  – Zone Server cache                 │
│ RCU hashtable  (64 buckets)                      │
│ /proc/net/ipv8_zone    – cache dump + inserts    │
│ /proc/net/ipv8_config  – zone server address     │
└──────────────────────────────────────────────────┘
```

### Address translation (XLATE8)

| Direction | Trigger | Result |
|---|---|---|
| IPv4 → IPv8 | Incoming IPv4 dest matches configured XLATE8 prefix | Header rewritten; ASN set to `local_asn`; re-injected into IPv8 path |
| IPv8 → IPv4 | `daddr.asn == 0` (v4-compat address) | Header shrunk by 8 bytes; forwarded as plain IPv4 |
| Outgoing | Zone cache hit for IPv4 dest | IPv4 packet wrapped in IPv8 header on POSTROUTING |

---

## Limitations

- **No production use.** This is a PoC for an individual IETF draft that
  has not been adopted by any working group.
- `AF_INET8 = 47` and `ETH_P_IPV8 = 0x0888` are **provisional** — no IANA
  assignments exist yet.  If your kernel defines `AF_MAX >= 47`, change
  `AF_INET8` in `kernel/ipv8.h`.
- Routing is static (manual entries); no BGP8 or OSPF8 daemon is included.
- Zone Server queries are not yet implemented — the cache must be seeded
  manually via `/proc/net/ipv8_zone` or `ipv8_zone_update()`.
- `SOCK_STREAM` (TCP over IPv8) is not implemented.
- Only the default network namespace (`init_net`) is supported.

---

## References

- [draft-thain-ipv8-02 — Internet Protocol Version 8](https://datatracker.ietf.org/doc/draft-thain-ipv8/)
- [draft-thain-zoneserver-00 — Zone Server Architecture](https://datatracker.ietf.org/doc/draft-thain-zoneserver/)
- [draft-thain-routing-protocols-00 — BGP8 / OSPF8 / IS-IS8](https://datatracker.ietf.org/doc/draft-thain-routing-protocols/)
- [ipv8.es — Project home page](https://ipv8.es/en/)
- [The Register — IPv8 coverage](https://www.theregister.com/networks/2026/05/12/veteran-network-architect-proposes-ipv8-to-improve-ipv4-not-leapfrog-v6/5238474)
