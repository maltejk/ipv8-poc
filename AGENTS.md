# AGENTS.md — Instructions for AI agents

This file tells AI coding agents how to work safely and effectively in this
repository.  Read it before making any change.

---

## What this repo is

A Linux kernel module implementing **draft-thain-ipv8** (Internet Protocol
Version 8), plus userspace tools and tests.  It is a proof-of-concept — not
production code — but it must compile and load cleanly on a real kernel.

---

## Mandatory pre-commit checklist

Before committing any change to `kernel/`, run through every item below.
The user builds on Debian 13 arm64 with Linux 6.12 and `-Werror` in CFLAGS.
Broken builds reach the user before they reach you; fix them first.

### 1. No missing prototypes (`-Werror=missing-prototypes`)

Every non-`static` function in a `.c` file must have a matching declaration
in `kernel/ipv8.h`.  Run this to verify:

```bash
grep -hEo '^(int|void|struct [a-z_]+ \*|__sum16|bool|u[0-9]+) [a-z_][a-z0-9_]+\(' \
  kernel/*.c | grep -v '^static' | sed 's/[( ].*//; s/.* //' | sort -u \
| while read fn; do
    grep -q "$fn" kernel/ipv8.h || echo "MISSING: $fn"
  done
```

If a function is only used within its own `.c` file, make it `static` instead.
If it is unused entirely, delete it — an unused static function is also a
`-Werror` (`-Wunused-function`).

### 2. No removed kernel APIs

These APIs were removed and must not be used:

| Removed API | Replacement | Since |
|---|---|---|
| `strlcpy` / `strlcat` | `strscpy` / `strscpy_pad` | kernel 6.8 |
| `SK_DEFAULT_SNDBUF` | (remove; `sock_init_data` sets it) | — |

Scan before committing:
```bash
grep -rn "strlcpy\|strlcat\|SK_DEFAULT_SNDBUF" kernel/
```

### 3. No missing `#include`s

Key headers that are easy to forget:

| Function / macro | Header |
|---|---|
| `jhash` | `<linux/jhash.h>` |
| `strscpy` | `<linux/string.h>` |
| `synchronize_rcu`, `call_rcu`, `rcu_barrier` | `<linux/rcupdate.h>` |
| `nf_register_net_hooks` | `<linux/netfilter.h>` |
| `ip_route_output_key` | `<net/route.h>` |
| `dst_neigh_lookup`, `neigh_output` | `<net/neighbour.h>` |

### 4. AF_INET8 = 19 everywhere

`AF_INET8` is defined as **19** (the vacant `AF_ECONET` slot, removed in
Linux 3.5).  Linux 6.x sets `AF_MAX = NPROTO = 46`; any value ≥ 46 is
rejected by `sock_register()` with `ENOBUFS`.

The number appears in four places — keep them in sync:

| File | Symbol |
|---|---|
| `kernel/ipv8.h` | `#define AF_INET8 19` |
| `tools/ipv8_tools.h` | `#define AF_INET8 19` |
| `tests/sock_test.c` | `#define AF_INET8 19` |
| `README.md` | Key constants table |

### 5. All non-static functions in ipv8.h, all static-but-unused functions deleted

The compiler flags `-Werror=missing-prototypes` and `-Werror=unused-function`
treat both cases as errors.  There is no middle ground: a function is either
exported (declared in `ipv8.h`) or internal (`static`), and if internal it
must be called somewhere.

---

## Building

Kernel headers are **not** available in the AI agent's sandbox environment.
You cannot run `make` in `kernel/`.  You can and should build the userspace
tools as a partial sanity check:

```bash
cd tools && make clean && make
```

For the kernel module, perform the static checks above instead of a live
build.  Document in the commit message if a change is untested due to missing
headers.

The user builds on:
- Architecture: arm64
- Kernel: 6.12.x (Debian 13)
- Compiler: GCC with `-Wall -Wextra -Werror -DDEBUG`

---

## Repository conventions

- **Commit messages**: one subject line, blank line, body explaining *why*
  (not what), session URL on the last line.
- **No `// removed`-style comments**: delete dead code outright.
- **No comments that describe what the code does**: only comments that explain
  non-obvious *why* (hidden constraint, workaround, protocol quirk).
- **No new files unless explicitly requested**: edit existing files.
- **Branch**: develop on `claude/ipv8-linux-kernel-module-Pt5eb`, merge to
  `main` only when the work is complete and builds clean.

---

## Known sharp edges

| Symptom | Root cause |
|---|---|
| `sock_register failed: -105 (ENOBUFS)` | `AF_INET8 ≥ NPROTO`; use 19 |
| `in4_pton` / `inet_pton` rejects ASN string | ASNs must be valid dotted-quad (0-255 per octet); AS65001 = `0.0.253.233`, not `65001.0.0.1` |
| `dmesg_ipv8 \| tail -5` misses early lines | Module emits ~11 ipv8 lines; use `tail -20` |
| `module verification failed / taints kernel` | Expected on Debian/Ubuntu; harmless |
| `ip_compute_csum` returns 0x0000 for a valid header, not 0xffff | `csum_fold` applies `~sum`; check `!= 0`, not `!= 0xffff` |
| `neigh_output` error path: do NOT `kfree_skb` | `neigh_output` always consumes the skb |
| `hash_del` + `kfree` in `zone_flush_all` | Use `hash_del_rcu` + `call_rcu` + `rcu_barrier()` |
| Reading route fields after `rcu_read_unlock` | Save all fields inside the RCU critical section |

---

## Testing

```bash
# Userspace socket tests (no module needed, but module must be loaded for
# the socket-creation tests to pass)
cd tests && make && sudo ./sock_test

# Shell smoke tests (requires root, loads/unloads the module automatically)
sudo bash tests/smoke.sh

# End-to-end ping test (module loaded, two terminals)
sudo tools/ipv8_echod -v          # terminal 1
sudo tools/ping8 -c 4 127.0.0.1  # terminal 2
```

---

## What NOT to do

- Do not push directly to `main` in the middle of a task; use the feature
  branch.
- Do not add `(void)` casts to silence unused-variable warnings caused by
  bad logic — fix the logic.
- Do not add error-handling for scenarios that cannot happen (trust internal
  kernel guarantees).
- Do not use `sleep` loops to wait for background processes; use the Monitor
  tool or `run_in_background`.
- Do not create documentation files (`.md`, `README.*`) unless explicitly
  asked.
