#!/usr/bin/env bash
# smoke.sh – TAP-formatted smoke tests for the ipv8 kernel module
#
# Tests module load/unload, dmesg output, procfs creation, zone cache
# read/write, and config write/readback.
#
# Must be run as root (requires insmod/rmmod).
# Outputs TAP version 13 so it integrates with prove(1) / kselftest.
#
# Usage:
#   sudo bash smoke.sh [path/to/ipv8.ko]
#   sudo prove -e bash smoke.sh

set -euo pipefail

KO="${1:-../kernel/ipv8.ko}"
TAP_COUNT=0
TAP_FAIL=0

tap_plan() { printf 'TAP version 13\n1..%d\n' "$1"; }
pass()      { TAP_COUNT=$((TAP_COUNT+1)); printf 'ok %d - %s\n' "$TAP_COUNT" "$*"; }
fail()      { TAP_COUNT=$((TAP_COUNT+1)); TAP_FAIL=$((TAP_FAIL+1));
              printf 'not ok %d - %s\n' "$TAP_COUNT" "$*"; }
skip()      { TAP_COUNT=$((TAP_COUNT+1)); printf 'ok %d - %s # SKIP %s\n' "$TAP_COUNT" "$1" "$2"; }
diag()      { printf '# %s\n' "$*"; }

# ------------------------------------------------------------------ #
# Pre-flight
# ------------------------------------------------------------------ #

if [[ $EUID -ne 0 ]]; then
    echo 'Bail out! Must be run as root'
    exit 1
fi

if [[ ! -f "$KO" ]]; then
    echo "Bail out! Module not found: $KO  (run 'make' in kernel/ first)"
    exit 1
fi

TOTAL_TESTS=17
tap_plan $TOTAL_TESTS

# ------------------------------------------------------------------ #
# Helper: read last N lines of dmesg that mention ipv8
# ------------------------------------------------------------------ #
dmesg_ipv8() { dmesg | grep -i 'ipv8' | tail -20; }

# ------------------------------------------------------------------ #
# 1. Module not yet loaded
# ------------------------------------------------------------------ #
if lsmod | grep -q '^ipv8 '; then
    diag "WARNING: ipv8 already loaded – unloading first"
    rmmod ipv8 2>/dev/null || true
fi

if ! lsmod | grep -q '^ipv8 '; then
    pass "module not loaded before test begins"
else
    fail "module not loaded before test begins"
fi

# ------------------------------------------------------------------ #
# 2. insmod succeeds
# ------------------------------------------------------------------ #
if insmod "$KO" 2>/dev/null; then
    pass "insmod succeeds"
else
    fail "insmod succeeds"
    diag "$(dmesg | tail -10)"
    # Cannot continue without the module
    echo "Bail out! insmod failed"
    exit 1
fi

# ------------------------------------------------------------------ #
# 3. Module appears in lsmod
# ------------------------------------------------------------------ #
if lsmod | grep -q '^ipv8 '; then
    pass "module visible in lsmod"
else
    fail "module visible in lsmod"
fi

# ------------------------------------------------------------------ #
# 4-5. dmesg shows expected load messages
# ------------------------------------------------------------------ #
if dmesg_ipv8 | grep -q 'loaded successfully'; then
    pass "dmesg: 'loaded successfully' message present"
else
    fail "dmesg: 'loaded successfully' message present"
    diag "$(dmesg_ipv8)"
fi

if dmesg_ipv8 | grep -q 'ETH_P_IPV8.*0x0888\|0x0888.*provisional'; then
    pass "dmesg: provisional EtherType 0x0888 announced"
else
    fail "dmesg: provisional EtherType 0x0888 announced"
fi

# ------------------------------------------------------------------ #
# 6-7. /proc/net entries created
# ------------------------------------------------------------------ #
if [[ -f /proc/net/ipv8_zone ]]; then
    pass "/proc/net/ipv8_zone created"
else
    fail "/proc/net/ipv8_zone created"
fi

if [[ -f /proc/net/ipv8_config ]]; then
    pass "/proc/net/ipv8_config created"
else
    fail "/proc/net/ipv8_config created"
fi

# ------------------------------------------------------------------ #
# 8. /proc/net/ipv8_zone is readable and shows header line
# ------------------------------------------------------------------ #
ZONE_HDR=$(cat /proc/net/ipv8_zone 2>/dev/null | head -1)
if echo "$ZONE_HDR" | grep -q 'NAME'; then
    pass "/proc/net/ipv8_zone readable (header present)"
else
    fail "/proc/net/ipv8_zone readable (header present)"
    diag "Got: $ZONE_HDR"
fi

# ------------------------------------------------------------------ #
# 9. /proc/net/ipv8_config is readable and contains zone_server key
# ------------------------------------------------------------------ #
CONFIG_OUT=$(cat /proc/net/ipv8_config 2>/dev/null)
if echo "$CONFIG_OUT" | grep -q 'zone_server'; then
    pass "/proc/net/ipv8_config readable (zone_server key present)"
else
    fail "/proc/net/ipv8_config readable (zone_server key present)"
    diag "Got: $CONFIG_OUT"
fi

# ------------------------------------------------------------------ #
# 10. Write zone_server config
# ------------------------------------------------------------------ #
if echo 'zone_server 0.0.253.233 10.0.0.1' > /proc/net/ipv8_config 2>/dev/null; then
    pass "write zone_server to /proc/net/ipv8_config"
else
    fail "write zone_server to /proc/net/ipv8_config"
fi

# ------------------------------------------------------------------ #
# 11. dmesg confirms zone server address was accepted
# ------------------------------------------------------------------ #
if dmesg_ipv8 | grep -q 'server set to'; then
    pass "dmesg: zone server address accepted"
else
    fail "dmesg: zone server address accepted"
fi

# ------------------------------------------------------------------ #
# 12. Write a zone cache entry
# ------------------------------------------------------------------ #
ENTRY='peer.example.com 0.0.253.233 203.0.113.7 300'
if echo "$ENTRY" > /proc/net/ipv8_zone 2>/dev/null; then
    pass "write zone entry to /proc/net/ipv8_zone"
else
    fail "write zone entry to /proc/net/ipv8_zone"
fi

# ------------------------------------------------------------------ #
# 13. Zone entry appears in cache dump
# ------------------------------------------------------------------ #
ZONE_DUMP=$(cat /proc/net/ipv8_zone 2>/dev/null)
if echo "$ZONE_DUMP" | grep -q 'peer.example.com'; then
    pass "zone entry 'peer.example.com' visible in cache dump"
else
    fail "zone entry 'peer.example.com' visible in cache dump"
    diag "Cache contents: $ZONE_DUMP"
fi

# ------------------------------------------------------------------ #
# 14. Zone dump contains expected ASN and host fields
# ------------------------------------------------------------------ #
if echo "$ZONE_DUMP" | grep 'peer.example.com' | grep -q '203.0.113.7'; then
    pass "zone entry contains correct host address 203.0.113.7"
else
    fail "zone entry contains correct host address 203.0.113.7"
    diag "$(echo "$ZONE_DUMP" | grep peer)"
fi

# ------------------------------------------------------------------ #
# 15. EtherType 0x0888 registered in /proc/net/ptype
# ------------------------------------------------------------------ #
if grep -qi '0888' /proc/net/ptype 2>/dev/null; then
    pass "EtherType 0x0888 registered in /proc/net/ptype"
else
    fail "EtherType 0x0888 registered in /proc/net/ptype"
    diag "/proc/net/ptype contents:"
    diag "$(cat /proc/net/ptype)"
fi

# ------------------------------------------------------------------ #
# 16. rmmod succeeds
# ------------------------------------------------------------------ #
if rmmod ipv8 2>/dev/null; then
    pass "rmmod succeeds"
else
    fail "rmmod succeeds"
    diag "$(dmesg | tail -5)"
fi

# ------------------------------------------------------------------ #
# 17. /proc entries removed after unload
# ------------------------------------------------------------------ #
if [[ ! -f /proc/net/ipv8_zone ]] && [[ ! -f /proc/net/ipv8_config ]]; then
    pass "/proc/net entries removed after rmmod"
else
    fail "/proc/net entries removed after rmmod"
fi

# ------------------------------------------------------------------ #
# Summary
# ------------------------------------------------------------------ #
diag "Passed: $((TOTAL_TESTS - TAP_FAIL)) / $TOTAL_TESTS"
[[ $TAP_FAIL -eq 0 ]]
