# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for ipv8 smoke tests
#
# Targets:
#   all        – build the C test binary
#   run        – build the module, run all smoke tests (requires root)
#   run-sock   – run only the userspace socket tests (requires root + module)
#   run-shell  – run only the shell smoke tests (requires root + module)
#   clean      – remove build artefacts

CC      ?= gcc
CFLAGS  := -Wall -Wextra -std=c11 -g -O0
KO      := ../kernel/ipv8.ko

.PHONY: all run run-sock run-shell clean

all: sock_test

sock_test: sock_test.c
	$(CC) $(CFLAGS) -o $@ $<

# Build the kernel module if it isn't already built
$(KO):
	$(MAKE) -C ../kernel

# Run every test suite under sudo
run: all $(KO)
	@echo "=== Running shell smoke tests ==="
	sudo bash smoke.sh $(KO) 2>&1 | tee /tmp/ipv8_smoke.tap
	@echo ""
	@echo "=== Running userspace socket tests ==="
	sudo insmod $(KO) 2>/dev/null || true
	sudo ./sock_test 2>&1 | tee /tmp/ipv8_sock.tap
	sudo rmmod ipv8 2>/dev/null || true
	@echo ""
	@echo "=== TAP summary ==="
	@grep -hc '^ok'     /tmp/ipv8_smoke.tap /tmp/ipv8_sock.tap | paste -sd+ | bc | xargs -I{} echo "PASSED: {}"
	@grep -hc '^not ok' /tmp/ipv8_smoke.tap /tmp/ipv8_sock.tap | paste -sd+ | bc | xargs -I{} echo "FAILED: {}"

run-shell: $(KO)
	sudo bash smoke.sh $(KO)

run-sock: all $(KO)
	sudo insmod $(KO) 2>/dev/null || true
	sudo ./sock_test
	sudo rmmod ipv8 2>/dev/null || true

clean:
	rm -f sock_test
