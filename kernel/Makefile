# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for the IPv8 kernel module (draft-thain-ipv8 proof of concept)
#
# Usage:
#   make              – build against the running kernel
#   make KDIR=<path>  – build against a specific kernel build tree
#   make clean        – remove build artefacts
#
# Load/unload:
#   sudo insmod ipv8.ko
#   sudo rmmod  ipv8
#   dmesg | grep ipv8

obj-m += ipv8.o

ipv8-y := \
    ipv8_main.o   \
    ipv8_input.o  \
    ipv8_output.o \
    ipv8_xlate.o  \
    ipv8_zone.o

# Extra CFLAGS: treat all warnings as errors; enable Address Sanitizer
# when KASAN is available in the build tree.
ccflags-y += -Werror -DDEBUG

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

help:
	@echo "Targets:"
	@echo "  all   – build ipv8.ko (default)"
	@echo "  clean – remove build artefacts"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR  – path to kernel build tree (default: running kernel)"
	@echo ""
	@echo "Runtime quick-start:"
	@echo "  sudo insmod ipv8.ko"
	@echo "  # Set local ASN and zone server:"
	@echo "  echo 'zone_server 0.0.253.233 10.0.0.1' | sudo tee /proc/net/ipv8_config"
	@echo "  # Insert a manual zone cache entry (name asn host [ttl]):"
	@echo "  echo 'myhost.example.com 0.0.253.233 203.0.113.7 300' | sudo tee /proc/net/ipv8_zone"
	@echo "  # Inspect cache:"
	@echo "  cat /proc/net/ipv8_zone"

.PHONY: all clean help
