# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for IPv8 userspace tools
#
# Targets:
#   all          – build all tools (default)
#   ping8        – build only ping8
#   ipv8_echod   – build only the echo daemon
#   clean        – remove build artefacts
#
# Prerequisites: GCC, glibc (no extra libraries needed)

CC     ?= gcc
CFLAGS := -Wall -Wextra -std=c11 -g -O2 -I.

TOOLS  := ping8 ipv8_echod

.PHONY: all clean $(TOOLS)

all: $(TOOLS)

ping8: ping8.c ipv8_tools.h
	$(CC) $(CFLAGS) -o $@ $< -lm

ipv8_echod: ipv8_echod.c ipv8_tools.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TOOLS)
