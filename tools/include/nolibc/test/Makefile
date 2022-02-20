# SPDX-License-Identifier: GPL-2.0
# Makefile for nolibc itests
include ../../../scripts/Makefile.include

CFLAGS  ?= -Os -fno-ident -fno-asynchronous-unwind-tables
LDFLAGS := -s

all: nolibc-test

nolibc-test: nolibc-test.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ \
	  -nostdlib -static -I../sysroot/include $^ -lgcc
