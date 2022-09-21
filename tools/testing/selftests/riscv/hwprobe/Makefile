# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 ARM Limited
# Originally tools/testing/arm64/abi/Makefile

TEST_GEN_PROGS := hwprobe

include ../../lib.mk

$(OUTPUT)/hwprobe: hwprobe.c ../libc.S sys_hwprobe.S
	$(CC) -o$@ $(CFLAGS) $(LDFLAGS) -nostdlib $^
