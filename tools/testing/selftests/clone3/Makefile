# SPDX-License-Identifier: GPL-2.0
uname_M := $(shell uname -m 2>/dev/null || echo not)
ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/)

CFLAGS += -I../../../../usr/include/

ifeq ($(ARCH),x86_64)
	TEST_GEN_PROGS := clone3 clone3_set_tid
endif

include ../lib.mk
