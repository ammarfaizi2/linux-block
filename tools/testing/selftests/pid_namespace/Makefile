# SPDX-License-Identifier: GPL-2.0
CFLAGS += -g -I../../../../usr/include/

TEST_GEN_PROGS := regression_enomem
TEST_GEN_PROGS += pid_max

include ../lib.mk

$(OUTPUT)/regression_enomem: regression_enomem.c ../pidfd/pidfd.h
$(OUTPUT)/pid_max: pid_max.c ../pidfd/pidfd.h
