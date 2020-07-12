# SPDX-License-Identifier: GPL-2.0
CFLAGS += -g -I../../../../usr/include/

TEST_GEN_PROGS := regression_enomem
TEST_GEN_PROGS := pid_translation

include ../lib.mk

$(OUTPUT)/regression_enomem: regression_enomem.c ../pidfd/pidfd.h
$(OUTPUT)/pid_translation: pid_translation.c ../clone3/clone3_selftests.h ../pidfd/pidfd.h
