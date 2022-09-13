/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022 Rivos, Inc
 */

#ifndef _UAPI_ASM_HWPROBE_H
#define _UAPI_ASM_HWPROBE_H

#include <uapi/linux/types.h>

/*
 * Interface for probing hardware capabilities from userspace, see
 * Documentation/riscv/hwprobe.rst for more information.
 */
struct riscv_hwprobe {
    __u64 key, val;
};

#define RISCV_HWPROBE_KEY_MVENDORID	0
#define RISCV_HWPROBE_KEY_MARCHID	1
#define RISCV_HWPROBE_KEY_MIMPID	2
#define RISCV_HWPROBE_KEY_BASE_BEHAVIOR	3
#define		RISCV_HWPROBE_BASE_BEHAVIOR_IMA	(1 << 0)
#define RISCV_HWPROBE_KEY_IMA_EXT_0	4
#define		RISCV_HWPROBE_IMA_FD		(1 << 0)
#define		RISCV_HWPROBE_IMA_C		(1 << 1)
#define RISCV_HWPROBE_KEY_CPUPERF_0	5
#define		RISCV_HWPROBE_MISALIGNED_UNKNOWN	(0)
#define		RISCV_HWPROBE_MISALIGNED_EMULATED	(1)
#define		RISCV_HWPROBE_MISALIGNED_SLOW		(2)
#define		RISCV_HWPROBE_MISALIGNED_FAST		(3)
/* Increase RISCV_HWPROBE_MAX_KEY when adding items. */



#endif
