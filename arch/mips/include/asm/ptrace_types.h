/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1994, 95, 96, 97, 98, 99, 2000 by Ralf Baechle
 * Copyright (C) 1999, 2000 Silicon Graphics, Inc.
 */
#ifndef _ASM_PTRACE_TYPES_H
#define _ASM_PTRACE_TYPES_H

#include <linux/compiler.h>

/*
 * This struct defines the way the registers are stored on the stack during a
 * system call/exception. As usual the registers k0/k1 aren't being saved.
 *
 * If you add a register here, also add it to regoffset_table[] in
 * arch/mips/kernel/ptrace.c.
 */
struct pt_regs {
#ifdef CONFIG_32BIT
	/* Pad bytes for argument save space on the stack. */
	unsigned long pad0[8];
#endif

	/* Saved main processor registers. */
	unsigned long regs[32];

	/* Saved special registers. */
	unsigned long cp0_status;
	unsigned long hi;
	unsigned long lo;
#ifdef CONFIG_CPU_HAS_SMARTMIPS
	unsigned long acx;
#endif
	unsigned long cp0_badvaddr;
	unsigned long cp0_cause;
	unsigned long cp0_epc;
#ifdef CONFIG_CPU_CAVIUM_OCTEON
	unsigned long long mpl[6];        /* MTM{0-5} */
	unsigned long long mtp[6];        /* MTP{0-5} */
#endif
	unsigned long __last[0];
} __aligned(8);

#endif /* _ASM_PTRACE_TYPES_H */
