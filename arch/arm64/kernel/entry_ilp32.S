/* SPDX-License-Identifier: GPL-2.0+ */

/*
 * ILP32 system call wrappers
 */

#include <linux/linkage.h>

ENTRY(ilp32_sys_rt_sigreturn_wrapper)
	mov	x0, sp
	b	ilp32_sys_rt_sigreturn
ENDPROC(ilp32_sys_rt_sigreturn_wrapper)
