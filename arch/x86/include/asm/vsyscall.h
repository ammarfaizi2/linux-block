/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_VSYSCALL_H
#define _ASM_X86_VSYSCALL_H

#include <linux/seqlock.h>
#include <uapi/asm/vsyscall.h>

#ifdef CONFIG_X86_VSYSCALL_EMULATION
extern void map_vsyscall(void);
extern void set_vsyscall_pgtable_user_bits(pgd_t *root);

/*
 * Called on a page fault in the vsyscall page.
 * Returns true if handled.
 */
extern bool handle_vsyscall_fault(struct pt_regs *regs, unsigned long address,
				  unsigned long error_code);
#else
static inline void map_vsyscall(void) {}
static inline bool handle_vsyscall_fault(struct pt_regs *regs,
					 unsigned long address,
					 unsigned long error_code)
{
	return false;
}
#endif

#endif /* _ASM_X86_VSYSCALL_H */
