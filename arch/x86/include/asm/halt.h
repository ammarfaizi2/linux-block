/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_HALT_H_
#define _X86_HALT_H_

#include <linux/cpu.h>

#include <asm/nospec-branch.h>

static inline __cpuidle void native_safe_halt(void)
{
	mds_idle_clear_cpu_buffers();
	asm volatile("sti; hlt": : :"memory");
}

static inline __cpuidle void native_halt(void)
{
	mds_idle_clear_cpu_buffers();
	asm volatile("hlt": : :"memory");
}

#ifdef CONFIG_PARAVIRT_XXL
# include <asm/paravirt.h>
#else

/*
 * Used in the idle loop; sti takes one instruction cycle
 * to complete:
 */
static inline __cpuidle void arch_safe_halt(void)
{
	native_safe_halt();
}

/*
 * Used when interrupts are already enabled or to
 * shutdown the processor:
 */
static inline __cpuidle void halt(void)
{
	native_halt();
}

#endif /* CONFIG_PARAVIRT_XXL */

#endif /* _X86_HALT_H_ */
