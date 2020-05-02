/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_IRQ_STACK_H
#define _ASM_X86_IRQ_STACK_H

#include <linux/ptrace.h>

#include <asm/processor.h>

#ifdef CONFIG_X86_64
static __always_inline bool irqstack_active(void)
{
	return __this_cpu_read(irq_count) != -1;
}

/*
 * Macro to emit code for running @func on the irq stack.
 */
#define RUN_ON_IRQSTACK(func)	{					\
	unsigned long tos;						\
									\
	lockdep_assert_irqs_disabled();					\
									\
	tos = ((unsigned long)__this_cpu_read(hardirq_stack_ptr)) - 8;	\
									\
	__this_cpu_add(irq_count, 1);					\
	asm volatile(							\
		"pushq  %%rbp					\n"	\
		"movq   %%rsp, %%rbp				\n"	\
		"movq	%%rsp, (%[ts])				\n"	\
		"movq	%[ts], %%rsp				\n"	\
		"1:						\n"	\
		"	.pushsection .discard.instr_begin	\n"	\
		"	.long 1b - .				\n"	\
		"	.popsection				\n"	\
		"call	" __ASM_FORM(func) "			\n"	\
		"2:						\n"	\
		"	.pushsection .discard.instr_end		\n"	\
		"	.long 2b - .				\n"	\
		"	.popsection				\n"	\
		"popq	%%rsp					\n"	\
		"leaveq						\n"	\
		:							\
		: [ts] "r" (tos)					\
		: "memory"						\
		);							\
	__this_cpu_sub(irq_count, 1);					\
}

#else /* CONFIG_X86_64 */
static __always_inline bool irqstack_active(void) { return false; }
#define RUN_ON_IRQSTACK(func)	do { } while (0)
#endif /* !CONFIG_X86_64 */

static __always_inline bool irq_needs_irq_stack(struct pt_regs *regs)
{
	if (IS_ENABLED(CONFIG_X86_32))
		return false;
	return !user_mode(regs) && !irqstack_active();
}

#endif
