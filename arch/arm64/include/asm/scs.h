/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SCS_H
#define _ASM_SCS_H

#ifdef __ASSEMBLY__

#include <asm/asm-offsets.h>

#ifdef CONFIG_SHADOW_CALL_STACK
	scs_sp	.req	x18

	.macro scs_load tsk
	ldr	scs_sp, [\tsk, #TSK_TI_SCS_SP]
	.endm

	.macro scs_save tsk
	str	scs_sp, [\tsk, #TSK_TI_SCS_SP]
	.endm
#else
	.macro scs_load tsk
	.endm

	.macro scs_save tsk
	.endm
#endif /* CONFIG_SHADOW_CALL_STACK */

#else /* __ASSEMBLY__ */

#include <linux/percpu.h>

DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_saved_ptr);
DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_saved_ptr);
DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_saved_ptr);

#endif /* __ASSEMBLY__ */

#endif /* _ASM_SCS_H */
