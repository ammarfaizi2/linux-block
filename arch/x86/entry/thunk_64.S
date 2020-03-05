/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Save registers before calling assembly functions. This avoids
 * disturbance of register allocation in some inline assembly constructs.
 * Copyright 2001,2002 by Andi Kleen, SuSE Labs.
 */
#include <linux/linkage.h>
#include "calling.h"
#include <asm/asm.h>
#include <asm/export.h>
#include <asm/irqflags.h>

.code64
.section .noinstr.text, "ax"

	/* rdi:	arg1 ... normal C conventions. rax is saved/restored. */
	.macro THUNK name, func, put_ret_addr_in_rdi=0, check_if=0
SYM_FUNC_START_NOALIGN(\name)

	.if \check_if
	/*
	 * Check for interrupts disabled right here. No point in
	 * going all the way down
	 */
	pushq	%rax
	SAVE_FLAGS(CLBR_RAX)
	testl	$X86_EFLAGS_IF, %eax
	popq	%rax
	jnz	1f
	ret
1:
	.endif

	pushq %rbp
	movq %rsp, %rbp

	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %rax
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11

	.if \put_ret_addr_in_rdi
	/* 8(%rbp) is return addr on stack */
	movq 8(%rbp), %rdi
	.endif

	/*
	 * noinstr callers will have interrupts disabled and will thus
	 * not get here. Annotate the call as objtool does not know about
	 * this and would complain about leaving the noinstr section.
	 */
1:
	.pushsection .discard.instr_begin
	.long 1b - .
	.popsection

	call \func
2:
	.pushsection .discard.instr_end
	.long 2b - .
	.popsection

	jmp  .L_restore
SYM_FUNC_END(\name)
	.endm

#ifdef CONFIG_PREEMPTION
	THUNK preempt_schedule_thunk, preempt_schedule
	EXPORT_SYMBOL(preempt_schedule_thunk)

	THUNK preempt_schedule_notrace_thunk, preempt_schedule_notrace, check_if=1
	EXPORT_SYMBOL(preempt_schedule_notrace_thunk)
#endif

#ifdef CONFIG_PREEMPTION
SYM_CODE_START_LOCAL_NOALIGN(.L_restore)
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rax
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
	popq %rbp
	ret
SYM_CODE_END(.L_restore)
#endif
