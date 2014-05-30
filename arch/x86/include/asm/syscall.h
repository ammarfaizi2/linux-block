/*
 * Access to user system call parameters and results
 *
 * Copyright (C) 2008-2009 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * See asm-generic/syscall.h for descriptions of what we must do here.
 */

#ifndef _ASM_X86_SYSCALL_H
#define _ASM_X86_SYSCALL_H

#include <uapi/linux/audit.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <asm/asm-offsets.h>	/* For NR_syscalls */
#include <asm/thread_info.h>	/* for TS_COMPAT */
#include <asm/unistd.h>

typedef void (*sys_call_ptr_t)(void);
extern const sys_call_ptr_t sys_call_table[];

/**
 * syscall_in_syscall() - are we in a syscall context?
 * @task: The task to query.
 * @regs: The task's pt_regs.
 *
 * This checks whether we are in a syscall.  "In a syscall" is a somewhat
 * nebulous concept; read below for details.
 *
 * If it returns true, then syscall_get_nr(), etc are usable and
 * current is currently processing a system call.
 *
 * Conversely, if we were called by normal C code from a syscall
 * implementation, syscall_in_syscall() will return true.
 *
 * These are the only guarantees made.  For example, if we are in an
 * NMI or processing a page fault caused by a syscall handler,
 * syscall_in_syscall() can return true or false.  Similarly, a
 * syscall with an invalid nr can cause syscall_in_syscall() to return
 * an indeterminate value (although, if syscall_in_syscall() returns
 * true, the the rest of the syscall_xyz() functions will work).
 */
static inline bool syscall_in_syscall(struct task_struct *task,
				      struct pt_regs *regs)
{
	/*
	 * This relies on the fact that all of the non-IST, non-syscall
	 * entries either set orig_ax to -1 before running C code or the
	 * first thing that the C code does is to mark the CPU as being
	 * in an interrupt.  Similarly, the syscall entries put the nr
	 * into in_interrupt, and nr == -1 only happens for bad
	 * syscalls.
	 *
	 * This is a bit more subtle on x86_32: system_call is a trap
	 * gate, so another interrupt can happen after system_call
	 * starts but before pt_regs is set up.  If this happens, we'll
	 * either switch stacks or be in_interrupt(), though, so we're
	 * still safe.
	 */
	unsigned long sp;
#ifdef CONFIG_X86_64
	asm("movq %%rsp,%0" : "=rm" (sp));
#else
	asm("movl %%esp,%0" : "=rm" (sp));
#endif
	return regs->orig_ax != -1 && !in_interrupt() &&
		((sp ^ this_cpu_read_stable(kernel_stack)) &
		 -THREAD_SIZE) == 0;
}

/*
 * Only the low 32 bits of orig_ax are meaningful, so we return int.
 * This importantly ignores the high bits on 64-bit, so comparisons
 * sign-extend the low 32 bits.
 */
static inline int syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	return regs->orig_ax;
}

static inline void syscall_rollback(struct task_struct *task,
				    struct pt_regs *regs)
{
	regs->ax = regs->orig_ax;
}

static inline long syscall_get_error(struct task_struct *task,
				     struct pt_regs *regs)
{
	unsigned long error = regs->ax;
#ifdef CONFIG_IA32_EMULATION
	/*
	 * TS_COMPAT is set for 32-bit syscall entries and then
	 * remains set until we return to user mode.
	 */
	if (task_thread_info(task)->status & TS_COMPAT)
		/*
		 * Sign-extend the value so (int)-EFOO becomes (long)-EFOO
		 * and will match correctly in comparisons.
		 */
		error = (long) (int) error;
#endif
	return IS_ERR_VALUE(error) ? error : 0;
}

static inline long syscall_get_return_value(struct task_struct *task,
					    struct pt_regs *regs)
{
	return regs->ax;
}

static inline void syscall_set_return_value(struct task_struct *task,
					    struct pt_regs *regs,
					    int error, long val)
{
	regs->ax = (long) error ?: val;
}

#ifdef CONFIG_X86_32

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 unsigned long *args)
{
	BUG_ON(i + n > 6);
	memcpy(args, &regs->bx + i, n * sizeof(args[0]));
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 const unsigned long *args)
{
	BUG_ON(i + n > 6);
	memcpy(&regs->bx + i, args, n * sizeof(args[0]));
}

static inline int syscall_get_arch(void)
{
	return AUDIT_ARCH_I386;
}

#else	 /* CONFIG_X86_64 */

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 unsigned long *args)
{
# ifdef CONFIG_IA32_EMULATION
	if (task_thread_info(task)->status & TS_COMPAT)
		switch (i) {
		case 0:
			if (!n--) break;
			*args++ = regs->bx;
		case 1:
			if (!n--) break;
			*args++ = regs->cx;
		case 2:
			if (!n--) break;
			*args++ = regs->dx;
		case 3:
			if (!n--) break;
			*args++ = regs->si;
		case 4:
			if (!n--) break;
			*args++ = regs->di;
		case 5:
			if (!n--) break;
			*args++ = regs->bp;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
	else
# endif
		switch (i) {
		case 0:
			if (!n--) break;
			*args++ = regs->di;
		case 1:
			if (!n--) break;
			*args++ = regs->si;
		case 2:
			if (!n--) break;
			*args++ = regs->dx;
		case 3:
			if (!n--) break;
			*args++ = regs->r10;
		case 4:
			if (!n--) break;
			*args++ = regs->r8;
		case 5:
			if (!n--) break;
			*args++ = regs->r9;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 const unsigned long *args)
{
# ifdef CONFIG_IA32_EMULATION
	if (task_thread_info(task)->status & TS_COMPAT)
		switch (i) {
		case 0:
			if (!n--) break;
			regs->bx = *args++;
		case 1:
			if (!n--) break;
			regs->cx = *args++;
		case 2:
			if (!n--) break;
			regs->dx = *args++;
		case 3:
			if (!n--) break;
			regs->si = *args++;
		case 4:
			if (!n--) break;
			regs->di = *args++;
		case 5:
			if (!n--) break;
			regs->bp = *args++;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
	else
# endif
		switch (i) {
		case 0:
			if (!n--) break;
			regs->di = *args++;
		case 1:
			if (!n--) break;
			regs->si = *args++;
		case 2:
			if (!n--) break;
			regs->dx = *args++;
		case 3:
			if (!n--) break;
			regs->r10 = *args++;
		case 4:
			if (!n--) break;
			regs->r8 = *args++;
		case 5:
			if (!n--) break;
			regs->r9 = *args++;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
}

static inline int syscall_get_arch(void)
{
#ifdef CONFIG_IA32_EMULATION
	/*
	 * TS_COMPAT is set for 32-bit syscall entry and then
	 * remains set until we return to user mode.
	 *
	 * TIF_IA32 tasks should always have TS_COMPAT set at
	 * system call time.
	 *
	 * x32 tasks should be considered AUDIT_ARCH_X86_64.
	 */
	if (task_thread_info(current)->status & TS_COMPAT)
		return AUDIT_ARCH_I386;
#endif
	/* Both x32 and x86_64 are considered "64-bit". */
	return AUDIT_ARCH_X86_64;
}
#endif	/* CONFIG_X86_32 */

#endif	/* _ASM_X86_SYSCALL_H */
