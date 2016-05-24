/*
 * Based on arch/arm/kernel/signal.c
 *
 * Copyright (C) 1995-2009 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2017 Cavium Networks.
 * Yury Norov <ynorov@caviumnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/compat.h>
#include <linux/signal.h>
#include <linux/syscalls.h>
#include <linux/ratelimit.h>

#include <asm/esr.h>
#include <asm/fpsimd.h>
#include <asm/signal_ilp32.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/ucontext.h>


#define ILP32_RT_SIGFRAME_FP_POS (offsetof(struct ilp32_rt_sigframe, sig)	\
			+ offsetof(struct ilp32_sigframe, fp))

struct ilp32_ucontext {
        u32		uc_flags;
        u32		uc_link;
        compat_stack_t  uc_stack;
        compat_sigset_t uc_sigmask;
        /* glibc uses a 1024-bit sigset_t */
        __u8            __unused[1024 / 8 - sizeof(compat_sigset_t)];
        /* last for future expansion */
        struct sigcontext uc_mcontext;
};

struct ilp32_sigframe {
	struct ilp32_ucontext uc;
	u64 fp;
	u64 lr;
};

struct ilp32_rt_sigframe {
	struct compat_siginfo info;
	struct ilp32_sigframe sig;
};

static int restore_ilp32_sigframe(struct pt_regs *regs,
                            struct ilp32_sigframe __user *sf)
{
	sigset_t set;
	int err;
	err = get_sigset_t(&set, &sf->uc.uc_sigmask);
	if (err == 0)
		set_current_blocked(&set);
	err |= restore_sigcontext(regs, &sf->uc.uc_mcontext);
	return err;
}

static int setup_ilp32_sigframe(struct ilp32_sigframe __user *sf,
                          struct pt_regs *regs, sigset_t *set)
{
	int err = 0;
	/* set up the stack frame for unwinding */
	__put_user_error(regs->regs[29], &sf->fp, err);
	__put_user_error(regs->regs[30], &sf->lr, err);

	err |= put_sigset_t(&sf->uc.uc_sigmask, set);
	err |= setup_sigcontext(&sf->uc.uc_mcontext, regs);
	return err;
}

asmlinkage long ilp32_sys_rt_sigreturn(struct pt_regs *regs)
{
	struct ilp32_rt_sigframe __user *frame;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	/*
	 * Since we stacked the signal on a 128-bit boundary,
	 * then 'sp' should be word aligned here.  If it's
	 * not, then the user is trying to mess with us.
	 */
	if (regs->sp & 15)
		goto badframe;

	frame = (struct ilp32_rt_sigframe __user *)regs->sp;

	if (!access_ok(VERIFY_READ, frame, sizeof (*frame)))
		goto badframe;

	if (restore_ilp32_sigframe(regs, &frame->sig))
		goto badframe;

	if (compat_restore_altstack(&frame->sig.uc.uc_stack))
		goto badframe;

	return regs->regs[0];

badframe:
	if (show_unhandled_signals)
		pr_info_ratelimited("%s[%d]: bad frame in %s: pc=%08llx sp=%08llx\n",
				    current->comm, task_pid_nr(current), __func__,
				    regs->pc, regs->sp);
	force_sig(SIGSEGV, current);
	return 0;
}

static struct ilp32_rt_sigframe __user *ilp32_get_sigframe(struct ksignal *ksig,
					       struct pt_regs *regs)
{
	unsigned long sp, sp_top;
	struct ilp32_rt_sigframe __user *frame;

	sp = sp_top = sigsp(regs->sp, ksig);

	sp = (sp - sizeof(struct ilp32_rt_sigframe)) & ~15;
	frame = (struct ilp32_rt_sigframe __user *)sp;

	/*
	 * Check that we can actually write to the signal frame.
	 */
	if (!access_ok(VERIFY_WRITE, frame, sp_top - sp))
		frame = NULL;

	return frame;
}

/*
 * ILP32 signal handling routines called from signal.c
 */
int ilp32_setup_rt_frame(int usig, struct ksignal *ksig,
			  sigset_t *set, struct pt_regs *regs)
{
	struct ilp32_rt_sigframe __user *frame;
	int err = 0;

	frame = ilp32_get_sigframe(ksig, regs);

	if (!frame)
		return 1;

	err |= copy_siginfo_to_user32(&frame->info, &ksig->info);

	__put_user_error(0, &frame->sig.uc.uc_flags, err);
	__put_user_error(0, &frame->sig.uc.uc_link, err);

	err |= __compat_save_altstack(&frame->sig.uc.uc_stack, regs->sp);
	err |= setup_ilp32_sigframe(&frame->sig, regs, set);
	if (err == 0) {
		setup_return(regs, &ksig->ka, frame, ILP32_RT_SIGFRAME_FP_POS, usig);
		regs->regs[1] = (unsigned long)&frame->info;
		regs->regs[2] = (unsigned long)&frame->sig.uc;
	}

	return err;
}
