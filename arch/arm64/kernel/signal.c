/*
 * Based on arch/arm/kernel/signal.c
 *
 * Copyright (C) 1995-2009 Russell King
 * Copyright (C) 2012 ARM Ltd.
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
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/personality.h>
#include <linux/freezer.h>
#include <linux/uaccess.h>
#include <linux/tracehook.h>
#include <linux/ratelimit.h>

#include <asm/debug-monitors.h>
#include <asm/elf.h>
#include <asm/cacheflush.h>
#include <asm/ucontext.h>
#include <asm/unistd.h>
#include <asm/fpsimd.h>
#include <asm/signal32.h>
#include <asm/vdso.h>
#include <asm/signal_common.h>
#include <asm/signal_ilp32.h>

#define RT_SIGFRAME_FP_POS (offsetof(struct rt_sigframe, sig)	\
			+ offsetof(struct sigframe, fp))

struct sigframe {
	struct ucontext uc;
	u64 fp;
	u64 lr;
};

/*
 * Do a signal return; undo the signal stack. These are aligned to 128-bit.
 */
struct rt_sigframe {
	struct siginfo info;
	struct sigframe sig;
};

int preserve_fpsimd_context(struct fpsimd_context __user *ctx)
{
	struct fpsimd_state *fpsimd = &current->thread.fpsimd_state;
	int err;

	/* dump the hardware registers to the fpsimd_state structure */
	fpsimd_preserve_current_state();

	/* copy the FP and status/control registers */
	err = __copy_to_user(ctx->vregs, fpsimd->vregs, sizeof(fpsimd->vregs));
	__put_user_error(fpsimd->fpsr, &ctx->fpsr, err);
	__put_user_error(fpsimd->fpcr, &ctx->fpcr, err);

	/* copy the magic/size information */
	__put_user_error(FPSIMD_MAGIC, &ctx->head.magic, err);
	__put_user_error(sizeof(struct fpsimd_context), &ctx->head.size, err);

	return err ? -EFAULT : 0;
}

int restore_fpsimd_context(struct fpsimd_context __user *ctx)
{
	struct fpsimd_state fpsimd;
	__u32 magic, size;
	int err = 0;

	/* check the magic/size information */
	__get_user_error(magic, &ctx->head.magic, err);
	__get_user_error(size, &ctx->head.size, err);
	if (err)
		return -EFAULT;
	if (magic != FPSIMD_MAGIC || size != sizeof(struct fpsimd_context))
		return -EINVAL;

	/* copy the FP and status/control registers */
	err = __copy_from_user(fpsimd.vregs, ctx->vregs,
			       sizeof(fpsimd.vregs));
	__get_user_error(fpsimd.fpsr, &ctx->fpsr, err);
	__get_user_error(fpsimd.fpcr, &ctx->fpcr, err);

	/* load the hardware registers from the fpsimd_state structure */
	if (!err)
		fpsimd_update_current_state(&fpsimd);

	return err ? -EFAULT : 0;
}

static int restore_sigframe(struct pt_regs *regs,
			    struct sigframe __user *sf)
{
	sigset_t set;
	int err;
	err = __copy_from_user(&set, &sf->uc.uc_sigmask, sizeof(set));
	if (err == 0)
		set_current_blocked(&set);

	err |= restore_sigcontext(regs, &sf->uc.uc_mcontext);
	return err;
}


int restore_sigcontext(struct pt_regs *regs, struct sigcontext __user *uc_mcontext)
{
	int i, err = 0;
	void *aux = uc_mcontext->__reserved;

	for (i = 0; i < 31; i++)
		__get_user_error(regs->regs[i], &uc_mcontext->regs[i],
				 err);
	__get_user_error(regs->sp, &uc_mcontext->sp, err);
	__get_user_error(regs->pc, &uc_mcontext->pc, err);
	__get_user_error(regs->pstate, &uc_mcontext->pstate, err);

	/*
	 * Avoid sys_rt_sigreturn() restarting.
	 */
	regs->syscallno = ~0UL;

	err |= !valid_user_regs(&regs->user_regs, current);

	if (err == 0) {
		struct fpsimd_context *fpsimd_ctx =
			container_of(aux, struct fpsimd_context, head);
		err |= restore_fpsimd_context(fpsimd_ctx);
	}

	return err;
}

asmlinkage long sys_rt_sigreturn(struct pt_regs *regs)
{
	struct rt_sigframe __user *frame;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	/*
	 * Since we stacked the signal on a 128-bit boundary, then 'sp' should
	 * be word aligned here.
	 */
	if (regs->sp & 15)
		goto badframe;

	frame = (struct rt_sigframe __user *)regs->sp;

	if (!access_ok(VERIFY_READ, frame, sizeof (*frame)))
		goto badframe;

	if (restore_sigframe(regs, &frame->sig))
		goto badframe;

	if (restore_altstack(&frame->sig.uc.uc_stack))
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

static int setup_sigframe(struct sigframe __user *sf,
			  struct pt_regs *regs, sigset_t *set)
{
	int err = 0;

	/* set up the stack frame for unwinding */
	__put_user_error(regs->regs[29], &sf->fp, err);
	__put_user_error(regs->regs[30], &sf->lr, err);
	err |= __copy_to_user(&sf->uc.uc_sigmask, set, sizeof(*set));
	err |= setup_sigcontext(&sf->uc.uc_mcontext, regs);

	return err;
}

int setup_sigcontext(struct sigcontext __user *uc_mcontext,
			struct pt_regs *regs)
{
	void *aux = uc_mcontext->__reserved;
	struct _aarch64_ctx *end;
	int i, err = 0;

	for (i = 0; i < 31; i++)
		__put_user_error(regs->regs[i], &uc_mcontext->regs[i],
				 err);

	__put_user_error(regs->sp, &uc_mcontext->sp, err);
	__put_user_error(regs->pc, &uc_mcontext->pc, err);
	__put_user_error(regs->pstate, &uc_mcontext->pstate, err);

	__put_user_error(current->thread.fault_address, &uc_mcontext->fault_address, err);

	if (err == 0) {
		struct fpsimd_context *fpsimd_ctx =
			container_of(aux, struct fpsimd_context, head);
		err |= preserve_fpsimd_context(fpsimd_ctx);
		aux += sizeof(*fpsimd_ctx);
	}

	/* fault information, if valid */
	if (current->thread.fault_code) {
		struct esr_context *esr_ctx =
			container_of(aux, struct esr_context, head);
		__put_user_error(ESR_MAGIC, &esr_ctx->head.magic, err);
		__put_user_error(sizeof(*esr_ctx), &esr_ctx->head.size, err);
		__put_user_error(current->thread.fault_code, &esr_ctx->esr, err);
		aux += sizeof(*esr_ctx);
	}

	/* set the "end" magic */
	end = aux;
	__put_user_error(0, &end->magic, err);
	__put_user_error(0, &end->size, err);

	return err;
}

static struct rt_sigframe __user *get_sigframe(struct ksignal *ksig,
					       struct pt_regs *regs)
{
	unsigned long sp, sp_top;
	struct rt_sigframe __user *frame;

	sp = sp_top = sigsp(regs->sp, ksig);

	sp = (sp - sizeof(struct rt_sigframe)) & ~15;
	frame = (struct rt_sigframe __user *)sp;

	/*
	 * Check that we can actually write to the signal frame.
	 */
	if (!access_ok(VERIFY_WRITE, frame, sp_top - sp))
		frame = NULL;

	return frame;
}

void setup_return(struct pt_regs *regs, struct k_sigaction *ka,
			 void __user *frame, off_t fp_pos, int usig)
{
	__sigrestore_t sigtramp;

	regs->regs[0] = usig;
	regs->sp = (unsigned long)frame;
	regs->regs[29] = regs->sp + fp_pos;
	regs->pc = (unsigned long)ka->sa.sa_handler;

	if (ka->sa.sa_flags & SA_RESTORER)
		sigtramp = ka->sa.sa_restorer;
	else
		sigtramp = VDSO_SYMBOL(current->mm->context.vdso, sigtramp);

	regs->regs[30] = (unsigned long)sigtramp;
}

static int setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs)
{
	struct rt_sigframe __user *frame;
	int err = 0;

	frame = get_sigframe(ksig, regs);
	if (!frame)
		return 1;

	__put_user_error(0, &frame->sig.uc.uc_flags, err);
	__put_user_error(NULL, &frame->sig.uc.uc_link, err);

	err |= __save_altstack(&frame->sig.uc.uc_stack, regs->sp);
	err |= setup_sigframe(&frame->sig, regs, set);
	if (err == 0) {
		setup_return(regs, &ksig->ka, frame, RT_SIGFRAME_FP_POS, usig);
		if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
			err |= copy_siginfo_to_user(&frame->info, &ksig->info);
			regs->regs[1] = (unsigned long)&frame->info;
			regs->regs[2] = (unsigned long)&frame->sig.uc;
		}
	}

	return err;
}

static void setup_restart_syscall(struct pt_regs *regs)
{
	if (is_a32_compat_task())
		a32_setup_restart_syscall(regs);
	else
		regs->regs[8] = __NR_restart_syscall;
}

/*
 * OK, we're invoking a handler
 */
static void handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	sigset_t *oldset = sigmask_to_save();
	int usig = ksig->sig;
	int ret;

	/*
	 * Set up the stack frame
	 */
	if (is_a32_compat_task()) {
		if (ksig->ka.sa.sa_flags & SA_SIGINFO)
			ret = a32_setup_rt_frame(usig, ksig, oldset, regs);
		else
			ret = a32_setup_frame(usig, ksig, oldset, regs);
	} else if (is_ilp32_compat_task()) {
		ret = ilp32_setup_rt_frame(usig, ksig, oldset, regs);
	} else {
		ret = setup_rt_frame(usig, ksig, oldset, regs);
	}

	/*
	 * Check that the resulting registers are actually sane.
	 */
	ret |= !valid_user_regs(&regs->user_regs, current);

	/*
	 * Fast forward the stepping logic so we step into the signal
	 * handler.
	 */
	if (!ret)
		user_fastforward_single_step(tsk);

	signal_setup_done(ret, ksig, 0);
}

/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 *
 * Note that we go through the signals twice: once to check the signals that
 * the kernel can handle, and then we build all the user-level signal handling
 * stack-frames in one go after that.
 */
static void do_signal(struct pt_regs *regs)
{
	unsigned long continue_addr = 0, restart_addr = 0;
	int retval = 0;
	int syscall = (int)regs->syscallno;
	struct ksignal ksig;

	/*
	 * If we were from a system call, check for system call restarting...
	 */
	if (syscall >= 0) {
		continue_addr = regs->pc;
		restart_addr = continue_addr - (a32_thumb_mode(regs) ? 2 : 4);
		retval = regs->regs[0];

		/*
		 * Avoid additional syscall restarting via ret_to_user.
		 */
		regs->syscallno = ~0UL;

		/*
		 * Prepare for system call restart. We do this here so that a
		 * debugger will see the already changed PC.
		 */
		switch (retval) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
		case -ERESTART_RESTARTBLOCK:
			regs->regs[0] = regs->orig_x0;
			regs->pc = restart_addr;
			break;
		}
	}

	/*
	 * Get the signal to deliver. When running under ptrace, at this point
	 * the debugger may change all of our registers.
	 */
	if (get_signal(&ksig)) {
		/*
		 * Depending on the signal settings, we may need to revert the
		 * decision to restart the system call, but skip this if a
		 * debugger has chosen to restart at a different PC.
		 */
		if (regs->pc == restart_addr &&
		    (retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK ||
		     (retval == -ERESTARTSYS &&
		      !(ksig.ka.sa.sa_flags & SA_RESTART)))) {
			regs->regs[0] = -EINTR;
			regs->pc = continue_addr;
		}

		handle_signal(&ksig, regs);
		return;
	}

	/*
	 * Handle restarting a different system call. As above, if a debugger
	 * has chosen to restart at a different PC, ignore the restart.
	 */
	if (syscall >= 0 && regs->pc == restart_addr) {
		if (retval == -ERESTART_RESTARTBLOCK)
			setup_restart_syscall(regs);
		user_rewind_single_step(current);
	}

	restore_saved_sigmask();
}

asmlinkage void do_notify_resume(struct pt_regs *regs,
				 unsigned int thread_flags)
{
	/*
	 * The assembly code enters us with IRQs off, but it hasn't
	 * informed the tracing code of that for efficiency reasons.
	 * Update the trace code with the current status.
	 */
	trace_hardirqs_off();
	do {
		if (thread_flags & _TIF_NEED_RESCHED) {
			schedule();
		} else {
			local_irq_enable();

			if (thread_flags & _TIF_UPROBE)
				uprobe_notify_resume(regs);

			if (thread_flags & _TIF_SIGPENDING)
				do_signal(regs);

			if (thread_flags & _TIF_NOTIFY_RESUME) {
				clear_thread_flag(TIF_NOTIFY_RESUME);
				tracehook_notify_resume(regs);
			}

			if (thread_flags & _TIF_FOREIGN_FPSTATE)
				fpsimd_restore_current_state();
		}

		local_irq_disable();
		thread_flags = READ_ONCE(current_thread_info()->flags);
	} while (thread_flags & _TIF_WORK_MASK);
}
