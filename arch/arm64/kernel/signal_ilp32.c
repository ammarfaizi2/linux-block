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

#include <asm/fpsimd.h>
#include <asm/unistd.h>
#include <asm/ucontext.h>
#include <asm/vdso.h>

#include <asm/signal_ilp32.h>
#include <asm/signal32_common.h>
#include <asm/signal_common.h>

#define BASE_SIGFRAME_SIZE round_up(sizeof(struct ilp32_rt_sigframe), 16)

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

struct ilp32_rt_sigframe {
	struct compat_siginfo info;
	struct ilp32_ucontext uc;
};

struct ilp32_rt_sigframe_user_layout {
	struct ilp32_rt_sigframe __user *sigframe;
	struct frame_record __user *next_frame;

	unsigned int size;	/* size of allocated sigframe data */
	unsigned int limit;	/* largest allowed size */

	unsigned int fpsimd_offset;
	unsigned int esr_offset;
	unsigned int extra_offset;
	unsigned int end_offset;
};

static size_t ilp32_sigframe_size(struct ilp32_rt_sigframe_user_layout const *user)
{
	return round_up(max(user->size, (unsigned int)sizeof(struct ilp32_rt_sigframe)), 16);
}

static void __user *apply_user_offset(
	struct ilp32_rt_sigframe_user_layout const *user, unsigned long offset)
{
	char __user *base = (char __user *)user->sigframe;

	return base + offset;
}

static void ilp32_init_user_layout(struct ilp32_rt_sigframe_user_layout *user)
{
	const size_t reserved_size =
		sizeof(user->sigframe->uc.uc_mcontext.__reserved);

	memset(user, 0, sizeof(*user));
	user->size = offsetof(struct ilp32_rt_sigframe, uc.uc_mcontext.__reserved);

	user->limit = user->size + reserved_size;

	user->limit -= TERMINATOR_SIZE;
	user->limit -= EXTRA_CONTEXT_SIZE;
	/* Reserve space for extension and terminator ^ */
}

static int ilp32_restore_sigframe(struct pt_regs *regs,
			    struct ilp32_rt_sigframe __user *sf)
{
	sigset_t set;
	int i, err;
	struct user_ctxs user;

	err = get_sigset_t(&set, &sf->uc.uc_sigmask);
	if (err == 0)
		set_current_blocked(&set);

	for (i = 0; i < 31; i++)
		__get_user_error(regs->regs[i], &sf->uc.uc_mcontext.regs[i],
				 err);
	__get_user_error(regs->sp, &sf->uc.uc_mcontext.sp, err);
	__get_user_error(regs->pc, &sf->uc.uc_mcontext.pc, err);
	__get_user_error(regs->pstate, &sf->uc.uc_mcontext.pstate, err);

	/*
	 * Avoid sys_rt_sigreturn() restarting.
	 */
	forget_syscall(regs);

	err |= !valid_user_regs(&regs->user_regs, current);
	if (err == 0)
		err = parse_user_sigcontext(&user, sf);

	if (err == 0)
		err = restore_fpsimd_context(user.fpsimd);

	return err;
}
asmlinkage long ilp32_sys_rt_sigreturn(struct pt_regs *regs)
{
	struct ilp32_rt_sigframe __user *frame;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	/*
	 * Since we stacked the signal on a 128-bit boundary, then 'sp' should
	 * be word aligned here.
	 */
	if (regs->sp & 15)
		goto badframe;

	frame = (struct ilp32_rt_sigframe __user *)regs->sp;

	if (!access_ok(VERIFY_READ, frame, sizeof (*frame)))
		goto badframe;

	if (ilp32_restore_sigframe(regs, frame))
		goto badframe;

	if (compat_restore_altstack(&frame->uc.uc_stack))
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

static int __ilp32_sigframe_alloc(struct ilp32_rt_sigframe_user_layout *user,
			    unsigned int *offset, size_t size, bool extend)
{
	size_t padded_size = round_up(size, 16);

	if (padded_size > user->limit - user->size &&
	    !user->extra_offset &&
	    extend) {
		int ret;

		user->limit += EXTRA_CONTEXT_SIZE;
		ret = __ilp32_sigframe_alloc(user, &user->extra_offset,
				       sizeof(struct extra_context), false);
		if (ret) {
			user->limit -= EXTRA_CONTEXT_SIZE;
			return ret;
		}

		/* Reserve space for the __reserved[] terminator */
		user->size += TERMINATOR_SIZE;

		/*
		 * Allow expansion up to SIGFRAME_MAXSZ, ensuring space for
		 * the terminator:
		 */
		user->limit = SIGFRAME_MAXSZ - TERMINATOR_SIZE;
	}

	/* Still not enough space?  Bad luck! */
	if (padded_size > user->limit - user->size)
		return -ENOMEM;

	*offset = user->size;
	user->size += padded_size;

	return 0;
}

/*
 * Allocate space for an optional record of <size> bytes in the user
 * signal frame.  The offset from the signal frame base address to the
 * allocated block is assigned to *offset.
 */
static int ilp32_sigframe_alloc(struct ilp32_rt_sigframe_user_layout *user,
			  unsigned int *offset, size_t size)
{
	return __ilp32_sigframe_alloc(user, offset, size, true);
}

/* Allocate the null terminator record and prevent further allocations */
static int ilp32_sigframe_alloc_end(struct ilp32_rt_sigframe_user_layout *user)
{
	int ret;

	/* Un-reserve the space reserved for the terminator: */
	user->limit += TERMINATOR_SIZE;

	ret = ilp32_sigframe_alloc(user, &user->end_offset,
			     sizeof(struct _aarch64_ctx));
	if (ret)
		return ret;

	/* Prevent further allocation: */
	user->limit = user->size;
	return 0;
}

/* Determine the layout of optional records in the signal frame */
static int ilp32_setup_sigframe_layout(struct ilp32_rt_sigframe_user_layout *user)
{
	int err;

	err = ilp32_sigframe_alloc(user, &user->fpsimd_offset,
			     sizeof(struct fpsimd_context));
	if (err)
		return err;

	/* fault information, if valid */
	if (current->thread.fault_code) {
		err = ilp32_sigframe_alloc(user, &user->esr_offset,
				     sizeof(struct esr_context));
		if (err)
			return err;
	}

	return ilp32_sigframe_alloc_end(user);
}

static int ilp32_setup_sigframe(struct ilp32_rt_sigframe_user_layout *user,
			  struct pt_regs *regs, sigset_t *set)
{
	int i, err = 0;
	struct ilp32_rt_sigframe __user *sf = user->sigframe;

	/* set up the stack frame for unwinding */
	__put_user_error(regs->regs[29], &user->next_frame->fp, err);
	__put_user_error(regs->regs[30], &user->next_frame->lr, err);

	for (i = 0; i < 31; i++)
		__put_user_error(regs->regs[i], &sf->uc.uc_mcontext.regs[i],
				 err);
	__put_user_error(regs->sp, &sf->uc.uc_mcontext.sp, err);
	__put_user_error(regs->pc, &sf->uc.uc_mcontext.pc, err);
	__put_user_error(regs->pstate, &sf->uc.uc_mcontext.pstate, err);

	__put_user_error(current->thread.fault_address, &sf->uc.uc_mcontext.fault_address, err);

	err |= put_sigset_t(&sf->uc.uc_sigmask, set);

	if (err == 0) {
		struct fpsimd_context __user *fpsimd_ctx =
			apply_user_offset(user, user->fpsimd_offset);
		err |= preserve_fpsimd_context(fpsimd_ctx);
	}

	/* fault information, if valid */
	if (err == 0 && user->esr_offset) {
		struct esr_context __user *esr_ctx =
			apply_user_offset(user, user->esr_offset);

		__put_user_error(ESR_MAGIC, &esr_ctx->head.magic, err);
		__put_user_error(sizeof(*esr_ctx), &esr_ctx->head.size, err);
		__put_user_error(current->thread.fault_code, &esr_ctx->esr, err);
	}

	if (err == 0 && user->extra_offset)
		setup_extra_context((char *) user->sigframe, user->size,
				(char *) apply_user_offset(user, user->extra_offset));

	/* set the "end" magic */
	if (err == 0) {
		struct _aarch64_ctx __user *end =
			apply_user_offset(user, user->end_offset);

		__put_user_error(0, &end->magic, err);
		__put_user_error(0, &end->size, err);
	}

	return err;
}

static int ilp32_get_sigframe(struct ilp32_rt_sigframe_user_layout *user,
			 struct ksignal *ksig, struct pt_regs *regs)
{
	unsigned long sp, sp_top;
	int err;

	ilp32_init_user_layout(user);
	err = ilp32_setup_sigframe_layout(user);
	if (err)
		return err;

	sp = sp_top = sigsp(regs->sp, ksig);

	sp = round_down(sp - sizeof(struct frame_record), 16);
	user->next_frame = (struct frame_record __user *)sp;

	sp = round_down(sp, 16) - ilp32_sigframe_size(user);
	user->sigframe = (struct ilp32_rt_sigframe __user *)sp;

	/*
	 * Check that we can actually write to the signal frame.
	 */
	if (!access_ok(VERIFY_WRITE, user->sigframe, sp_top - sp))
		return -EFAULT;

	return 0;
}


void ilp32_setup_return(struct pt_regs *regs, struct k_sigaction *ka,
			 struct ilp32_rt_sigframe_user_layout *user, int usig)
{
	__sigrestore_t sigtramp;

	regs->regs[0] = usig;
	regs->sp = (unsigned long)user->sigframe;
	regs->regs[29] = (unsigned long)&user->next_frame->fp;
	regs->pc = (unsigned long)ka->sa.sa_handler;

	if (ka->sa.sa_flags & SA_RESTORER)
		sigtramp = ka->sa.sa_restorer;
	else
		sigtramp = VDSO_SYMBOL(current->mm->context.vdso, sigtramp_ilp32);

	regs->regs[30] = (unsigned long)sigtramp;
}

int ilp32_setup_rt_frame(int usig, struct ksignal *ksig,
			  sigset_t *set, struct pt_regs *regs)
{
	struct ilp32_rt_sigframe_user_layout user;
	struct ilp32_rt_sigframe __user *frame;
	int err = 0;

	if (ilp32_get_sigframe(&user, ksig, regs))
		return 1;

	frame = user.sigframe;

	__put_user_error(0, &frame->uc.uc_flags, err);
	__put_user_error(0, &frame->uc.uc_link, err);

	err |= __compat_save_altstack(&frame->uc.uc_stack, regs->sp);
	err |= ilp32_setup_sigframe(&user, regs, set);
	if (err == 0) {
		ilp32_setup_return(regs, &ksig->ka, &user, usig);
		if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
			err = copy_siginfo_to_user32(&frame->info, &ksig->info);
			regs->regs[1] = (unsigned long)&frame->info;
			regs->regs[2] = (unsigned long)&frame->uc;
		}
	}

	return err;
}
