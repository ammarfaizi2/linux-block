/*
 *  linux/arch/x86_64/ia32/ia32_signal.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  1997-11-28  Modified for POSIX.1b signals by Richard Henderson
 *  2000-06-20  Pentium III FXSR, SSE support by Gareth Hughes
 *  2000-12-*   x86-64 compatibility mode signal handling by Andi Kleen
 */

#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/unistd.h>
#include <linux/stddef.h>
#include <linux/personality.h>
#include <linux/compat.h>
#include <linux/binfmts.h>
#include <asm/ucontext.h>
#include <linux/uaccess.h>
#include <asm/fpu/internal.h>
#include <asm/fpu/signal.h>
#include <asm/ptrace.h>
#include <asm/ia32_unistd.h>
#include <asm/user32.h>
#include <uapi/asm/sigcontext.h>
#include <asm/proto.h>
#include <asm/vdso.h>
#include <asm/sigframe.h>
#include <asm/sighandling.h>
#include <asm/sys_ia32.h>
#include <asm/smap.h>

/*
 * Do a signal return; undo the signal stack.
 */
#define loadsegment_gs(v)	load_gs_index(v)
#define loadsegment_fs(v)	loadsegment(fs, v)
#define loadsegment_ds(v)	loadsegment(ds, v)
#define loadsegment_es(v)	loadsegment(es, v)

#define get_user_seg(seg)	({ unsigned int v; savesegment(seg, v); v; })
#define set_user_seg(seg, v)	loadsegment_##seg(v)

#define COPY(x)			{		\
	get_user_ex(regs->x, &sc->x);		\
}

#define GET_SEG(seg)		({			\
	unsigned short tmp;				\
	get_user_ex(tmp, &sc->seg);			\
	tmp;						\
})

#define COPY_SEG_CPL3(seg)	do {			\
	regs->seg = GET_SEG(seg) | 3;			\
} while (0)

#define RELOAD_SEG(seg)		{		\
	unsigned int pre = GET_SEG(seg);	\
	unsigned int cur = get_user_seg(seg);	\
	pre |= 3;				\
	if (pre != cur)				\
		set_user_seg(seg, pre);		\
}

static int ia32_restore_sigcontext(struct pt_regs *regs,
				   struct sigcontext_32 __user *sc)
{
	unsigned int tmpflags, err = 0;
	void __user *buf;
	u32 tmp;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	get_user_try {
		/*
		 * Reload fs and gs if they have changed in the signal
		 * handler.  This does not handle long fs/gs base changes in
		 * the handler, but does not clobber them at least in the
		 * normal case.
		 */
		RELOAD_SEG(gs);
		RELOAD_SEG(fs);
		RELOAD_SEG(ds);
		RELOAD_SEG(es);

		COPY(di); COPY(si); COPY(bp); COPY(sp); COPY(bx);
		COPY(dx); COPY(cx); COPY(ip); COPY(ax);
		/* Don't touch extended registers */

		COPY_SEG_CPL3(cs);
		COPY_SEG_CPL3(ss);

		get_user_ex(tmpflags, &sc->flags);
		regs->flags = (regs->flags & ~FIX_EFLAGS) | (tmpflags & FIX_EFLAGS);
		/* disable syscall checks */
		regs->orig_ax = -1;

		get_user_ex(tmp, &sc->fpstate);
		buf = compat_ptr(tmp);
	} get_user_catch(err);

	err |= fpu__restore_sig(buf, 1);

	force_iret();

	return err;
}

asmlinkage long sys32_sigreturn(void)
{
	struct pt_regs *regs = current_pt_regs();
	struct sigframe_ia32 __user *frame = (struct sigframe_ia32 __user *)(regs->sp-8);
	sigset_t set;

	if (!access_ok(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	if (__get_user(set.sig[0], &frame->sc.oldmask)
	    || (_COMPAT_NSIG_WORDS > 1
		&& __copy_from_user((((char *) &set.sig) + 4),
				    &frame->extramask,
				    sizeof(frame->extramask))))
		goto badframe;

	set_current_blocked(&set);

	if (ia32_restore_sigcontext(regs, &frame->sc))
		goto badframe;
	return regs->ax;

badframe:
	signal_fault(regs, frame, "32bit sigreturn");
	return 0;
}

asmlinkage long sys32_rt_sigreturn(void)
{
	struct pt_regs *regs = current_pt_regs();
	struct rt_sigframe_ia32 __user *frame;
	sigset_t set;

	frame = (struct rt_sigframe_ia32 __user *)(regs->sp - 4);

	if (!access_ok(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	if (__copy_from_user(&set, &frame->uc.uc_sigmask, sizeof(set)))
		goto badframe;

	set_current_blocked(&set);

	if (ia32_restore_sigcontext(regs, &frame->uc.uc_mcontext))
		goto badframe;

	if (compat_restore_altstack(&frame->uc.uc_stack))
		goto badframe;

	return regs->ax;

badframe:
	signal_fault(regs, frame, "32bit rt sigreturn");
	return 0;
}
