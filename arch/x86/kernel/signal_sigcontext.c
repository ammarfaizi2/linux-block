/*
 * Signal code that has compile-time dependencies on signal ABI.
 *
 * This file is compiled twice on 64-bit systems with IA32 support.
 */

#ifdef SIGABI_64

typedef unsigned long word_t;
#define ABI(x) x##_64

#elif defined(SIGABI_32)

typedef unsigned int word_t;
#define ABI(x) x##_32

#else

#error signal_sigcontext.c must not be compiled directly

#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/tracehook.h>
#include <linux/unistd.h>
#include <linux/stddef.h>
#include <linux/personality.h>
#include <linux/uaccess.h>
#include <linux/user-return-notifier.h>
#include <linux/uprobes.h>
#include <linux/context_tracking.h>

#include <asm/processor.h>
#include <asm/ucontext.h>
#include <asm/fpu/internal.h>
#include <asm/fpu/signal.h>
#include <asm/vdso.h>
#include <asm/mce.h>
#include <asm/sighandling.h>
#include <asm/vm86.h>

#ifdef CONFIG_X86_64
#include <asm/proto.h>
#include <asm/ia32_unistd.h>
#endif /* CONFIG_X86_64 */

#include <asm/syscall.h>
#include <asm/syscalls.h>

#include <asm/sigframe.h>
#include <asm/signal.h>

#define COPY(x)			do {			\
	get_user_ex(regs->x, &sc->x);			\
} while (0)

#define GET_SEG(seg)		({			\
	unsigned short tmp;				\
	get_user_ex(tmp, &sc->seg);			\
	tmp;						\
})

#define COPY_SEG(seg)		do {			\
	set_current_##seg(regs, GET_SEG(seg));		\
} while (0)

#define COPY_SEG_CPL3(seg)	do {			\
	regs->seg = GET_SEG(seg) | 3;			\
} while (0)

int ABI(restore_sigcontext)(struct pt_regs *regs,
			    ABI(sigcontext_t) __user *sc,
			    unsigned long uc_flags)
{
	unsigned long buf_val;
	void __user *buf;
	unsigned int tmpflags;
	unsigned int err = 0;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	get_user_try {

#ifdef SIGABI_32
		set_current_gs(regs, GET_SEG(gs));
		COPY_SEG(fs);
		COPY_SEG(es);
		COPY_SEG(ds);
#endif /* SIGABI_32 */

		COPY(di); COPY(si); COPY(bp); COPY(sp); COPY(bx);
		COPY(dx); COPY(cx); COPY(ip); COPY(ax);

#ifdef SIGABI_64
		COPY(r8);
		COPY(r9);
		COPY(r10);
		COPY(r11);
		COPY(r12);
		COPY(r13);
		COPY(r14);
		COPY(r15);
#endif /* SIGABI_64 */

		COPY_SEG_CPL3(cs);
		COPY_SEG_CPL3(ss);

#ifdef SIGABI_64
		/*
		 * Fix up SS if needed for the benefit of old DOSEMU and
		 * CRIU.
		 */
		if (unlikely(!(uc_flags & UC_STRICT_RESTORE_SS) &&
			     user_64bit_mode(regs)))
			force_valid_ss(regs);
#endif

		get_user_ex(tmpflags, &sc->flags);
		regs->flags = (regs->flags & ~FIX_EFLAGS) | (tmpflags & FIX_EFLAGS);
		regs->orig_ax = -1;		/* disable syscall checks */

		get_user_ex(buf_val, &sc->fpstate);
		buf = (void __user *)buf_val;
	} get_user_catch(err);

	err |= fpu__restore_sig(buf, IS_ENABLED(CONFIG_X86_32));

	force_iret();

	return err;
}

int ABI(setup_sigcontext)(ABI(sigcontext_t) __user *sc,
			  void __user *fpstate,
			  struct pt_regs *regs, unsigned long mask)
{
	int err = 0;

	put_user_try {

#ifdef SIGABI_32
		put_user_ex(get_current_gs(regs), (unsigned int __user *)&sc->gs);
		put_user_ex(get_current_fs(regs), (unsigned int __user *)&sc->fs);
		put_user_ex(get_current_es(regs), (unsigned int __user *)&sc->es);
		put_user_ex(get_current_ds(regs), (unsigned int __user *)&sc->ds);
#endif /* SIGABI_32 */

		put_user_ex(regs->di, &sc->di);
		put_user_ex(regs->si, &sc->si);
		put_user_ex(regs->bp, &sc->bp);
		put_user_ex(regs->sp, &sc->sp);
		put_user_ex(regs->bx, &sc->bx);
		put_user_ex(regs->dx, &sc->dx);
		put_user_ex(regs->cx, &sc->cx);
		put_user_ex(regs->ax, &sc->ax);
#ifdef SIGABI_64
		put_user_ex(regs->r8, &sc->r8);
		put_user_ex(regs->r9, &sc->r9);
		put_user_ex(regs->r10, &sc->r10);
		put_user_ex(regs->r11, &sc->r11);
		put_user_ex(regs->r12, &sc->r12);
		put_user_ex(regs->r13, &sc->r13);
		put_user_ex(regs->r14, &sc->r14);
		put_user_ex(regs->r15, &sc->r15);
#endif /* SIGABI_64 */

		put_user_ex(current->thread.trap_nr, &sc->trapno);
		put_user_ex(current->thread.error_code, &sc->err);
		put_user_ex(regs->ip, &sc->ip);
		put_user_ex(get_current_cs(regs), &sc->cs);

#ifdef SIGABI_32
		put_user_ex(regs->flags, &sc->flags);
		put_user_ex(regs->sp, &sc->sp_at_signal);
		put_user_ex(get_current_ss(regs), (unsigned int __user *)&sc->ss);
#else /* !SIGABI_32 */
		put_user_ex(regs->flags, &sc->flags);
		put_user_ex(0, &sc->gs);
		put_user_ex(0, &sc->fs);
		put_user_ex(regs->ss, &sc->ss);
#endif /* CONFIG_X86_32 */

		put_user_ex((word_t)(unsigned long)fpstate, &sc->fpstate);

		/* non-iBCS2 extensions.. */
		put_user_ex(mask, &sc->oldmask);
		put_user_ex(current->thread.cr2, &sc->cr2);
	} put_user_catch(err);

	return err;
}

