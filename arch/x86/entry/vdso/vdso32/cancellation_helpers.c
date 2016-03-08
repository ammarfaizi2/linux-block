/*
 * Copyright (c) 2016 Andrew Lutomirski
 * Subject to the GNU Public License, v.2
 *
 * This provides helpers to enable libc implementations to cancel
 * interrupted AT_SYSINFO invocations without needing to parse the
 * DWARF unwinding instructions.
 */

typedef unsigned long size_t;
#define NULL ((void *)0)
#include <linux/compiler.h>

#undef __KERNEL__  /* Get the uapi signal types */
#include <asm/posix_types.h>
#include <asm/errno.h>
#include <asm/sigcontext.h>
#include <asm/signal.h>
#include <asm/ucontext.h>

extern char __kernel_vsyscall[] __attribute__((visibility("hidden")));
extern char int80_landing_pad[] __attribute__((visibility("hidden")));

static unsigned long *pending_syscall_retaddr_ptr(const void *context)
{
	const struct ucontext *uc = context;
	unsigned long ctx_eip = uc->uc_mcontext.eip;
	unsigned long offset_into_vsyscall;
	unsigned long *retaddr;

	/*
	 * An AT_SYSINFO system call is pending if and only if we're in
	 * __kernel_vsyscall before int80_landing_pad.  If we're at
	 * int80_landing_pad or beyond, we've finished the system call
	 * and are on our way out.
	 *
	 * If we're at int80_landing_pad-2, then either we're using the
	 * int $0x80 slow path because we have no fast system call
	 * support or we are restarting a fast system call.  Either way,
	 * the system call is still pending.
	 */

	if (ctx_eip < (unsigned long)__kernel_vsyscall ||
	    ctx_eip >= (unsigned long)int80_landing_pad)
		return NULL;

	/*
	 * The first three instructions of __kernel_vsyscall are one-byte
	 * pushes.
	 */
	offset_into_vsyscall = (ctx_eip - (unsigned long)__kernel_vsyscall);
	retaddr = (unsigned long *)uc->uc_mcontext.esp;
	if (offset_into_vsyscall < 3)
		retaddr += offset_into_vsyscall;
	else
		retaddr += 3;

	/*
	 * GCC (correctly) fails to deduce out that retaddr can't be NULL
	 * in the success path.  Helping it out reduces code size.
	 * Use __builtin_unreachable() because unreachable() has an asm
	 * statement and thus forces the branch to be generated.
	 */
	if (!retaddr)
		__builtin_unreachable();

	return retaddr;
}

/*
 * If context is a sigcontext for a pending AT_SYSINFO syscall, returns
 * the return address of that syscall.  Otherwise returns -1UL.
 */
unsigned long __vdso_pending_syscall_return_address(const void *context)
{
	unsigned long *retaddr = pending_syscall_retaddr_ptr(context);
	return retaddr ? *retaddr : -1UL;
}

/*
 * If context is a sigcontext for a pending AT_SYSINFO syscall, then
 * this will pop off the call frame and point the context to
 * AT_SYSINFO's return address.  ESP will contain whatever value it had
 * immediately prior to the call instruction (i.e. ESP acts as though
 * the system call returned normally).  EAX will be set to -EINTR.  All
 * other GPRs will be clobbered.  __vdso_abort_pending_syscall will
 * return 0.
 *
 * If context is a valid sigcontext that does not represent a pending
 * AT_SYSINFO syscall, then __vdso_abort_pending_syscall returns
 * -EINVAL.
 *
 * If context is not a valid sigcontext at all, behavior is undefined.
 */
long __vdso_abort_pending_syscall(void *context)
{
	struct ucontext *uc = context;
	unsigned long *retaddr = pending_syscall_retaddr_ptr(context);

	if (!retaddr)
		return -EINVAL;

	uc->uc_mcontext.eip = *retaddr;
	uc->uc_mcontext.esp = (unsigned long)(retaddr + 1);

	/*
	 * Clobber GPRs -- we don't want to implement full unwinding, and we
	 * don't want userspace to start expecting anything about the final
	 * state of the GPRs.
	 *
	 * (There really are subtleties here.  EAX can be clobbered by
	 *  syscall restart, and register limitations mean that the
	 *  saved context has at least one of the argument registers
	 *  used for a different purpose by the calling sequence just
	 *  prior to kernel entry.  In the current implementation, that
	 *  register is EBP, but it could change.)
	 */
	uc->uc_mcontext.eax = -EINTR;
	uc->uc_mcontext.ebx = 0xFFFFFFFF;
	uc->uc_mcontext.ecx = 0xFFFFFFFF;
	uc->uc_mcontext.edx = 0xFFFFFFFF;
	uc->uc_mcontext.esi = 0xFFFFFFFF;
	uc->uc_mcontext.edi = 0xFFFFFFFF;
	uc->uc_mcontext.ebp = 0xFFFFFFFF;
	return 0;
}
