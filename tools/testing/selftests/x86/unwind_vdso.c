/*
 * unwind_vdso.c - tests unwind info for AT_SYSINFO in the vDSO
 * Copyright (c) 2014-2015 Andrew Lutomirski
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * This tests __kernel_vsyscall's unwind info.
 */

#define _GNU_SOURCE

#include <features.h>
#include <stdio.h>

#if defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 16

int main()
{
	/* We need getauxval(). */
	printf("[SKIP]\tGLIBC before 2.16 cannot compile this test\n");
	return 0;
}

#else

#include <sys/time.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <err.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/ucontext.h>
#include <link.h>
#include <sys/auxv.h>
#include <dlfcn.h>
#include <unwind.h>

static void sethandler(int sig, void (*handler)(int, siginfo_t *, void *),
		       int flags)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO | flags;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, 0))
		err(1, "sigaction");
}

#ifdef __x86_64__
# define WIDTH "q"
#else
# define WIDTH "l"
#endif

static unsigned long get_eflags(void)
{
	unsigned long eflags;
	asm volatile ("pushf" WIDTH "\n\tpop" WIDTH " %0" : "=rm" (eflags));
	return eflags;
}

static void set_eflags(unsigned long eflags)
{
	asm volatile ("push" WIDTH " %0\n\tpopf" WIDTH
		      : : "rm" (eflags) : "flags");
}

#define X86_EFLAGS_TF (1UL << 8)

static volatile sig_atomic_t nerrs;
static unsigned long sysinfo;
static bool got_sysinfo = false;
static unsigned long return_address;

static unsigned long (*vdso_pending_syscall_return_address)(
	const void *context);

struct unwind_state {
	unsigned long ip;	/* trap source */
	unsigned long ax;	/* ax at call site */
	int depth;		/* -1 until we hit the trap source */
};

_Unwind_Reason_Code trace_fn(struct _Unwind_Context * ctx, void *opaque)
{
	struct unwind_state *state = opaque;
	unsigned long ip = _Unwind_GetIP(ctx);

	if (state->depth == -1) {
		if (ip == state->ip)
			state->depth = 0;
		else
			return _URC_NO_REASON;	/* Not there yet */
	}
	printf("\t  0x%lx\n", ip);

	if (ip == return_address) {
		/* Here we are. */
		unsigned long eax = _Unwind_GetGR(ctx, 0);
		unsigned long ecx = _Unwind_GetGR(ctx, 1);
		unsigned long edx = _Unwind_GetGR(ctx, 2);
		unsigned long ebx = _Unwind_GetGR(ctx, 3);
		unsigned long ebp = _Unwind_GetGR(ctx, 5);
		unsigned long esi = _Unwind_GetGR(ctx, 6);
		unsigned long edi = _Unwind_GetGR(ctx, 7);
		bool ok = (eax == SYS_break || eax == -ENOSYS) &&
			ebx == 1 && ecx == 2 && edx == 3 &&
			esi == 4 && edi == 5 && ebp == 6;

		if (!ok)
			nerrs++;
		printf("[%s]\t  NR = %ld, args = %ld, %ld, %ld, %ld, %ld, %ld\n",
		       (ok ? "OK" : "FAIL"),
		       eax, ebx, ecx, edx, esi, edi, ebp);

		state->ax = eax;

		return _URC_NORMAL_STOP;
	} else {
		state->depth++;
		return _URC_NO_REASON;
	}
}

static void sigtrap(int sig, siginfo_t *info, void *ctx_void)
{
	ucontext_t *ctx = (ucontext_t *)ctx_void;
	struct unwind_state state;
	unsigned long ip = ctx->uc_mcontext.gregs[REG_EIP];
	unsigned long reported_return_address = 0;

	if (!got_sysinfo && ip == sysinfo) {
		got_sysinfo = true;

		/* Find the return address. */
		return_address = *(unsigned long *)(unsigned long)ctx->uc_mcontext.gregs[REG_ESP];

		printf("\tIn vsyscall at 0x%lx, returning to 0x%lx\n",
		       ip, return_address);
	}

	if (!got_sysinfo) {
		if (vdso_pending_syscall_return_address &&
		    vdso_pending_syscall_return_address(ctx_void) != -1UL) {
			printf("[FAIL]\t__vdso_pending_syscall_return_address incorrectly detected a pending syscall\n");
			nerrs++;
		}

		return;		/* We haven't started AT_SYSINFO yet */
	}

	if (ip == return_address) {
		ctx->uc_mcontext.gregs[REG_EFL] &= ~X86_EFLAGS_TF;
		printf("\tVsyscall is done\n");
		return;
	}

	if (vdso_pending_syscall_return_address) {
		reported_return_address =
			vdso_pending_syscall_return_address(ctx_void);
		if (reported_return_address != -1UL)
			printf("\tSIGTRAP at 0x%lx, pending syscall will return to 0x%lx\n",
			       ip, reported_return_address);
		else
			printf("\tSIGTRAP at 0x%lx, no syscall pending\n", ip);
	} else {
		printf("\tSIGTRAP at 0x%lx\n", ip);
	}

	state.ip = ip;
	state.depth = -1;
	_Unwind_Backtrace(trace_fn, &state);

	if (vdso_pending_syscall_return_address) {
		unsigned long expected =
			(state.ax == SYS_break ? return_address : -1UL);
		if (reported_return_address != expected) {
			printf("[FAIL]\t  __vdso_pending_syscall_return_address returned 0x%lx; expected 0x%lx\n", reported_return_address, expected);
			nerrs++;
		} else {
			printf("[OK]\t  __vdso_pending_syscall_return_address returned the correct value\n");
		}
	}
}

int main()
{
	sysinfo = getauxval(AT_SYSINFO);
	printf("\tAT_SYSINFO is 0x%lx\n", sysinfo);

	Dl_info info;
	if (!dladdr((void *)sysinfo, &info)) {
		printf("[WARN]\tdladdr failed on AT_SYSINFO\n");
	} else {
		printf("[OK]\tAT_SYSINFO maps to %s, loaded at 0x%p\n",
		       info.dli_fname, info.dli_fbase);
	}

	void *vdso = dlopen("linux-gate.so.1", RTLD_NOW);
	if (vdso)
		vdso_pending_syscall_return_address = dlsym(vdso, "__vdso_pending_syscall_return_address");

	sethandler(SIGTRAP, sigtrap, 0);

	syscall(SYS_break);  /* Force symbol binding without TF set. */
	printf("[RUN]\tSet TF and check a fast syscall\n");
	set_eflags(get_eflags() | X86_EFLAGS_TF);

	/*
	 * We need a harmless syscall that will never return its own syscall
	 * nr.  SYS_break is not implemented and returns -ENOSYS.
	 */
	syscall(SYS_break, 1, 2, 3, 4, 5, 6);
	if (!got_sysinfo) {
		set_eflags(get_eflags() & ~X86_EFLAGS_TF);

		/*
		 * The most likely cause of this is that you're on Debian or
		 * a Debian-based distro, you're missing libc6-i686, and you're
		 * affected by libc/19006 (https://sourceware.org/PR19006).
		 */
		printf("[WARN]\tsyscall(2) didn't enter AT_SYSINFO\n");
	}

	if (get_eflags() & X86_EFLAGS_TF) {
		printf("[FAIL]\tTF is still set\n");
		nerrs++;
	}

	if (nerrs) {
		printf("[FAIL]\tThere were errors\n");
		return 1;
	} else {
		printf("[OK]\tAll is well\n");
		return 0;
	}
}

#endif	/* New enough libc */
