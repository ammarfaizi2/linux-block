// SPDX-License-Identifier: GPL-2.0-only
/*
 * sigreturn.c - tests that x86 avoids Intel SYSRET pitfalls
 * Copyright (c) 2014-2016 Andrew Lutomirski
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/signal.h>
#include <sys/ucontext.h>
#include <sys/syscall.h>
#include <err.h>
#include <stddef.h>
#include <stdbool.h>
#include <setjmp.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <assert.h>


asm (
	".pushsection \".text\", \"ax\"\n\t"
	".balign 4096\n\t"
	"test_page: .globl test_page\n\t"
	".fill 4094,1,0xcc\n\t"
	"test_syscall_insn:\n\t"
	"syscall\n\t"
	".ifne . - test_page - 4096\n\t"
	".error \"test page is not one page long\"\n\t"
	".endif\n\t"
	".popsection"
    );

extern const char test_page[];
static void const *current_test_page_addr = test_page;

/*
 * Arbitrary values.
 */
static const unsigned long r11_sentinel = 0xfeedfacedeadbeef;
static const unsigned long rcx_sentinel = 0x5ca1ab1e0b57ac1e;

/*
 * An arbitrary *valid* RFLAGS value.
 */
static const unsigned long rflags_sentinel = 0x200a93;

enum regs_ok {
	REGS_UNDEFINED	= -1,
	REGS_SAVED	=  0,	/* Registers properly preserved (Intel FRED). */
	REGS_SYSRET	=  1	/* Registers match syscall/sysret. */
};

/*
 * @rbx should be set to the syscall return %rip.
 */
static void check_regs_result(unsigned long r11, unsigned long rcx,
			      unsigned long rbx)
{
	static enum regs_ok regs_ok_state = REGS_UNDEFINED;
	enum regs_ok ret;

	if (r11 == r11_sentinel && rcx == rcx_sentinel) {
		ret = REGS_SAVED;
	} else if (r11 == rflags_sentinel && rcx == rbx) {
		ret = REGS_SYSRET;
	} else {
		printf("[FAIL] check_regs_result\n");
		printf("        r11_sentinel = %#lx; %%r11 = %#lx;\n", r11_sentinel, r11);
		printf("        rcx_sentinel = %#lx; %%rcx = %#lx;\n", rcx_sentinel, rcx);
		printf("        rflags_sentinel = %#lx\n", rflags_sentinel);
		exit(1);
	}


	/*
	 * Test that we don't get a mix of REGS_SAVED and REGS_SYSRET.
	 * It needs at least calling check_regs_result() twice to assert.
	 */
	if (regs_ok_state == REGS_UNDEFINED) {
		/*
		 * First time calling check_regs_result().
		 */
		regs_ok_state = ret;
	} else {
		assert(regs_ok_state == ret);
	}
}

/*
 * There are two cases:
 *
 *   A) 'syscall' in a FRED system preserves %rcx and %r11.
 *   B) 'syscall' in a non-FRED system sets %rcx=%rip and %r11=%rflags.
 *
 * When the do_syscall() function is called for the first time,
 * check_regs_result() will memorize the behavior, either (A) or (B).
 * Then, the next do_syscall() call will verify that the 'syscall'
 * behavior is the same.
 *
 * This function needs to be called at least twice to assert.
 */
static long do_syscall(long nr_syscall, unsigned long arg1, unsigned long arg2,
		       unsigned long arg3, unsigned long arg4,
		       unsigned long arg5, unsigned long arg6)
{
	unsigned long rbx;
	unsigned long rcx = rcx_sentinel;
	register unsigned long r11 __asm__("%r11") = r11_sentinel;
	register unsigned long r10 __asm__("%r10") = arg4;
	register unsigned long r8 __asm__("%r8") = arg5;
	register unsigned long r9 __asm__("%r9") = arg6;

	__asm__ volatile (
		"movq       -8(%%rsp), %%r12\n\t"    // Do not clobber the red zone.
		"pushq      %[rflags_sentinel]\n\t"
		"popfq\n\t"
		"movq       %%r12, -8(%%rsp)\n\t"
		"leaq       1f(%%rip), %[rbx]\n\t"
		"syscall\n"
		"1:"

		: "+a" (nr_syscall),
		  "+r" (r11),
		  "+c" (rcx),
		  [rbx] "=b" (rbx)

		: [rflags_sentinel] "g" (rflags_sentinel),
		  "D" (arg1),	/* %rdi */
		  "S" (arg2),	/* %rsi */
		  "d" (arg3),	/* %rdx */
		  "r" (r10),
		  "r" (r8),
		  "r" (r9)

		: "r12", "memory"
	);

	check_regs_result(r11, rcx, rbx);
	return nr_syscall;
}

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

static void clearhandler(int sig)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, 0))
		err(1, "sigaction");
}

/* State used by our signal handlers. */
static gregset_t initial_regs;

static volatile unsigned long rip;

static void sigsegv_for_sigreturn_test(int sig, siginfo_t *info, void *ctx_void)
{
	ucontext_t *ctx = (ucontext_t*)ctx_void;

	if (rip != ctx->uc_mcontext.gregs[REG_RIP]) {
		printf("[FAIL]\tRequested RIP=0x%lx but got RIP=0x%lx\n",
		       rip, (unsigned long)ctx->uc_mcontext.gregs[REG_RIP]);
		fflush(stdout);
		_exit(1);
	}

	memcpy(&ctx->uc_mcontext.gregs, &initial_regs, sizeof(gregset_t));

	printf("[OK]\tGot SIGSEGV at RIP=0x%lx\n", rip);
}

static void sigusr1(int sig, siginfo_t *info, void *ctx_void)
{
	ucontext_t *ctx = (ucontext_t*)ctx_void;

	memcpy(&initial_regs, &ctx->uc_mcontext.gregs, sizeof(gregset_t));

	check_regs_result(ctx->uc_mcontext.gregs[REG_R11],
			  ctx->uc_mcontext.gregs[REG_RCX],
			  ctx->uc_mcontext.gregs[REG_RBX]);

	/* Set IP and CX to match so that SYSRET can happen. */
	ctx->uc_mcontext.gregs[REG_RIP] = rip;
	ctx->uc_mcontext.gregs[REG_RCX] = rip;
	sethandler(SIGSEGV, sigsegv_for_sigreturn_test, SA_RESETHAND);
}

static void __raise(int sig)
{
	do_syscall(__NR_kill, getpid(), sig, 0, 0, 0, 0);
}

static void test_sigreturn_to(unsigned long ip)
{
	rip = ip;
	printf("[RUN]\tsigreturn to 0x%lx\n", ip);
	__raise(SIGUSR1);
}

static jmp_buf jmpbuf;

static void sigsegv_for_fallthrough(int sig, siginfo_t *info, void *ctx_void)
{
	ucontext_t *ctx = (ucontext_t*)ctx_void;

	if (rip != ctx->uc_mcontext.gregs[REG_RIP]) {
		printf("[FAIL]\tExpected SIGSEGV at 0x%lx but got RIP=0x%lx\n",
		       rip, (unsigned long)ctx->uc_mcontext.gregs[REG_RIP]);
		fflush(stdout);
		_exit(1);
	}

	siglongjmp(jmpbuf, 1);
}

static void test_syscall_fallthrough_to(unsigned long ip)
{
	void *new_address = (void *)(ip - 4096);
	void *ret;

	printf("[RUN]\tTrying a SYSCALL that falls through to 0x%lx\n", ip);

	ret = mremap((void *)current_test_page_addr, 4096, 4096,
		     MREMAP_MAYMOVE | MREMAP_FIXED, new_address);
	if (ret == MAP_FAILED) {
		if (ip <= (1UL << 47) - PAGE_SIZE) {
			err(1, "mremap to %p", new_address);
		} else {
			printf("[OK]\tmremap to %p failed\n", new_address);
			return;
		}
	}

	if (ret != new_address)
		errx(1, "mremap malfunctioned: asked for %p but got %p\n",
		     new_address, ret);

	current_test_page_addr = new_address;
	rip = ip;

	if (sigsetjmp(jmpbuf, 1) == 0) {
		asm volatile ("call *%[syscall_insn]" :: "a" (SYS_getpid),
			      [syscall_insn] "rm" (ip - 2));
		errx(1, "[FAIL]\tSyscall trampoline returned");
	}

	printf("[OK]\tWe survived\n");
}

int main()
{
	/*
	 * When the kernel returns from a slow-path syscall, it will
	 * detect whether SYSRET is appropriate.  If it incorrectly
	 * thinks that SYSRET is appropriate when RIP is noncanonical,
	 * it'll crash on Intel CPUs.
	 */
	sethandler(SIGUSR1, sigusr1, 0);
	for (int i = 47; i < 64; i++)
		test_sigreturn_to(1UL<<i);

	clearhandler(SIGUSR1);

	sethandler(SIGSEGV, sigsegv_for_fallthrough, 0);

	/* One extra test to check that we didn't screw up the mremap logic. */
	test_syscall_fallthrough_to((1UL << 47) - 2*PAGE_SIZE);

	/* These are the interesting cases. */
	for (int i = 47; i < 64; i++) {
		test_syscall_fallthrough_to((1UL<<i) - PAGE_SIZE);
		test_syscall_fallthrough_to(1UL<<i);
	}

	return 0;
}
