/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mov_ss_trap.c: Exercise the bizarre side effects of a watchpoint on MOV SS
 *
 * This does MOV SS from a watchpointed address followed by various
 * types of kernel entries.  A MOV SS that hits a watchpoint will queue
 * up a #DB trap but will not actually deliver that trap.  The trap
 * will be delivered after the next instruction instead.  The CPU's logic
 * seems to be:
 *
 *  - Any fault: drop the pending #DB trap.
 *  - INT $N, INT3, INTO, SYSCALL, SYSENTER: enter the kernel and then
 *    deliver #DB.
 *  - ICEBP: enter the kernel but do not deliver the watchpoint trap
 *  - breakpoint: only one #DB is delivered (phew!)
 *
 * There are plenty of ways for a kernel to handle this incorrectly.  This
 * test tries to exercise all the cases.
 *
 * This should mostly cover CVE-2018-1087 and CVE-2018-8897.
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <setjmp.h>
#include <sys/prctl.h>

#define X86_EFLAGS_RF (1UL << 16)

#if __x86_64__
# define REG_IP REG_RIP
#else
# define REG_IP REG_EIP
#endif

unsigned short ss;
extern unsigned char breakpoint_insn[];
sigjmp_buf jmpbuf;
static unsigned char altstack_data[SIGSTKSZ];

struct ptrace_req {
	enum __ptrace_request req;
	void *addr;
	void *data;
	long ret;
};

struct ptrace_req_set {
	struct ptrace_req *requests;
	size_t count;
	pid_t target;
	int num_processed;
};

static void *ptrace_thread(void *arg)
{
	struct ptrace_request_set *req_set = arg;
	int i;

	req_set->num_processed = 0;

	if (ptrace(PTRACE_ATTACH, target, NULL, NULL) != 0)
		err(1, "PTRACE_ATTACH");

	if (waitpid(req_set->target, &status, 0) != req_set->target)
		err(1, "waitpid for ptrace target");

	for (i = 0; i < req_set.count; i++) {
		struct ptrace_req *req = &req_set->requests[i];

		req->ret = ptrace(req->req, parent, req->addr, req->data);
	}

	if (ptrace(PTRACE_DETACH, req_set->target, NULL, NULL) != 0)
		err(1, "PTRACE_DETACH");

	return 0;
}

static void ptrace_me(struct ptrace_request_set *requests)
{
	pid_t me = syscall(SYS_gettid);
	pthread_t thread;

	requests->target = me;

	if (pthread_create(&thread, NULL, ptrace_thread, requests) != 0)
		err(1, "pthread_create");

	if (pthread_join(thread, NULL) != 0)
		err(1, "pthread_join");
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

static char const * const signames[] = {
	[SIGSEGV] = "SIGSEGV",
	[SIGBUS] = "SIBGUS",
	[SIGTRAP] = "SIGTRAP",
	[SIGILL] = "SIGILL",
};

static void sigtrap(int sig, siginfo_t *si, void *ctx_void)
{
	ucontext_t *ctx = ctx_void;

	printf("\tGot SIGTRAP with RIP=%lx, EFLAGS.RF=%d\n",
	       (unsigned long)ctx->uc_mcontext.gregs[REG_IP],
	       !!(ctx->uc_mcontext.gregs[REG_EFL] & X86_EFLAGS_RF));
}

static void handle_and_return(int sig, siginfo_t *si, void *ctx_void)
{
	ucontext_t *ctx = ctx_void;

	printf("\tGot %s with RIP=%lx\n", signames[sig],
	       (unsigned long)ctx->uc_mcontext.gregs[REG_IP]);
}

static void handle_and_longjmp(int sig, siginfo_t *si, void *ctx_void)
{
	ucontext_t *ctx = ctx_void;

	printf("\tGot %s with RIP=%lx\n", signames[sig],
	       (unsigned long)ctx->uc_mcontext.gregs[REG_IP]);

	siglongjmp(jmpbuf, 1);
}

int main()
{
	unsigned long nr;

	if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) == 0)
		printf("\tPR_SET_PTRACER_ANY succeeded\n");

	printf("\tSet up a watchpoint\n");
	sethandler(SIGTRAP, sigtrap, 0);
	enable_watchpoint();

	printf("[RUN]\tRead from watched memory (should get SIGTRAP)\n");
	asm volatile ("mov %[ss], %[tmp]" : [tmp] "=r" (nr) : [ss] "m" (ss));

	printf("[RUN]\tMOV SS; INT3\n");
	asm volatile ("mov %[ss], %%ss; int3" :: [ss] "m" (ss));

	printf("[RUN]\tMOV SS; INT 3\n");
	asm volatile ("mov %[ss], %%ss; .byte 0xcd, 0x3" :: [ss] "m" (ss));

	printf("[RUN]\tMOV SS; CS CS INT3\n");
	asm volatile ("mov %[ss], %%ss; .byte 0x2e, 0x2e; int3" :: [ss] "m" (ss));

	printf("[RUN]\tMOV SS; CSx14 INT3\n");
	asm volatile ("mov %[ss], %%ss; .fill 14,1,0x2e; int3" :: [ss] "m" (ss));

	printf("[RUN]\tMOV SS; INT 4\n");
	sethandler(SIGSEGV, handle_and_return, SA_RESETHAND);
	asm volatile ("mov %[ss], %%ss; int $4" :: [ss] "m" (ss));

#ifdef __i386__
	printf("[RUN]\tMOV SS; INTO\n");
	sethandler(SIGSEGV, handle_and_return, SA_RESETHAND);
	nr = -1;
	asm volatile ("add $1, %[tmp]; mov %[ss], %%ss; into"
		      : [tmp] "+r" (nr) : [ss] "m" (ss));
#endif

	if (sigsetjmp(jmpbuf, 1) == 0) {
		printf("[RUN]\tMOV SS; ICEBP\n");

		/* Some emulators (e.g. QEMU TCG) don't emulate ICEBP. */
		sethandler(SIGILL, handle_and_longjmp, SA_RESETHAND);

		asm volatile ("mov %[ss], %%ss; .byte 0xf1" :: [ss] "m" (ss));
	}

	if (sigsetjmp(jmpbuf, 1) == 0) {
		printf("[RUN]\tMOV SS; CLI\n");
		sethandler(SIGSEGV, handle_and_longjmp, SA_RESETHAND);
		asm volatile ("mov %[ss], %%ss; cli" :: [ss] "m" (ss));
	}

	if (sigsetjmp(jmpbuf, 1) == 0) {
		printf("[RUN]\tMOV SS; #PF\n");
		sethandler(SIGSEGV, handle_and_longjmp, SA_RESETHAND);
		asm volatile ("mov %[ss], %%ss; mov (-1), %[tmp]"
			      : [tmp] "=r" (nr) : [ss] "m" (ss));
	}

	/*
	 * INT $1: if #DB has DPL=3 and there isn't special handling,
	 * then the kernel will die.
	 */
	if (sigsetjmp(jmpbuf, 1) == 0) {
		printf("[RUN]\tMOV SS; INT 1\n");
		sethandler(SIGSEGV, handle_and_longjmp, SA_RESETHAND);
		asm volatile ("mov %[ss], %%ss; int $1" :: [ss] "m" (ss));
	}

#ifdef __x86_64__
	/*
	 * In principle, we should test 32-bit SYSCALL as well, but
	 * the calling convention is so unpredictable that it's
	 * not obviously worth the effort.
	 */
	if (sigsetjmp(jmpbuf, 1) == 0) {
		printf("[RUN]\tMOV SS; SYSCALL\n");
		sethandler(SIGILL, handle_and_longjmp, SA_RESETHAND);
		nr = SYS_getpid;
		/*
		 * Toggle the high bit of RSP to make it noncanonical to
		 * strengthen this test on non-SMAP systems.
		 */
		asm volatile ("btc $63, %%rsp\n\t"
			      "mov %[ss], %%ss; syscall\n\t"
			      "btc $63, %%rsp"
			      : "+a" (nr) : [ss] "m" (ss)
			      : "rcx"
#ifdef __x86_64__
				, "r11"
#endif
			);
	}
#endif

	printf("[RUN]\tMOV SS; breakpointed NOP\n");
	asm volatile ("mov %[ss], %%ss; breakpoint_insn: nop" :: [ss] "m" (ss));

	/*
	 * Invoking SYSENTER directly breaks all the rules.  Just handle
	 * the SIGSEGV.
	 */
	if (sigsetjmp(jmpbuf, 1) == 0) {
		printf("[RUN]\tMOV SS; SYSENTER\n");
		stack_t stack = {
			.ss_sp = altstack_data,
			.ss_size = SIGSTKSZ,
		};
		if (sigaltstack(&stack, NULL) != 0)
			err(1, "sigaltstack");
		sethandler(SIGSEGV, handle_and_longjmp, SA_RESETHAND | SA_ONSTACK);
		nr = SYS_getpid;
		/* Clear EBP first to make sure we segfault cleanly. */
		asm volatile ("xorl %%ebp, %%ebp; mov %[ss], %%ss; SYSENTER" : "+a" (nr)
			      : [ss] "m" (ss) : "flags", "rcx"
#ifdef __x86_64__
				, "r11"
#endif
			);

		/* We're unreachable here.  SYSENTER forgets RIP. */
	}

	if (sigsetjmp(jmpbuf, 1) == 0) {
		printf("[RUN]\tMOV SS; INT $0x80\n");
		sethandler(SIGSEGV, handle_and_longjmp, SA_RESETHAND);
		nr = 20;	/* compat getpid */
		asm volatile ("mov %[ss], %%ss; int $0x80"
			      : "+a" (nr) : [ss] "m" (ss)
			      : "flags"
#ifdef __x86_64__
				, "r8", "r9", "r10", "r11"
#endif
			);
	}

	printf("[OK]\tI aten't dead\n");
	return 0;
}
