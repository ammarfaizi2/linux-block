#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <err.h>
#include <pthread.h>

#ifdef __x86_64__
#include <xmmintrin.h>
#endif

typedef uint32_t u32;

struct fenv_state {
	u32			cwd;	/* FPU Control Word		*/
	u32			swd;	/* FPU Status Word		*/
	u32			twd;	/* FPU Tag Word			*/
	u32			fip;	/* FPU IP Offset		*/
	u32			fcs;	/* FPU IP Selector		*/
	u32			foo;	/* FPU Operand Pointer Offset	*/
	u32			fos;	/* FPU Operand Pointer Selector	*/
};

static void fninit(void)
{
	asm volatile ("fninit");
}

static void fnstenv(struct fenv_state *env)
{
	asm volatile ("fnstenv %0" : "=m" (*env));
}

static void fldenv(const struct fenv_state *env)
{
	asm volatile ("fldenv %0" :: "m" (*env));
}

static volatile int ftx;

static void *threadproc(void *ctx)
{
	/* Whenever ftx becomes 1, change it back to 0. */
	while (1) {
		syscall(SYS_futex, &ftx, FUTEX_WAIT, 0, NULL, NULL, 0);
		if (ftx == 1) {
			ftx = 0;
			syscall(SYS_futex, &ftx, FUTEX_WAKE, 1, NULL, NULL, 0);
		}
	}

	return NULL;
}


int main()
{
	/*
	 * Start a thread on the same CPU we're on.  For simplicity,
	 * just stick everything to CPU 0.  This will fail in some
	 * containers, but that's probably okay.
	 */
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0)
		printf("[WARN]\tsched_setaffinity failed\n");

	pthread_t thread;
	if (pthread_create(&thread, 0, threadproc, 0) != 0)
		err(1, "pthread_create");

	struct fenv_state fenv;
	fninit();
	fnstenv(&fenv);
	printf("\tInitial FPU control word: 0x%hx\n", (uint16_t)fenv.cwd);
	/* Unmask all exceptions, set single precision, round to zero */
	fenv.cwd = 3 << 10;
	/* Set IE (invalid op pending) and ES (which appears to be ignored) */
	fenv.swd |= ((1 << 0) | (1 << 7));	/* set IE and ES */
	fldenv(&fenv);

	#ifdef __x86_64__
	/* All exceptions signaled, none masked, round to zero, FTZ. */
	_mm_setcsr(0x3f | (7 << 13));
	#endif

	/* Make the helper thread run on this CPU to force scheduling. */
	ftx = 1;
	syscall(SYS_futex, &ftx, FUTEX_WAKE, 1, NULL, NULL, 0);
	while (ftx == 1)
		syscall(SYS_futex, &ftx, FUTEX_WAIT, 1, NULL, NULL, 0);
	
	asm volatile ("fwait");

	return 0;
}
