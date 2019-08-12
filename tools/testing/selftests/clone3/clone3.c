// SPDX-License-Identifier: GPL-2.0

/* Based on Christian Brauner's clone3() example */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>

#include "../kselftest.h"

/*
 * Different sizes of struct clone_args
 */
#define CLONE3_ARGS_SIZE_V0 64
/* V1 includes set_tid */
#define CLONE3_ARGS_SIZE_V1 72

#define CLONE3_ARGS_NO_TEST 0
#define CLONE3_ARGS_ALL_0 1
#define CLONE3_ARGS_ALL_1 2

static pid_t raw_clone(struct clone_args *args, size_t size)
{
	return syscall(__NR_clone3, args, size);
}

static int call_clone3(int flags, size_t size, int test_mode)
{
	struct clone_args args = {0};
	pid_t ppid = -1;
	pid_t pid = -1;
	int status;

	args.flags = flags;
	args.exit_signal = SIGCHLD;

	if (size == 0)
		size = sizeof(struct clone_args);

	if (test_mode == CLONE3_ARGS_ALL_0) {
		args.flags = 0;
		args.pidfd = 0;
		args.child_tid = 0;
		args.parent_tid = 0;
		args.exit_signal = 0;
		args.stack = 0;
		args. stack_size = 0;
		args.tls = 0;
		args.set_tid = 0;
	} else if (test_mode == CLONE3_ARGS_ALL_1) {
		args.flags = 1;
		args.pidfd = 1;
		args.child_tid = 1;
		args.parent_tid = 1;
		args.exit_signal = 1;
		args.stack = 1;
		args. stack_size = 1;
		args.tls = 1;
		args.set_tid = 1;
	}

	pid = raw_clone(&args, size);
	if (pid < 0) {
		ksft_print_msg("%s - Failed to create new process\n",
				strerror(errno));
		return -errno;
	}

	if (pid == 0) {
		ksft_print_msg("I am the child, my PID is %d\n", getpid());
		_exit(EXIT_SUCCESS);
	}

	ppid = getpid();
	ksft_print_msg("I am the parent (%d). My child's pid is %d\n",
			ppid, pid);

	(void)wait(&status);
	if (WEXITSTATUS(status))
		return WEXITSTATUS(status);

	return 0;
}

static int test_clone3(int flags, size_t size, int expected, int test_mode)
{
	int ret;

	ksft_print_msg("[%d] Trying clone3() with flags 0x%x (size %d)\n",
			getpid(), flags, size);
	ret = call_clone3(flags, size, test_mode);
	ksft_print_msg("[%d] clone3() with flags says :%d expected %d\n",
			getpid(), ret, expected);
	if (ret != expected)
		ksft_exit_fail_msg(
			"[%d] Result (%d) is different than expected (%d)\n",
			getpid(), ret, expected);
	ksft_test_result_pass("[%d] Result (%d) matches expectation (%d)\n",
			getpid(), ret, expected);
	return 0;
}
int main(int argc, char *argv[])
{
	int ret = -1;
	pid_t pid;

	ksft_print_header();
	ksft_set_plan(16);

	/* Just a simple clone3() should return 0.*/
	if (test_clone3(0, 0, 0, CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() in a new PID NS.*/
	if (test_clone3(CLONE_NEWPID, 0, 0, CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with CLONE3_ARGS_SIZE_V0. */
	if (test_clone3(0, CLONE3_ARGS_SIZE_V0, 0, CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with CLONE3_ARGS_SIZE_V1. */
	if (test_clone3(0, CLONE3_ARGS_SIZE_V0, 0, CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with CLONE3_ARGS_SIZE_V0 - 8 */
	if (test_clone3(0, CLONE3_ARGS_SIZE_V0 - 8, -EINVAL,
				CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with sizeof(struct clone_args) + 8 */
	if (test_clone3(0, sizeof(struct clone_args) + 8, -E2BIG,
				CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with all members set to 1 */
	if (test_clone3(0, CLONE3_ARGS_SIZE_V0, -EINVAL, CLONE3_ARGS_ALL_1))
		goto on_error;
	/*
	 * Do a clone3() with sizeof(struct clone_args) + 8
	 * and all members set to 0.
	 */
	if (test_clone3(0, sizeof(struct clone_args) + 8, -E2BIG,
				CLONE3_ARGS_ALL_0))
		goto on_error;
	/*
	 * Do a clone3() with sizeof(struct clone_args) + 8
	 * and all members set to 0.
	 */
	if (test_clone3(0, sizeof(struct clone_args) + 8, -E2BIG,
				CLONE3_ARGS_ALL_1))
		goto on_error;
	/* Do a clone3() with > page size */
	if (test_clone3(0, getpagesize() + 8, -E2BIG, CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with CLONE3_ARGS_SIZE_V0 in a new PID NS. */
	if (test_clone3(CLONE_NEWPID, CLONE3_ARGS_SIZE_V0, 0,
				CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with CLONE3_ARGS_SIZE_V1 in a new PID NS. */
	if (test_clone3(CLONE_NEWPID, CLONE3_ARGS_SIZE_V0, 0,
				CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with CLONE3_ARGS_SIZE_V0 - 8 in a new PID NS */
	if (test_clone3(CLONE_NEWPID, CLONE3_ARGS_SIZE_V0 - 8, -EINVAL,
				CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with sizeof(struct clone_args) + 8 in a new PID NS */
	if (test_clone3(CLONE_NEWPID, sizeof(struct clone_args) + 8, -E2BIG,
				CLONE3_ARGS_NO_TEST))
		goto on_error;
	/* Do a clone3() with > page size in a new PID NS */
	if (test_clone3(CLONE_NEWPID, getpagesize() + 8, -E2BIG,
				CLONE3_ARGS_NO_TEST))
		goto on_error;
	ksft_print_msg("First unshare\n");
	if (unshare(CLONE_NEWPID))
		goto on_error;
	/*
	 * Before clone3()ing in a new PID NS with
	 * CLONE_NEWPID a fork() is necessary.
	 */
	if (test_clone3(CLONE_NEWPID, 0, -EINVAL, CLONE3_ARGS_NO_TEST))
		goto on_error;
	pid = fork();
	if (pid < 0) {
		ksft_print_msg("First fork() failed\n");
		goto on_error;
	}
	if (pid > 0) {
		(void)wait(NULL);
		goto parent_out;
	}
	ksft_set_plan(19);
	if (test_clone3(CLONE_NEWPID, 0, 0, CLONE3_ARGS_NO_TEST))
		goto on_error;
	if (test_clone3(0, 0, 0, CLONE3_ARGS_NO_TEST))
		goto on_error;
	ksft_print_msg("Second unshare\n");
	if (unshare(CLONE_NEWPID))
		goto on_error;
	/*
	 * Before clone3()ing in a new PID NS with
	 * CLONE_NEWPID a fork() is necessary.
	 */
	if (test_clone3(CLONE_NEWPID, 0, -EINVAL, CLONE3_ARGS_NO_TEST))
		goto on_error;
	pid = fork();
	if (pid < 0) {
		ksft_print_msg("Second fork() failed\n");
		goto on_error;
	}
	if (pid > 0) {
		(void)wait(NULL);
		goto parent_out;
	}
	ksft_set_plan(21);
	if (test_clone3(CLONE_NEWPID, 0, 0, CLONE3_ARGS_NO_TEST))
		goto on_error;
	if (test_clone3(0, 0, 0, CLONE3_ARGS_NO_TEST))
		goto on_error;

parent_out:
	ret = 0;
on_error:

	return !ret ? ksft_exit_pass() : ksft_exit_fail();
}
