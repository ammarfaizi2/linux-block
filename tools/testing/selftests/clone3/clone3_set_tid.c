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

static pid_t raw_clone(struct clone_args *args)
{
	return syscall(__NR_clone3, args, sizeof(struct clone_args));
}

static int call_clone3_set_tid(int set_tid, int flags)
{
	struct clone_args args = {0};
	pid_t ppid = -1;
	pid_t pid = -1;
	int status;

	args.flags = flags;
	args.exit_signal = SIGCHLD;
	args.set_tid = set_tid;

	pid = raw_clone(&args);
	if (pid < 0) {
		ksft_print_msg("%s - Failed to create new process\n",
				strerror(errno));
		return -errno;
	}

	if (pid == 0) {
		ksft_print_msg("I am the child, my PID is %d (expected %d)\n",
				getpid(), set_tid);
		if (set_tid != getpid())
			_exit(EXIT_FAILURE);
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

static int test_clone3_set_tid(int set_tid, int flags, int expected)
{
	int ret;

	ksft_print_msg(
		"[%d] Trying clone3() with CLONE_SET_TID to %d and 0x%x\n",
		getpid(), set_tid, flags);
	ret = call_clone3_set_tid(set_tid, flags);
	ksft_print_msg(
		"[%d] clone3() with CLONE_SET_TID %d says :%d - expected %d\n",
		getpid(), set_tid, ret, expected);
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
	FILE *f;
	int pid_max = 0;
	pid_t pid;
	pid_t ns_pid;
	int ret = -1;

	ksft_print_header();
	ksft_set_plan(13);

	f = fopen("/proc/sys/kernel/pid_max", "r");
	if (f == NULL)
		ksft_exit_fail_msg(
			"%s - Could not open /proc/sys/kernel/pid_max\n",
			strerror(errno));
	fscanf(f, "%d", &pid_max);
	fclose(f);
	ksft_print_msg("/proc/sys/kernel/pid_max %d\n", pid_max);

	/* First try with an invalid PID */
	if (test_clone3_set_tid(-1, 0, -EINVAL))
		goto on_error;
	if (test_clone3_set_tid(-1, CLONE_NEWPID, -EINVAL))
		goto on_error;
	/* Then with PID 1 */
	if (test_clone3_set_tid(1, 0, -EEXIST))
		goto on_error;
	/* PID 1 should not fail in a PID namespace */
	if (test_clone3_set_tid(1, CLONE_NEWPID, 0))
		goto on_error;
	/* pid_max should fail everywhere */
	if (test_clone3_set_tid(pid_max, 0, -EINVAL))
		goto on_error;
	if (test_clone3_set_tid(pid_max, CLONE_NEWPID, -EINVAL))
		goto on_error;
	/* Find the current active PID */
	pid = fork();
	if (pid == 0) {
		ksft_print_msg("Child has PID %d\n", getpid());
		sleep(1);
		_exit(EXIT_SUCCESS);
	}
	/* Try to create a process with that PID should fail */
	if (test_clone3_set_tid(pid, 0, -EEXIST))
		goto on_error;
	(void)wait(NULL);
	/* After the child has finished, try again with the same PID */
	if (test_clone3_set_tid(pid, 0, 0))
		goto on_error;
	/* This should fail as there is no PID 1 in that namespace */
	if (test_clone3_set_tid(pid, CLONE_NEWPID, -EINVAL))
		goto on_error;
	unshare(CLONE_NEWPID);
	if (test_clone3_set_tid(10, 0, -EINVAL))
		goto on_error;
	/* Let's create a PID 1 */
	ns_pid = fork();
	if (ns_pid == 0) {
		ksft_print_msg("Child in PID namespace has PID %d\n", getpid());
		sleep(1);
		_exit(EXIT_SUCCESS);
	}
	/*
	 * Now, after the unshare() it should be possible to create a process
	 * with another ID than 1 in the PID namespace.
	 */
	if (test_clone3_set_tid(2, 0, 0))
		goto on_error;
	/* Use a different PID in this namespace. */
	if (test_clone3_set_tid(2222, 0, 0))
		goto on_error;
	if (test_clone3_set_tid(1, 0, -EEXIST))
		goto on_error;
	(void)wait(NULL);

	ret = 0;
on_error:

	return !ret ? ksft_exit_pass() : ksft_exit_fail();
}
