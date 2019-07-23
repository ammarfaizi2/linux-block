/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pidfd.h"
#include "../kselftest.h"

#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))

static pid_t sys_clone3(struct clone_args *args)
{
	return syscall(__NR_clone3, args, sizeof(struct clone_args));
}

static pid_t sys_pidfd_wait(int pidfd, int *wstatus, siginfo_t *info,
			    struct rusage *ru, unsigned int states,
			    unsigned int flags)
{
	return syscall(__NR_pidfd_wait, pidfd, wstatus, info, ru, states, flags);
}

static int test_pidfd_wait_syscall_support(void)
{
	int ret;
	const char *test_name = "pidfd_wait check for support";

	ret = sys_pidfd_wait(-EBADF, NULL, NULL, NULL, WEXITED, 0);
	if (ret < 0 && errno == ENOSYS)
		ksft_exit_skip("%s test: pidfd_wait() syscall not supported\n",
			       test_name);

	ksft_test_result_pass("%s test: Passed\n", test_name);
	return 0;
}

static int test_pidfd_wait_simple(void)
{
	const char *test_name = "pidfd_wait simple";
	int pidfd = -1, status = 0;
	pid_t parent_tid = -1;
	struct clone_args args = {
		.parent_tid = ptr_to_u64(&parent_tid),
		.pidfd = ptr_to_u64(&pidfd),
		.flags = CLONE_PIDFD | CLONE_PARENT_SETTID,
		.exit_signal = SIGCHLD,
	};
	pid_t pid;

	pid = sys_clone3(&args);
	if (pid < 0)
		ksft_exit_fail_msg("%s test: failed to create new process %s",
				   test_name, strerror(errno));

	if (pid == 0)
		exit(EXIT_SUCCESS);

	pid = sys_pidfd_wait(pidfd, NULL, NULL, NULL, -1, 0);
	if (pid > 0)
		ksft_exit_fail_msg(
			"%s test: succeeded to wait on process with invalid flags passed",
			test_name);

	pid = sys_pidfd_wait(pidfd, NULL, NULL, NULL, 0, -1);
	if (pid > 0)
		ksft_exit_fail_msg(
			"%s test: succeeded to wait on process with invalid flags passed",
			test_name);

	pid = sys_pidfd_wait(pidfd, NULL, NULL, NULL, 0, 0);
	if (pid > 0)
		ksft_exit_fail_msg(
			"%s test: succeeded to wait on process with invalid flags passed",
			test_name);

	pid = sys_pidfd_wait(pidfd, NULL, NULL, NULL, WEXITED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));
	close(pidfd);

	pidfd = -1;
	parent_tid = -1;
	pid = sys_clone3(&args);
	if (pid < 0)
		ksft_exit_fail_msg("%s test: failed to create new process %s",
				   test_name, strerror(errno));

	if (pid == 0)
		exit(EXIT_SUCCESS);

	pid = sys_pidfd_wait(pidfd, &status, NULL, NULL, WEXITED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	if (!WIFEXITED(status) || WEXITSTATUS(status))
		ksft_exit_fail_msg(
			"%s test: unexpected status received after waiting on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));
	close(pidfd);

	pidfd = -1;
	parent_tid = -1;
	pid = sys_clone3(&args);
	if (pid < 0)
		ksft_exit_fail_msg("%s test: failed to create new process %s",
				   test_name, strerror(errno));

	if (pid == 0)
		exit(EXIT_FAILURE);

	pid = sys_pidfd_wait(pidfd, &status, NULL, NULL, WEXITED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	if (!WIFEXITED(status) || !WEXITSTATUS(status))
		ksft_exit_fail_msg(
			"%s test: unexpected status received after waiting on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));
	close(pidfd);

	ksft_test_result_pass("%s test: Passed\n", test_name);
	return 0;
}

static int test_pidfd_wait_rusage(void)
{
	const char *test_name = "pidfd_wait rusage";
	int pidfd = -1, status = 0;
	pid_t parent_tid = -1;
	struct clone_args args = {
		.parent_tid = ptr_to_u64(&parent_tid),
		.pidfd = ptr_to_u64(&pidfd),
		.flags = CLONE_PIDFD | CLONE_PARENT_SETTID,
		.exit_signal = SIGCHLD,
	};
	pid_t pid;
	struct rusage rusage = { 0 };

	pid = sys_clone3(&args);
	if (pid < 0)
		ksft_exit_fail_msg("%s test: failed to create new process %s",
				   test_name, strerror(errno));

	if (pid == 0)
		exit(EXIT_SUCCESS);

	pid = sys_pidfd_wait(pidfd, &status, NULL, &rusage, WEXITED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	if (!WIFEXITED(status) || WEXITSTATUS(status))
		ksft_exit_fail_msg(
			"%s test: unexpected status received after waiting on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));
	close(pidfd);

	ksft_test_result_pass("%s test: Passed\n", test_name);
	return 0;
}

static int test_pidfd_wait_siginfo(void)
{
	const char *test_name = "pidfd_wait siginfo";
	int pidfd = -1, status = 0;
	pid_t parent_tid = -1;
	struct clone_args args = {
		.parent_tid = ptr_to_u64(&parent_tid),
		.pidfd = ptr_to_u64(&pidfd),
		.flags = CLONE_PIDFD | CLONE_PARENT_SETTID,
		.exit_signal = SIGCHLD,
	};
	pid_t pid;
	siginfo_t info = {
		.si_signo = 0,
	};

	pid = sys_clone3(&args);
	if (pid < 0)
		ksft_exit_fail_msg("%s test: failed to create new process %s",
				   test_name, strerror(errno));

	if (pid == 0)
		exit(EXIT_SUCCESS);

	pid = sys_pidfd_wait(pidfd, &status, &info, NULL, WEXITED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	if (!WIFEXITED(status) || WEXITSTATUS(status))
		ksft_exit_fail_msg(
			"%s test: unexpected status received after waiting on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));
	close(pidfd);

	if (info.si_signo != SIGCHLD)
		ksft_exit_fail_msg(
			"%s test: unexpected si_signo value %d received after waiting on process with pid %d and pidfd %d: %s",
			test_name, info.si_signo, parent_tid, pidfd,
			strerror(errno));

	if (info.si_code != CLD_EXITED)
		ksft_exit_fail_msg(
			"%s test: unexpected si_code value %d received after waiting on process with pid %d and pidfd %d: %s",
			test_name, info.si_code, parent_tid, pidfd,
			strerror(errno));

	ksft_test_result_pass("%s test: Passed\n", test_name);
	return 0;
}

static int test_pidfd_wait_states(void)
{
	const char *test_name = "pidfd_wait states";
	int pidfd = -1, status = 0;
	pid_t parent_tid = -1;
	struct clone_args args = {
		.parent_tid = ptr_to_u64(&parent_tid),
		.pidfd = ptr_to_u64(&pidfd),
		.flags = CLONE_PIDFD | CLONE_PARENT_SETTID,
		.exit_signal = SIGCHLD,
	};
	int ret;
	pid_t pid;
	siginfo_t info = {
		.si_signo = 0,
	};

	pid = sys_clone3(&args);
	if (pid < 0)
		ksft_exit_fail_msg("%s test: failed to create new process %s",
				   test_name, strerror(errno));

	if (pid == 0) {
		kill(getpid(), SIGSTOP);
		kill(getpid(), SIGSTOP);
		exit(EXIT_SUCCESS);
	}

	pid = sys_pidfd_wait(pidfd, &status, &info, NULL, WSTOPPED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	ret = sys_pidfd_send_signal(pidfd, SIGCONT, NULL, 0);
	if (ret < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	pid = sys_pidfd_wait(pidfd, &status, &info, NULL, WCONTINUED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	pid = sys_pidfd_wait(pidfd, &status, &info, NULL, WUNTRACED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	ret = sys_pidfd_send_signal(pidfd, SIGKILL, NULL, 0);
	if (ret < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	pid = sys_pidfd_wait(pidfd, &status, &info, NULL, WEXITED, 0);
	if (pid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	close(pidfd);

	ksft_test_result_pass("%s test: Passed\n", test_name);
	return 0;
}

static int test_clone_wait_pid(void)
{
	const char *test_name = "CLONE_WAIT_PID";
	int pidfd = -1, status = 0;
	pid_t parent_tid = -1;
	struct clone_args args = {
		.parent_tid = ptr_to_u64(&parent_tid),
		.pidfd = ptr_to_u64(&pidfd),
		.flags = CLONE_PARENT_SETTID | CLONE_WAIT_PID,
		.exit_signal = SIGCHLD,
	};
	int ret;
	pid_t pid, rpid;

	pid = sys_clone3(&args);
	if (pid > 0)
		ksft_exit_fail_msg(
			"%s test: managed to create new process with CLONE_WAIT_PID but without CLONE_PIDFD",
			test_name);

	args.flags |= CLONE_PIDFD;
	pid = sys_clone3(&args);
	if (pid < 0)
		ksft_exit_fail_msg("%s test: failed to create new process %s",
				   test_name, strerror(errno));

	if (pid == 0)
		exit(EXIT_SUCCESS);

	ret = syscall(__NR_waitid, P_ALL, -1, NULL, WEXITED, NULL);
	if (ret == 0)
		ksft_exit_fail_msg(
			"%s test: managed to wait on process created with CLONE_PIDFD | CLONE_WAIT_PID with pid %d and pidfd %d through waitid(P_ALL) request",
			test_name, parent_tid, pidfd);

	ret = syscall(__NR_waitid, P_PGID, getpgid(0), NULL, WEXITED, NULL);
	if (ret == 0)
		ksft_exit_fail_msg(
			"%s test: managed to wait on process created with CLONE_PIDFD | CLONE_WAIT_PID with pid %d and pidfd %d through waitid(P_PGID) request",
			test_name, parent_tid, pidfd);

	rpid = syscall(__NR_wait4, -1, NULL, 0, NULL);
	if (rpid > 0)
		ksft_exit_fail_msg(
			"%s test: managed to wait on process created with CLONE_PIDFD | CLONE_WAIT_PID with pid %d and pidfd %d through wait4(-1) request",
			test_name, parent_tid, pidfd);

	rpid = syscall(__NR_wait4, 0, NULL, 0, NULL);
	if (rpid > 0)
		ksft_exit_fail_msg(
			"%s test: managed to wait on process created with CLONE_PIDFD | CLONE_WAIT_PID with pid %d and pidfd %d through wait4(0) request",
			test_name, parent_tid, pidfd);

	ret = syscall(__NR_waitid, P_PID, pid, NULL, WEXITED | WNOWAIT | WNOHANG, NULL);
	if (ret < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process created with CLONE_PIDFD | CLONE_WAIT_PID with pid %d and pidfd %d through waitid(P_PID) request: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	rpid = sys_pidfd_wait(pidfd, NULL, NULL, NULL, WEXITED, WNOWAIT | WNOHANG);
	if (rpid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));

	rpid = syscall(__NR_wait4, pid, &status, 0, NULL);
	if (rpid < 0)
		ksft_exit_fail_msg(
			"%s test: failed to wait on process created with CLONE_PIDFD | CLONE_WAIT_PID with pid %d and pidfd %d through wait4(%d) request: %s",
			test_name, parent_tid, pidfd, parent_tid, strerror(errno));

	if (!WIFEXITED(status) || WEXITSTATUS(status))
		ksft_exit_fail_msg(
			"%s test: unexpected status received after waiting on process with pid %d and pidfd %d: %s",
			test_name, parent_tid, pidfd, strerror(errno));
	close(pidfd);

	ksft_test_result_pass("%s test: Passed\n", test_name);
	return 0;
}

int main(int argc, char **argv)
{
	ksft_print_header();
	ksft_set_plan(6);

	test_pidfd_wait_syscall_support();
	test_pidfd_wait_simple();
	test_pidfd_wait_rusage();
	test_pidfd_wait_siginfo();
	test_pidfd_wait_states();
	test_clone_wait_pid();

	return ksft_exit_pass();
}
