/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../kselftest.h"

static int parent_pidns_fd = -1;
static pid_t parent_pidns_pid = 0;

static int child_pidns_fd = -1;
static pid_t child_pidns_pid = 0;

static int cousin_pidns_fd = -1;
static pid_t cousin_pidns_pid = 0;

static bool pidns_supported = false;

static inline int sys_pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
					unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static inline int sys_pidctl(unsigned int cmd, pid_t pid, int source,
			     int target, unsigned int flags)
{
	return syscall(__NR_pidctl, cmd, pid, source, target, flags);
}

struct cr_clone_arg {
	char stack[128] __attribute__((aligned(16)));
	char stack_ptr[0];
};

static int child_pidns_creator(void *args)
{
	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	while (1)
		sleep(5);

	exit(0);
}

static int prepare_pid_namespaces(void)
{
	char path[512];
	struct cr_clone_arg ca;
	pid_t pid;

	parent_pidns_fd = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
	if (parent_pidns_fd < 0) {
		ksft_print_msg("failed to open current pid namespace");
		return -1;
	}
	parent_pidns_pid = getpid();

	pid = clone(child_pidns_creator, ca.stack_ptr, CLONE_NEWPID | SIGCHLD,
		    NULL);
	if (pid < 0) {
		ksft_print_msg("failed to clone child-pidns process in new pid namespace");
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);

	child_pidns_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (child_pidns_fd < 0) {
		ksft_print_msg("failed to open pid namespace");
		return -1;
	}
	child_pidns_pid = pid;

	pid = clone(child_pidns_creator, ca.stack_ptr, CLONE_NEWPID | SIGCHLD,
		    NULL);
	if (pid < 0) {
		ksft_print_msg("failed to clone cousin-pidns process in new pid namespace");
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);

	cousin_pidns_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (cousin_pidns_fd < 0) {
		ksft_print_msg("failed to open cousin pid namespace");
		return -1;
	}
	cousin_pidns_pid = pid;

	return 0;
}

static int test_pidcmd_query_pid(void)
{
	const char *test_name = "pidctl PIDCMD_QUERY_PID";
	pid_t pid, self;
	int parent_pidns_fd2;

	self = getpid();

	pid = sys_pidctl(PIDCMD_QUERY_PID, self, -1, -1, 1);
	if (pid >= 0) {
		ksft_print_msg("%s test %d: managed to pass invalid flag\n",
			       test_name, ksft_test_num());
		return -1;
	}

	pid = sys_pidctl(PIDCMD_QUERY_PID, self, -1, -1, 0);
	if (!pid || (pid != self)) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), self, pid);
		return -1;
	}
	ksft_inc_pass_cnt();

	if (!pidns_supported)
		goto out;

	parent_pidns_fd2 = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
	if (parent_pidns_fd2 < 0) {
		ksft_print_msg("%s test %d: Failed to open current pid namespace\n",
			       test_name, ksft_test_num());
		return -1;
	}

	pid = sys_pidctl(PIDCMD_QUERY_PID, self, parent_pidns_fd,
			 parent_pidns_fd2, 0);
	if (!pid || (pid != self)) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), self, pid);
		close(parent_pidns_fd2);
		return -1;
	}
	ksft_inc_pass_cnt();

	pid = sys_pidctl(PIDCMD_QUERY_PID, self, -1, parent_pidns_fd2, 0);
	if (!pid || (pid != self)) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), self, pid);
		close(parent_pidns_fd2);
		return -1;
	}
	ksft_inc_pass_cnt();

	pid = sys_pidctl(PIDCMD_QUERY_PID, self, parent_pidns_fd, -1, 0);
	if (!pid || (pid != self)) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), self, pid);
		close(parent_pidns_fd2);
		return -1;
	}
	ksft_inc_pass_cnt();

	close(parent_pidns_fd2);

	pid = sys_pidctl(PIDCMD_QUERY_PID, self, parent_pidns_fd,
			 child_pidns_fd, 0);
	if (pid >= 0 || ((pid < 0) && (errno != ENOENT))) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), self, pid);
		return -1;
	}
	ksft_inc_pass_cnt();

	pid = sys_pidctl(PIDCMD_QUERY_PID, self, child_pidns_fd,
			 parent_pidns_fd, 0);
	if (pid >= 0 || ((pid < 0) && (errno != ESRCH))) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), self, pid);
		return -1;
	}
	ksft_inc_pass_cnt();

	pid = sys_pidctl(PIDCMD_QUERY_PID, child_pidns_pid, parent_pidns_fd,
			 child_pidns_fd, 0);
	if (pid != 1) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), child_pidns_pid, pid);
		return -1;
	}
	ksft_inc_pass_cnt();

	pid = sys_pidctl(PIDCMD_QUERY_PID, 1, child_pidns_fd, parent_pidns_fd,
			 0);
	if (pid != child_pidns_pid) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), 1, pid);
		return -1;
	}
	ksft_inc_pass_cnt();

	pid = sys_pidctl(PIDCMD_QUERY_PID, 1, child_pidns_fd, cousin_pidns_fd, 0);
	if (pid >= 0 || ((pid < 0) && (errno != ENOENT))) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), 1, pid);
		return -1;
	}
	ksft_inc_pass_cnt();

	pid = sys_pidctl(PIDCMD_QUERY_PID, cousin_pidns_pid, child_pidns_fd,
			 cousin_pidns_fd, 0);
	if (pid >= 0 || ((pid < 0) && (errno != ESRCH))) {
		ksft_print_msg("%s test %d: argument pid %d, translated pid %d\n",
			       test_name, ksft_test_num(), cousin_pidns_pid, pid);
		return -1;
	}
	ksft_inc_pass_cnt();

out:
	ksft_test_result_pass("%s test: passed\n", test_name);
	return 0;
}

static int test_pidcmd_query_pidns(void)
{
	const char *test_name = "pidctl PIDCMD_QUERY_PIDNS";
	int parent_pidns_fd2;
	int query;

	query = sys_pidctl(PIDCMD_QUERY_PIDNS, 0, -1, -1, 1);
	if (query >= 0) {
		ksft_print_msg("%s test %d: managed to pass invalid flag\n",
			       test_name, ksft_test_num());
		return -1;
	}
	ksft_inc_pass_cnt();

	query = sys_pidctl(PIDCMD_QUERY_PIDNS, 1234, -1, -1, 0);
	if (query >= 0)
		ksft_print_msg("%s test %d: managed to pass invalid pid argument\n",
			test_name, ksft_test_num());
	ksft_inc_pass_cnt();

	if (!pidns_supported)
		goto out;

	parent_pidns_fd2 = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
	if (parent_pidns_fd2 < 0) {
		ksft_print_msg("%s test %d: Failed to open second pid namespace file descriptor\n",
			       test_name, ksft_test_num());
		return -1;
	}

	query = sys_pidctl(PIDCMD_QUERY_PIDNS, 0, parent_pidns_fd,
			   parent_pidns_fd2, 0);
	close(parent_pidns_fd2);
	if (query != PIDNS_EQUAL) {
		ksft_print_msg("%s test %d: failed to detect that pid namespaces are identical %d\n",
			       test_name, ksft_test_num(), query);
		return -1;
	}
	ksft_inc_pass_cnt();

	query = sys_pidctl(PIDCMD_QUERY_PIDNS, 0, parent_pidns_fd,
			   child_pidns_fd, 0);
	if (query != PIDNS_SOURCE_IS_ANCESTOR) {
		ksft_print_msg("%s test %d: failed to detect that source pid namespace is ancestor of target pid namespace %d\n",
			       test_name, ksft_test_num(), query);
		return -1;
	}
	ksft_inc_pass_cnt();

	query = sys_pidctl(PIDCMD_QUERY_PIDNS, 0, child_pidns_fd,
			   parent_pidns_fd, 0);
	if (query != PIDNS_TARGET_IS_ANCESTOR) {
		ksft_print_msg("%s test %d: failed to detect that target pid namespace is ancestor of source pid namespace %d\n",
			       test_name, ksft_test_num(), query);
		return -1;
	}
	ksft_inc_pass_cnt();

	query = sys_pidctl(PIDCMD_QUERY_PIDNS, 0, child_pidns_fd,
			   cousin_pidns_fd, 0);
	if (query != PIDNS_UNRELATED) {
		ksft_print_msg("%s test %d: failed to detect that pid namespace are not related %d\n",
			       test_name, ksft_test_num(), query);
		return -1;
	}
	ksft_inc_pass_cnt();

	query = sys_pidctl(PIDCMD_QUERY_PIDNS, 0, child_pidns_fd,
			   cousin_pidns_fd, 0);
	if (query != PIDNS_UNRELATED) {
		ksft_print_msg("%s test %d: failed to detect that pid namespace are not related %d\n",
			       test_name, ksft_test_num(), query);
		return -1;
	}
	ksft_inc_pass_cnt();

out:
	ksft_test_result_pass("%s test: passed\n", test_name);
	return 0;
}

static int test_pidcmd_get_pidfd(void)
{
	const char *test_name = "pidctl PIDCMD_GET_PIDFD";
	pid_t self;
	int pidfd, parent_pidns_fd2;

	self = getpid();

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, self, -1, -1, 0);
	if (pidfd < 0) {
		ksft_print_msg("%s test %d: failed to pass valid flag\n",
			       test_name, ksft_test_num());
		return -1;
	}
	close(pidfd);
	ksft_inc_pass_cnt();

	if (!pidns_supported)
		goto out;

	parent_pidns_fd2 = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
	if (parent_pidns_fd2 < 0) {
		ksft_print_msg("%s test %d: Failed to open current pid namespace\n",
			       test_name, ksft_test_num());
		return -1;
	}

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, self, parent_pidns_fd,
			   parent_pidns_fd2, 0);
	if (pidfd < 0) {
		ksft_print_msg("%s test %d: failed to retrieve pidfd\n",
			       test_name, ksft_test_num());
		close(parent_pidns_fd2);
		return -1;
	}
	close(pidfd);
	ksft_inc_pass_cnt();

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, self, -1, parent_pidns_fd2, 0);
	if (pidfd < 0) {
		ksft_print_msg("%s test %d: failed to retrieve pidfd\n",
			       test_name, ksft_test_num());
		close(parent_pidns_fd2);
		return -1;
	}
	close(pidfd);
	ksft_inc_pass_cnt();

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, self, parent_pidns_fd, -1, 0);
	if (pidfd < 0) {
		ksft_print_msg("%s test %d: failed to retrieve pidfd\n",
			       test_name, ksft_test_num());
		close(parent_pidns_fd2);
		return -1;
	}
	close(pidfd);
	ksft_inc_pass_cnt();

	close(parent_pidns_fd2);

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, self, parent_pidns_fd,
			   child_pidns_fd, 0);
	if (pidfd >= 0 || ((pidfd < 0) && (errno != ENOENT))) {
		ksft_print_msg("%s test %d: succeeded to retrieve pidfd but should've failed %s\n",
			       test_name, ksft_test_num(), strerror(errno));
		return -1;
	}
	ksft_inc_pass_cnt();

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, self, child_pidns_fd,
			   parent_pidns_fd, 0);
	if (pidfd >= 0 || ((pidfd < 0) && (errno != ESRCH))) {
		ksft_print_msg("%s test %d: succeeded to retrieve pidfd but should've failed %s\n",
			       test_name, ksft_test_num(), strerror(errno));
		return -1;
	}
	ksft_inc_pass_cnt();

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, 1, child_pidns_fd, parent_pidns_fd, 0);
	if (pidfd < 0) {
		ksft_print_msg("%s test %d: failed to retrieve pidfd\n",
			       test_name, ksft_test_num());
		return -1;
	}
	close(pidfd);
	ksft_inc_pass_cnt();

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, 1, child_pidns_fd, cousin_pidns_fd, 0);
	if (pidfd >= 0 || ((pidfd < 0) && (errno != ENOENT))) {
		ksft_print_msg("%s test %d: succeeded to retrieve pidfd but should've failed %s\n",
			       test_name, ksft_test_num(), strerror(errno));
		return -1;
	}
	ksft_inc_pass_cnt();

	pidfd = sys_pidctl(PIDCMD_GET_PIDFD, cousin_pidns_pid, child_pidns_fd,
			   cousin_pidns_fd, 0);
	if (pidfd >= 0 || ((pidfd < 0) && (errno != ESRCH))) {
		ksft_print_msg("%s test %d: succeeded to retrieve pidfd but should've failed %s\n",
			       test_name, ksft_test_num(), strerror(errno));
		return -1;
	}
	ksft_inc_pass_cnt();

out:
	ksft_test_result_pass("%s test: passed\n", test_name);
	return 0;
}

static void test_pidctl_pidfd_send_signal(void)
{
	const char *test_name = "pidctl with pidfd_send_signal";
	int child_pidfd, cousin_pidfd, ret;

	child_pidfd = sys_pidctl(PIDCMD_GET_PIDFD, child_pidns_pid, -1, -1, 0);
	if (child_pidfd < 0)
		ksft_print_msg("%s test %d: failed to retrieve pidfd\n",
			       test_name, ksft_test_num());
	ksft_inc_pass_cnt();

	ret = sys_pidfd_send_signal(child_pidfd, SIGKILL, NULL, 0);
	if (ret < 0) {
		kill(child_pidns_pid, SIGKILL);
		ksft_print_msg("%s test %d: failed to send signal via pidfd\n",
			       test_name, ksft_test_num());
	}
	ksft_inc_pass_cnt();

	cousin_pidfd = sys_pidctl(PIDCMD_GET_PIDFD, cousin_pidns_pid, -1, -1, 0);
	if (cousin_pidfd < 0)
		ksft_print_msg("%s test %d: failed to retrieve pidfd\n",
			       test_name, ksft_test_num());
	ksft_inc_pass_cnt();

	ret = sys_pidfd_send_signal(cousin_pidfd, SIGKILL, NULL, 0);
	if (ret < 0) {
		kill(cousin_pidfd, SIGKILL);
		ksft_print_msg("%s test %d: failed to send signal via pidfd\n",
			       test_name, ksft_test_num());
	}
	ksft_inc_pass_cnt();

	ksft_test_result_pass("%s test: passed\n", test_name);
}

int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (ret != pid)
		goto again;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		ksft_exit_fail_msg("Failed to create new process\n");

	if (pid == 0) {
		if (unshare(CLONE_NEWPID) < 0)
			exit(EXIT_FAILURE);

		exit(EXIT_SUCCESS);
	}

	if (!wait_for_pid(pid))
		pidns_supported = true;

	ksft_print_header();

	if (pidns_supported)
		prepare_pid_namespaces();
	else
		ksft_print_msg(
			"kernel does not support pid namespaces: skipping pid namespace parts of testsuite");

	ret = test_pidcmd_query_pid();
	if (ret < 0) {
		ksft_print_msg("PIDCMD_QUERY_PID tests failed");
		goto on_error;
	}

	ret = test_pidcmd_query_pidns();
	if (ret < 0) {
		ksft_print_msg("PIDCMD_QUERY_PIDNS tests failed");
		goto on_error;
	}

	ret = test_pidcmd_get_pidfd();
	if (ret < 0) {
		ksft_print_msg("PIDCMD_GET_PIDFD tests failed");
		goto on_error;
	}

	ret = 0;

on_error:
	if (pidns_supported)
		test_pidctl_pidfd_send_signal();

	if (parent_pidns_fd >= 0)
		close(parent_pidns_fd);

	if (child_pidns_fd >= 0)
		close(child_pidns_fd);

	if (cousin_pidns_fd >= 0)
		close(cousin_pidns_fd);

	return !ret ? ksft_exit_pass() : ksft_exit_fail();
}
