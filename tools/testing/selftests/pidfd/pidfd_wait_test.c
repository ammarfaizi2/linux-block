// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
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

#include "pidfd.h"
#include "../kselftest.h"

static int wait_process(int pidfd)
{
	int status, ret;

again:
	ret = waitpid(pidfd, &status, WPIDFD);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (!WIFEXITED(status))
		return -1;

	return WEXITSTATUS(status);
}

static int child_succeed(void *args)
{
	return 0;
}

static int child_fail(void *args)
{
	return KSFT_XFAIL;
}

int main(int argc, char **argv)
{
	pid_t pid;
	int pidfd = 0;

	pid = pidfd_clone(CLONE_PIDFD, &pidfd, child_succeed);
	if (pid < 0) {
		ksft_print_msg("%s - failed to create pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pidfd < 0) {
		ksft_print_msg("%s - failed to create pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (wait_process(pidfd)) {
		ksft_print_msg("%s - failed to wait for process through pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	pidfd = 0;
	pid = pidfd_clone(CLONE_PIDFD, &pidfd, child_fail);
	if (pid < 0) {
		ksft_print_msg("%s - failed to create pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pidfd < 0) {
		ksft_print_msg("%s - failed to create pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (wait_process(pidfd) != KSFT_XFAIL) {
		ksft_print_msg("%s - failed to wait for process through pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	pidfd = 0;
	pid = pidfd_clone(CLONE_PIDFD, &pidfd, child_succeed);
	if (pid < 0) {
		ksft_print_msg("%s - failed to create pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pidfd < 0) {
		ksft_print_msg("%s - failed to create pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (wait_process(pidfd)) {
		ksft_print_msg("%s - failed to wait for process through pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!wait_process(pidfd)) {
		ksft_print_msg("%s - failed to wait for process through pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	close(pidfd);
	if (!wait_process(pidfd)) {
		ksft_print_msg("%s - failed to wait for process through pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	pidfd = open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (pidfd < 0) {
		ksft_print_msg("%s - failed to open /proc/self\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!wait_process(pidfd)) {
		ksft_print_msg("%s - succeeded to wait for process through invalid pidfd\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
