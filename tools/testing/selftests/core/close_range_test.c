// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kernel.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

#include "../kselftest.h"

#ifndef __NR_close_range
#define __NR_close_range -1
#endif

static inline int sys_close_range(unsigned int fd, unsigned int max_fd,
				  unsigned int flags)
{
	return syscall(__NR_close_range, fd, max_fd, flags);
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

int main(int argc, char **argv)
{
	const char *test_name = "close_range";
	int i, ret;
	int open_fds[101];
	int fd_max, fd_mid, fd_min;

	ksft_set_plan(9);

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			if (errno == ENOENT)
				ksft_exit_skip(
					"%s test: skipping test since /dev/null does not exist\n",
					test_name);

			ksft_exit_fail_msg(
				"%s test: %s - failed to open /dev/null\n",
				strerror(errno), test_name);
		}

		open_fds[i] = fd;
	}

	fd_min = open_fds[0];
	fd_max = open_fds[99];

	ret = sys_close_range(fd_min, fd_max, 1);
	if (!ret)
		ksft_exit_fail_msg(
			"%s test: managed to pass invalid flag value\n",
			test_name);
	if (errno == ENOSYS)
		ksft_exit_skip("%s test: close_range() syscall not supported\n", test_name);

	ksft_test_result_pass("do not allow invalid flag values for close_range()\n");

	fd_mid = open_fds[50];
	ret = sys_close_range(fd_min, fd_mid, 0);
	if (ret < 0)
		ksft_exit_fail_msg(
			"%s test: Failed to close range of file descriptors from %d to %d\n",
			test_name, fd_min, fd_mid);
	ksft_test_result_pass("close_range() from %d to %d\n", fd_min, fd_mid);

	for (i = 0; i <= 50; i++) {
		ret = fcntl(open_fds[i], F_GETFL);
		if (ret >= 0)
			ksft_exit_fail_msg(
				"%s test: Failed to close range of file descriptors from %d to %d\n",
				test_name, fd_min, fd_mid);
	}
	ksft_test_result_pass("fcntl() verify closed range from %d to %d\n", fd_min, fd_mid);

	/* create a couple of gaps */
	close(57);
	close(78);
	close(81);
	close(82);
	close(84);
	close(90);

	fd_mid = open_fds[51];
	/* Choose slightly lower limit and leave some fds for a later test */
	fd_max = open_fds[92];
	ret = sys_close_range(fd_mid, fd_max, 0);
	if (ret < 0)
		ksft_exit_fail_msg(
			"%s test: Failed to close range of file descriptors from 51 to 100\n",
			test_name);
	ksft_test_result_pass("close_range() from %d to %d\n", fd_mid, fd_max);

	for (i = 51; i <= 92; i++) {
		ret = fcntl(open_fds[i], F_GETFL);
		if (ret >= 0)
			ksft_exit_fail_msg(
				"%s test: Failed to close range of file descriptors from 51 to 100\n",
				test_name);
	}
	ksft_test_result_pass("fcntl() verify closed range from %d to %d\n", fd_mid, fd_max);

	fd_mid = open_fds[93];
	fd_max = open_fds[99];
	/* test that the kernel caps and still closes all fds */
	ret = sys_close_range(fd_mid, UINT_MAX, 0);
	if (ret < 0)
		ksft_exit_fail_msg(
			"%s test: Failed to close range of file descriptors from 51 to 100\n",
			test_name);
	ksft_test_result_pass("close_range() from %d to %d\n", fd_mid, fd_max);

	for (i = 93; i < 100; i++) {
		ret = fcntl(open_fds[i], F_GETFL);
		if (ret >= 0)
			ksft_exit_fail_msg(
				"%s test: Failed to close range of file descriptors from 51 to 100\n",
				test_name);
	}
	ksft_test_result_pass("fcntl() verify closed range from %d to %d\n", fd_mid, fd_max);

	ret = sys_close_range(open_fds[100], open_fds[100], 0);
	if (ret < 0)
		ksft_exit_fail_msg(
			"%s test: Failed to close single file descriptor\n",
			test_name);
	ksft_test_result_pass("close_range() closed single file descriptor\n");

	ret = fcntl(open_fds[100], F_GETFL);
	if (ret >= 0)
		ksft_exit_fail_msg(
			"%s test: Failed to close single file descriptor\n",
			test_name);
	ksft_test_result_pass("fcntl() verify closed single file descriptor\n");

	return ksft_exit_pass();
}
