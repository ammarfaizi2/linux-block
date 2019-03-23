/* SPDX-License-Identifier: GPL-2.0 */

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

#include "../kselftest.h"

static inline int sys_pidfd_open(pid_t pid, int procfd, int pidfd,
				 unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, procfd, pidfd, flags);
}

static int safe_int(const char *numstr, int *converted)
{
	char *err = NULL;
	signed long int sli;

	errno = 0;
	sli = strtol(numstr, &err, 0);
	if (errno == ERANGE && (sli == LONG_MAX || sli == LONG_MIN))
		return -ERANGE;

	if (errno != 0 && sli == 0)
		return -EINVAL;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	if (sli > INT_MAX || sli < INT_MIN)
		return -ERANGE;

	*converted = (int)sli;
	return 0;
}

static int char_left_gc(const char *buffer, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buffer[i] == ' ' ||
		    buffer[i] == '\t')
			continue;

		return i;
	}

	return 0;
}

static int char_right_gc(const char *buffer, size_t len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		if (buffer[i] == ' '  ||
		    buffer[i] == '\t' ||
		    buffer[i] == '\n' ||
		    buffer[i] == '\0')
			continue;

		return i + 1;
	}

	return 0;
}

static char *trim_whitespace_in_place(char *buffer)
{
	buffer += char_left_gc(buffer, strlen(buffer));
	buffer[char_right_gc(buffer, strlen(buffer))] = '\0';
	return buffer;
}

static pid_t get_pid_from_status_file(int *fd)
{
	int ret;
	FILE *f;
	size_t n = 0;
	pid_t result = -1;
	char *line = NULL;

	/* fd now belongs to FILE and will be closed by fclose() */
	f = fdopen(*fd, "r");
	if (!f)
		return -1;

	while (getline(&line, &n, f) != -1) {
		char *numstr;

		if (strncmp(line, "Pid:", 4))
			continue;

		numstr = trim_whitespace_in_place(line + 4);
		ret = safe_int(numstr, &result);
		if (ret < 0)
			goto out;

		break;
	}

out:
	free(line);
	fclose(f);
	*fd = -1;
	return result;
}

int main(int argc, char **argv)
{
	int ret = 1;
	int pidfd = -1, pidfd2 = -1, procfd = -1, procpidfd = -1, statusfd = -1;
	pid_t pid;

	pidfd = sys_pidfd_open(getpid(), -1, -1, 0);
	if (pidfd < 0) {
		ksft_print_msg("%s - failed to open pidfd\n", strerror(errno));
		goto on_error;
	}

	procfd = open("/proc", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (procfd < 0) {
		ksft_print_msg("%s - failed to open /proc\n", strerror(errno));
		goto on_error;
	}

	procpidfd = sys_pidfd_open(-1, procfd, pidfd, PIDFD_TO_PROCFD);
	if (procpidfd < 0) {
		ksft_print_msg(
			"%s - failed to retrieve /proc/<pid> from pidfd\n",
			strerror(errno));
		goto on_error;
	}

	pidfd2 = sys_pidfd_open(-1, procpidfd, -1, PROCFD_TO_PIDFD);
	if (pidfd2 < 0) {
		ksft_print_msg(
			"%s - failed to retrieve  pidfd from procpidfd\n",
			strerror(errno));
		goto on_error;
	}

	statusfd = openat(procpidfd, "status", O_CLOEXEC | O_RDONLY);
	if (statusfd < 0) {
		ksft_print_msg("%s - failed to open /proc/<pid>/status\n",
			       strerror(errno));
		goto on_error;
	}

	pid = get_pid_from_status_file(&statusfd);
	if (pid < 0) {
		ksft_print_msg(
			"%s - failed to retrieve pid from /proc/<pid>/status\n",
			strerror(errno));
		goto on_error;
	}

	if (pid != getpid()) {
		ksft_print_msg(
			"%s - actual pid %d does not equal retrieved pid from /proc/<pid>/status\n",
			strerror(errno), pid, getpid());
		goto on_error;
	}

	ret = 0;

on_error:
	if (pidfd >= 0)
		close(pidfd);

	if (pidfd2 >= 0)
		close(pidfd2);

	if (procfd >= 0)
		close(procfd);

	if (procpidfd >= 0)
		close(procpidfd);

	if (statusfd >= 0)
		close(statusfd);

	return !ret ? ksft_exit_pass() : ksft_exit_fail();
}
