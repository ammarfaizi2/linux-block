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

#include "pidfd.h"
#include "../kselftest.h"

static inline int sys_pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
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

static pid_t get_pid_from_status_file(int *fd, const char *key, size_t keylen)
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

		if (strncmp(line, key, keylen))
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

static int set_ns_last_pid(void)
{
	int fd;
	ssize_t bytes;

	fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		ksft_print_msg("failed to open \"/proc/sys/kernel/ns_last_pid\"n");
		return -1;
	}

	bytes = write(fd, "999", sizeof("999") - 1);
	close(fd);
	if (bytes < 0 || (size_t)bytes != (sizeof("999") - 1))
		return -1;

	return 0;
}

static int test_pidfd_to_procfd_recycled_pid_fail(void)
{
	const char *test_name = "pidfd_open pidfd to procfd conversion on pid recycling";
	int ret;
	pid_t pid1;

	ret = unshare(CLONE_NEWPID);
	if (ret < 0)
		ksft_exit_fail_msg("%s test: Failed to unshare pid namespace\n",
				   test_name);

	ret = unshare(CLONE_NEWNS);
	if (ret < 0)
		ksft_exit_fail_msg(
			"%s test: Failed to unshare mount namespace\n",
			test_name);

	ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0);
	if (ret < 0)
		ksft_exit_fail_msg("%s test: Failed to remount / private\n",
				   test_name);

	/* pid 1 in new pid namespace */
	pid1 = fork();
	if (pid1 < 0)
		ksft_exit_fail_msg("%s test: Failed to create new process\n",
				   test_name);

	/*
	 * This is lazy with file descriptor closing in the child process but
	 * it doesn't matter since we are very short-lived anyway and the
	 * cleanup would just be more complexity in this test.
	 */
	if (pid1 == 0) {
		int pidfd, procpidfd, procfd, ret;
		pid_t pid2;


		(void)umount2("/proc", MNT_DETACH);
		ret = mount("proc", "/proc", "proc", 0, NULL);
		if (ret < 0) {
			ksft_print_msg("failed to mount a fresh /proc instance\n");
			_exit(PIDFD_ERROR);
		}

		/* get pidfd for pid 1000 */
		if (set_ns_last_pid() < 0) {
			ksft_print_msg("failed to set ns_last_pid\n");
			_exit(PIDFD_ERROR);
		}

		pid2 = fork();
		if (pid2 < 0) {
			ksft_print_msg("failed to create new process\n");
			_exit(PIDFD_ERROR);
		}

		if (pid2 == 0)
			_exit(PIDFD_PASS);

		if (pid2 == PID_RECYCLE) {
			pidfd = sys_pidfd_open(pid2, 0);
		} else {
			ksft_print_msg("failed to create process with pid %d\n",
				       PID_RECYCLE);
			_exit(PIDFD_ERROR);
		}

		if (wait_for_pid(pid2))
			_exit(PIDFD_ERROR);

		if (pidfd < 0)
			_exit(PIDFD_ERROR);

		/* recycle pid 1000 */
		if (set_ns_last_pid() < 0) {
			ksft_print_msg("failed to set ns_last_pid\n");
			_exit(PIDFD_ERROR);
		}

		pid2 = fork();
		if (pid2 < 0) {
			ksft_print_msg("failed to create new process\n");
			_exit(PIDFD_ERROR);
		}

		if (pid2 == 0)
			_exit(PIDFD_PASS);

		if (pid2 != PID_RECYCLE) {
			ksft_print_msg("failed to recycle pid %d\n",
				       PID_RECYCLE);
			_exit(PIDFD_ERROR);
		}

		/*
		 * Now PID_RECYCLE is in zombie state since we have not waited
		 * on it yet, but it might have already exited. This ensures
		 * that the /proc/<pid> directory stays around.
		 */
		procfd = open("/proc", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
		if (procfd < 0) {
			ksft_print_msg("%s - failed to open /proc\n",
				       strerror(errno));
			_exit(PIDFD_ERROR);
		}

		procpidfd = ioctl(pidfd, PIDFD_GET_PROCFD, procfd);
		if (procpidfd >= 0) {
			ksft_print_msg(
				"managed to get access to /proc/<pid> of recycled pid\n");
			_exit(PIDFD_ERROR);
		}

		if (wait_for_pid(pid2))
			_exit(PIDFD_ERROR);

		_exit(PIDFD_PASS);
	}

	if (wait_for_pid(pid1) != 0)
		return -1;

	ksft_test_result_pass("%s test: passed\n", test_name);
	ksft_inc_pass_cnt();
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;
	int pidfd = -1, procfd = -1, procpidfd = -1, statusfd = -1;
	pid_t pid;

	pidfd = sys_pidfd_open(-1, 0);
	if (pidfd >= 0) {
		ksft_print_msg(
			"%s - succeeded to open pidfd for invalid pid -1\n",
			strerror(errno));
		goto on_error;
	}
	ksft_test_result_pass("do not allow invalid pid test: passed\n");
	ksft_inc_pass_cnt();

	pidfd = sys_pidfd_open(getpid(), 1);
	if (pidfd >= 0) {
		ksft_print_msg(
			"%s - succeeded to open pidfd with invalid flag value specified\n",
			strerror(errno));
		goto on_error;
	}
	ksft_test_result_pass("do not allow invalid flag test: passed\n");
	ksft_inc_pass_cnt();

	pidfd = sys_pidfd_open(getpid(), 0);
	if (pidfd < 0) {
		ksft_print_msg("%s - failed to open pidfd\n", strerror(errno));
		goto on_error;
	}
	ksft_test_result_pass("open a new pidfd test: passed\n");
	ksft_inc_pass_cnt();

	procfd = open("/proc", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (procfd < 0) {
		ksft_print_msg("%s - failed to open /proc\n", strerror(errno));
		goto on_error;
	}

	procpidfd = ioctl(pidfd, PIDFD_GET_PROCFD, procfd);
	if (procpidfd < 0) {
		ksft_print_msg(
			"%s - failed to retrieve /proc/<pid> from pidfd\n",
			strerror(errno));
		goto on_error;
	}

	statusfd = openat(procpidfd, "status", O_CLOEXEC | O_RDONLY);
	if (statusfd < 0) {
		ksft_print_msg("%s - failed to open /proc/<pid>/status\n",
			       strerror(errno));
		goto on_error;
	}

	pid = get_pid_from_status_file(&statusfd, "Pid:", sizeof("Pid:") - 1);
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
	ksft_test_result_pass("convert pidfd to /proc/<pid> fd test: passed\n");
	ksft_inc_pass_cnt();

	ret = test_pidfd_to_procfd_recycled_pid_fail();

on_error:
	if (pidfd >= 0)
		close(pidfd);

	if (procfd >= 0)
		close(procfd);

	if (procpidfd >= 0)
		close(procpidfd);

	if (statusfd >= 0)
		close(statusfd);

	return !ret ? ksft_exit_pass() : ksft_exit_fail();
}
