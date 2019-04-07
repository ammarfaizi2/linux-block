// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

static int raw_clone_pidfd(void)
{
	unsigned long flags = CLONE_PIDFD | SIGCHLD;

#if defined(__s390x__) || defined(__s390__) || defined(__CRIS__)
	/*
	 * On s390/s390x and cris the order of the first and second arguments
	 * of the system call is reversed.
	 */
	return (int)syscall(__NR_clone, NULL, flags);
#elif defined(__sparc__) && defined(__arch64__)
	{
		/*
		 * sparc64 always returns the other process id in %o0, and a
		 * boolean flag whether this is the child or the parent in %o1.
		 * Inline assembly is needed to get the flag returned in %o1.
		 */
		int child_pid, in_child;

		asm volatile("mov %2, %%g1\n\t"
			     "mov %3, %%o0\n\t"
			     "mov 0 , %%o1\n\t"
			     "t 0x6d\n\t"
			     "mov %%o1, %0\n\t"
			     "mov %%o0, %1"
			     : "=r"(in_child), "=r"(child_pid)
			     : "i"(__NR_clone), "r"(flags)
			     : "%o1", "%o0", "%g1");

		if (in_child)
			return 0;
		else
			return child_pid;
	}
#elif defined(__ia64__)
	/* On ia64 stack and stack size are passed as separate arguments. */
	return (int)syscall(__NR_clone, flags, NULL, 0UL);
#else
	return (int)syscall(__NR_clone, flags, NULL);
#endif
}

static inline int sys_pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
					unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static int pidfd_metadata_fd(int pidfd)
{
	int procfd, ret;
	char path[100];
	FILE *f;
	size_t n = 0;
	char *line = NULL;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);

	f = fopen(path, "re");
	if (!f)
		return -1;

	ret = 0;
	while (getline(&line, &n, f) != -1) {
		char *numstr;
		size_t len;

		if (strncmp(line, "Pid:\t", 5))
			continue;

		numstr = line + 5;
		len = strlen(numstr);
		if (len > 0 && numstr[len - 1] == '\n')
			numstr[len - 1] = '\0';
		ret = snprintf(path, sizeof(path), "/proc/%s", numstr);
		break;
	}
	free(line);
	fclose(f);

	if (!ret) {
		errno = ENOENT;
		warn("Failed to parse pid from fdinfo\n");
		return -1;
	}

	procfd = open(path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (procfd < 0) {
		warn("Failed to open %s\n", path);
		return -1;
	}

	/*
	 * Verify that the pid has not been recycled and our /proc/<pid> handle
	 * is still valid.
	 */
	ret = sys_pidfd_send_signal(pidfd, 0, NULL, 0);
	if (ret < 0) {
		switch (errno) {
		case EPERM:
			/* Process exists, just not allowed to signal it. */
			break;
		default:
			warn("Failed to signal process\n");
			close(procfd);
			procfd = -1;
		}
	}

	return procfd;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char buf[4096] = { 0 };
	int pidfd, procfd, statusfd;
	ssize_t bytes;

	pidfd = raw_clone_pidfd();
	if (pidfd < 0)
		exit(ret);

	if (pidfd == 0) {
		printf("%d\n", getpid());
		exit(EXIT_SUCCESS);
	}

	procfd = pidfd_metadata_fd(pidfd);
	close(pidfd);
	if (procfd < 0)
		goto out;

	statusfd = openat(procfd, "status", O_RDONLY | O_CLOEXEC);
	close(procfd);
	if (statusfd < 0)
		goto out;

	bytes = read(statusfd, buf, sizeof(buf));
	if (bytes > 0)
		bytes = write(STDOUT_FILENO, buf, bytes);
	close(statusfd);
	ret = EXIT_SUCCESS;

out:
	(void)wait(NULL);

	exit(ret);
}
