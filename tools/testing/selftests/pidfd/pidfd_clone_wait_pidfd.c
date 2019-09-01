/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <err.h>
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

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

#ifndef CLONE_WAIT_PIDFD
#define CLONE_WAIT_PIDFD 0x100000000ULL
#endif

#ifndef __NR_pidfd_open
#define __NR_pidfd_open -1
#endif

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal -1
#endif

#ifndef __NR_clone3
#define __NR_clone3 -1
#endif
#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))

static pid_t sys_clone3(struct clone_args *args)
{
	return syscall(__NR_clone3, args, sizeof(struct clone_args));
}

static int sys_waitid(int which, pid_t pid, siginfo_t *info, int options,
		      struct rusage *ru)
{
	return syscall(__NR_waitid, which, pid, info, options, ru);
}

int main(int argc, char *argv[])
{
	int pidfd = -1, status = 0;
	pid_t parent_tid = -1;
	struct clone_args args = {
		.parent_tid = ptr_to_u64(&parent_tid),
		.pidfd = ptr_to_u64(&pidfd),
		.flags = CLONE_PIDFD | CLONE_PARENT_SETTID | CLONE_WAIT_PIDFD,
		.exit_signal = 0,
	};
	int ret;
	pid_t pid;
	siginfo_t info = {
		.si_signo = 0,
	};

	pid = sys_clone3(&args);
	if (pid < 0)
		err(EXIT_FAILURE, "Failed to create first new process");

	if (pid == 0)
		exit(EXIT_SUCCESS);

	pid = sys_waitid(P_PIDFD, pidfd, &info, WEXITED | __WCLONE, NULL);
	if (pid < 0)
		err(EXIT_FAILURE, "Failed to wait on first new process via P_PIDFD");

	if (!WIFEXITED(info.si_status) || WEXITSTATUS(info.si_status))
		errx(EXIT_FAILURE, "Unexpected exit code for first new process");
	close(pidfd);

	if (info.si_code != CLD_EXITED)
		errx(EXIT_FAILURE, "Unexpected exit code for first new process");

	if (info.si_pid != parent_tid)
		errx(EXIT_FAILURE, "Mismatch between pid and parent_tid for first new process");

	memset(&args, 0, sizeof(args));
	parent_tid = -1;
	args.parent_tid = ptr_to_u64(&parent_tid);
	pidfd = -1;
	args.pidfd = ptr_to_u64(&pidfd);
	args.flags = CLONE_PIDFD | CLONE_PARENT_SETTID | CLONE_WAIT_PIDFD;
	args.exit_signal = 0;
	memset(&info, 0, sizeof(info));

	pid = sys_clone3(&args);
	if (pid < 0)
		err(EXIT_FAILURE, "Failed to create second new process");

	if (pid == 0)
		exit(EXIT_SUCCESS);

	pid = sys_waitid(P_PID, parent_tid, &info, WEXITED | __WCLONE, NULL);
	if (pid > 0)
		err(EXIT_FAILURE, "Managed to wait on second new process via P_PID");

	pid = sys_waitid(P_PGID, parent_tid, &info, WEXITED | __WCLONE, NULL);
	if (pid > 0)
		err(EXIT_FAILURE, "Managed to wait on second new process via P_PGID");

	pid = sys_waitid(P_ALL, parent_tid, &info, WEXITED | __WCLONE, NULL);
	if (pid > 0)
		err(EXIT_FAILURE, "Managed to wait on second new process via P_ALL");

	close(pidfd);

	pid = sys_waitid(P_PID, parent_tid, &info, WEXITED | __WCLONE, NULL);
	if (pid < 0)
		err(EXIT_FAILURE, "Failed to wait on second new process via P_PID after close(pidfd)");

	if (!WIFEXITED(info.si_status) || WEXITSTATUS(info.si_status))
		errx(EXIT_FAILURE, "Unexpected exit code for first new process");

	if (info.si_code != CLD_EXITED)
		errx(EXIT_FAILURE, "Unexpected exit code for second new process");

	if (info.si_pid != parent_tid)
		errx(EXIT_FAILURE, "Mismatch between pid and parent_tid for second new process");

	exit(EXIT_FAILURE);
}
