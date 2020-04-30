// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/kcmp.h>

#include "pidfd.h"
#include "../clone3/clone3_selftests.h"
#include "../kselftest.h"
#include "../kselftest_harness.h"

enum {
	PIDFD_NS_USER,
	PIDFD_NS_MNT,
	PIDFD_NS_PID,
	PIDFD_NS_UTS,
	PIDFD_NS_IPC,
	PIDFD_NS_NET,
	PIDFD_NS_CGROUP,
	PIDFD_NS_MAX
};

const struct ns_info {
	const char *proc_name;
	int clone_flag;
	const char *flag_name;
} ns_info[] = {
	[PIDFD_NS_USER]    = { "user",   CLONE_NEWUSER,   "CLONE_NEWUSER",   },
	[PIDFD_NS_MNT]    =  { "mnt",    CLONE_NEWNS,     "CLONE_NEWNS",     },
	[PIDFD_NS_PID]    =  { "pid",    CLONE_NEWPID,    "CLONE_NEWPID",    },
	[PIDFD_NS_UTS]    =  { "uts",    CLONE_NEWUTS,    "CLONE_NEWUTS",    },
	[PIDFD_NS_IPC]    =  { "ipc",    CLONE_NEWIPC,    "CLONE_NEWIPC",    },
	[PIDFD_NS_NET]    =  { "net",    CLONE_NEWNET,    "CLONE_NEWNET",    },
	[PIDFD_NS_CGROUP] =  { "cgroup", CLONE_NEWCGROUP, "CLONE_NEWCGROUP", }
};

FIXTURE(current_nsset)
{
	int ns_fds[PIDFD_NS_MAX];
	int pidfd;
	pid_t pid;
	pid_t child_pid;
	int child_pidfd;
};

static int sys_waitid(int which, pid_t pid, int options)
{
	return syscall(__NR_waitid, which, pid, NULL, options, NULL);
}

pid_t create_child(int *pidfd)
{
	pid_t pid;

	struct clone_args args = {
		.flags		= CLONE_NEWUSER | CLONE_NEWNET | CLONE_PIDFD,
		.exit_signal	= SIGCHLD,
		.pidfd		= ptr_to_u64(pidfd),
	};

	return sys_clone3(&args, sizeof(struct clone_args));
}

FIXTURE_SETUP(current_nsset)
{
	int i;
	int proc_fd;

	proc_fd = open("/proc/self/ns", O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(proc_fd, 0) {
		TH_LOG("%m - Failed to open /proc/self/ns");
	}

	self->pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		self->ns_fds[i] = openat(proc_fd, info->proc_name, O_RDONLY | O_CLOEXEC);
		if (self->ns_fds[i] < 0) {
			EXPECT_EQ(errno, ENOENT) {
				TH_LOG("%m - Failed to open %s namespace for process %d",
				       info->proc_name, self->pid);
			}
		}
	}

	self->pidfd = sys_pidfd_open(self->pid, 0);
	ASSERT_GE(self->pidfd, 0) {
		TH_LOG("%m - Failed to open pidfd for process %d", self->pid);
	}

	self->child_pid = create_child(&self->child_pidfd);
	ASSERT_GE(self->child_pid, 0);

	if (self->child_pid == 0)
		_exit(EXIT_SUCCESS);

	ASSERT_EQ(sys_waitid(P_PID, self->child_pid, WEXITED | WNOWAIT), 0);
}

FIXTURE_TEARDOWN(current_nsset)
{
	int i;

	for (i = 0; i < PIDFD_NS_MAX; i++)
		if (self->ns_fds[i] >= 0)
			close(self->ns_fds[i]);

	EXPECT_EQ(0, close(self->pidfd));
}

int preserve_ns(const int pid, const char *ns)
{
	int ret;
/* 5 /proc + 21 /int_as_str + 3 /ns + 20 /NS_NAME + 1 \0 */
#define __NS_PATH_LEN 50
	char path[__NS_PATH_LEN];

	/* This way we can use this function to also check whether namespaces
	 * are supported by the kernel by passing in the NULL or the empty
	 * string.
	 */
	ret = snprintf(path, __NS_PATH_LEN, "/proc/%d/ns%s%s", pid,
		       !ns || strcmp(ns, "") == 0 ? "" : "/",
		       !ns || strcmp(ns, "") == 0 ? "" : ns);
	if (ret < 0 || (size_t)ret >= __NS_PATH_LEN) {
		errno = EFBIG;
		return -1;
	}

	return open(path, O_RDONLY | O_CLOEXEC);
}

static int in_same_namespace(int ns_fd1, pid_t pid2, const char *ns)
{
	int ns_fd2 = -EBADF;
	int ret = -1;
	struct stat ns_st1, ns_st2;

	ret = fstat(ns_fd1, &ns_st1);
	if (ret < 0)
		return -1;

	ns_fd2 = preserve_ns(pid2, ns);
	if (ns_fd2 < 0)
		return -1;

	ret = fstat(ns_fd2, &ns_st2);
	close(ns_fd2);
	if (ret < 0)
		return -1;

	/* processes are in the same namespace */
	if ((ns_st1.st_dev == ns_st2.st_dev) &&
	    (ns_st1.st_ino == ns_st2.st_ino))
		return 1;

	/* processes are in different namespaces */
	return 0;
}

TEST_F(current_nsset, invalid_flags)
{
	ASSERT_NE(setns(self->pidfd, -1), 0);
	EXPECT_EQ(errno, EINVAL);
	ASSERT_NE(setns(self->pidfd, CLONE_VM), 0);
	EXPECT_EQ(errno, EINVAL);
	ASSERT_NE(setns(self->pidfd, CLONE_NEWUSER | CLONE_VM), 0);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(current_nsset, exited_child)
{
	ASSERT_NE(setns(self->child_pidfd, CLONE_NEWUSER | CLONE_NEWNET), 0);
	EXPECT_EQ(errno, ESRCH);
}

TEST_HARNESS_MAIN
