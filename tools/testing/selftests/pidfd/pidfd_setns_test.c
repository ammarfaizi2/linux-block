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
	PIDFD_NS_PIDCLD,
	PIDFD_NS_MAX
};

const struct ns_info {
	const char *proc_name;
	int clone_flag;
	const char *flag_name;
} ns_info[] = {
	[PIDFD_NS_USER]   = { "user",             CLONE_NEWUSER,   "CLONE_NEWUSER",                 },
	[PIDFD_NS_MNT]    = { "mnt",              CLONE_NEWNS,     "CLONE_NEWNS",                   },
	[PIDFD_NS_PID]    = { "pid",              CLONE_NEWPID,    "CLONE_NEWPID",                  },
	[PIDFD_NS_UTS]    = { "uts",              CLONE_NEWUTS,    "CLONE_NEWUTS",                  },
	[PIDFD_NS_IPC]    = { "ipc",              CLONE_NEWIPC,    "CLONE_NEWIPC",                  },
	[PIDFD_NS_NET]    = { "net",              CLONE_NEWNET,    "CLONE_NEWNET",                  },
	[PIDFD_NS_CGROUP] = { "cgroup",           CLONE_NEWCGROUP, "CLONE_NEWCGROUP",               },
	[PIDFD_NS_PIDCLD] = { "pid_for_children", 0,               "INVALID_FLAG_PID_FOR_CHILDREN", },
};

FIXTURE(current_nsset)
{
	pid_t pid;
	int pidfd;
	int ns_fds[PIDFD_NS_MAX];

	pid_t child_pid_exited;
	int child_pidfd_exited;

	pid_t child_pid_all_ns_stopped1;
	int child_pidfd_all_ns_stopped1;
	int child_ns_fds_all_ns_stopped1[PIDFD_NS_MAX];

	pid_t child_pid_all_ns_stopped2;
	int child_pidfd_all_ns_stopped2;
	int child_ns_fds_all_ns_stopped2[PIDFD_NS_MAX];
};

static int sys_waitid(int which, pid_t pid, int options)
{
	return syscall(__NR_waitid, which, pid, NULL, options, NULL);
}

pid_t create_child(int *pidfd, unsigned flags)
{
	struct clone_args args = {
		.flags		= CLONE_PIDFD | flags,
		.exit_signal	= SIGCHLD,
		.pidfd		= ptr_to_u64(pidfd),
	};

	return sys_clone3(&args, sizeof(struct clone_args));
}

FIXTURE_SETUP(current_nsset)
{
	int i;
	int proc_fd;

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		self->ns_fds[i] = -EBADF;
		self->child_ns_fds_all_ns_stopped1[i] = -EBADF;
		self->child_ns_fds_all_ns_stopped2[i] = -EBADF;
	}

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

	/* Create task that exits right away. */
	self->child_pid_exited = create_child(&self->child_pidfd_exited,
					      CLONE_NEWUSER | CLONE_NEWNET);
	ASSERT_GE(self->child_pid_exited, 0);

	if (self->child_pid_exited == 0)
		_exit(EXIT_SUCCESS);

	ASSERT_EQ(sys_waitid(P_PID, self->child_pid_exited, WEXITED | WNOWAIT), 0);

	self->pidfd = sys_pidfd_open(self->pid, 0);
	ASSERT_GE(self->pidfd, 0) {
		TH_LOG("%m - Failed to open pidfd for process %d", self->pid);
	}

	/* Create tasks that will be stopped. */
	self->child_pid_all_ns_stopped1 = create_child(&self->child_pidfd_all_ns_stopped1,
						      CLONE_NEWUSER |
						      CLONE_NEWNS |
						      CLONE_NEWCGROUP |
						      CLONE_NEWIPC |
						      CLONE_NEWUTS |
						      CLONE_NEWPID |
						      CLONE_NEWNET);
	ASSERT_GE(self->child_pid_all_ns_stopped1, 0);

	if (self->child_pid_all_ns_stopped1 == 0) {
		pause();
		_exit(EXIT_SUCCESS);
	}

	self->child_pid_all_ns_stopped2 = create_child(&self->child_pidfd_all_ns_stopped2,
						      CLONE_NEWUSER |
						      CLONE_NEWNS |
						      CLONE_NEWCGROUP |
						      CLONE_NEWIPC |
						      CLONE_NEWUTS |
						      CLONE_NEWPID |
						      CLONE_NEWNET);
	ASSERT_GE(self->child_pid_all_ns_stopped2, 0);

	if (self->child_pid_all_ns_stopped2 == 0) {
		pause();
		_exit(EXIT_SUCCESS);
	}

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		char path[100];

		const struct ns_info *info = &ns_info[i];

		self->ns_fds[i] = openat(proc_fd, info->proc_name, O_RDONLY | O_CLOEXEC);
		if (self->ns_fds[i] < 0) {
			EXPECT_EQ(errno, ENOENT) {
				TH_LOG("%m - Failed to open %s namespace for process %d",
				       info->proc_name, self->pid);
			}
		}

		(void)snprintf(path, sizeof(path), "/proc/%d/ns/%s", self->child_pid_all_ns_stopped1, info->proc_name);
		self->child_ns_fds_all_ns_stopped1[i] = open(path, O_RDONLY | O_CLOEXEC);
		if (self->child_ns_fds_all_ns_stopped1[i] < 0) {
			EXPECT_EQ(errno, ENOENT) {
				TH_LOG("%m - Failed to open %s namespace for process %d",
				       info->proc_name, self->child_pid_all_ns_stopped1);
			}
		}

		(void)snprintf(path, sizeof(path), "/proc/%d/ns/%s", self->child_pid_all_ns_stopped1, info->proc_name);
		self->child_ns_fds_all_ns_stopped2[i] = open(path, O_RDONLY | O_CLOEXEC);
		if (self->child_ns_fds_all_ns_stopped2[i] < 0) {
			EXPECT_EQ(errno, ENOENT) {
				TH_LOG("%m - Failed to open %s namespace for process %d",
				       info->proc_name, self->child_pid_all_ns_stopped1);
			}
		}
	}
}

FIXTURE_TEARDOWN(current_nsset)
{
	int i;

	ASSERT_EQ(sys_pidfd_send_signal(self->child_pidfd_all_ns_stopped1,
					SIGKILL, NULL, 0), 0);
	ASSERT_EQ(sys_pidfd_send_signal(self->child_pidfd_all_ns_stopped2,
					SIGKILL, NULL, 0), 0);

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		if (self->ns_fds[i] >= 0)
			close(self->ns_fds[i]);
		if (self->child_ns_fds_all_ns_stopped1[i] >= 0)
			close(self->child_ns_fds_all_ns_stopped1[i]);
		if (self->child_ns_fds_all_ns_stopped2[i] >= 0)
			close(self->child_ns_fds_all_ns_stopped2[i]);
	}

	EXPECT_EQ(0, close(self->child_pidfd_all_ns_stopped1));
	EXPECT_EQ(0, close(self->child_pidfd_all_ns_stopped2));
	ASSERT_EQ(sys_waitid(P_PID, self->child_pid_exited, WEXITED), 0);
	ASSERT_EQ(sys_waitid(P_PID, self->child_pid_all_ns_stopped1, WEXITED), 0);
	ASSERT_EQ(sys_waitid(P_PID, self->child_pid_all_ns_stopped2, WEXITED), 0);
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

/* Test that we can't pass garbage to the kernel. */
TEST_F(current_nsset, invalid_flags)
{
	ASSERT_NE(setns(self->pidfd, 0), 0);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_NE(setns(self->pidfd, -1), 0);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_NE(setns(self->pidfd, CLONE_VM), 0);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_NE(setns(self->pidfd, CLONE_NEWUSER | CLONE_VM), 0);
	EXPECT_EQ(errno, EINVAL);
}

/* Test that we can't attach to a task that has already exited. */
TEST_F(current_nsset, exited_child)
{
	int i;
	pid_t pid;

	ASSERT_NE(setns(self->child_pidfd_exited, CLONE_NEWUSER | CLONE_NEWNET), 0);
	EXPECT_EQ(errno, ESRCH);

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		/* Verify that we haven't changed any namespaces. */
		if (self->ns_fds[i] >= 0)
			ASSERT_EQ(in_same_namespace(self->ns_fds[i], pid, info->proc_name), 1);
	}
}

TEST_F(current_nsset, incremental_setns)
{
	int i;
	pid_t pid;

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		int nsfd;

		if (self->child_ns_fds_all_ns_stopped1[i] < 0)
			continue;

		if (info->clone_flag) {
			ASSERT_EQ(setns(self->child_pidfd_all_ns_stopped1, info->clone_flag), 0) {
				TH_LOG("%m - Failed to setns to %s namespace of %d", info->proc_name, self->child_pid_all_ns_stopped1);
			}
		}

		/* Verify that we have changed to the correct namespaces. */
		if (info->clone_flag == CLONE_NEWPID)
			nsfd = self->ns_fds[i];
		else
			nsfd = self->child_ns_fds_all_ns_stopped1[i];
		ASSERT_EQ(in_same_namespace(nsfd, pid, info->proc_name), 1) {
			TH_LOG("setns failed to place us correctly into %s namespace of %d", info->proc_name, self->child_pid_all_ns_stopped1);
		}
		TH_LOG("Managed to correctly setns to %s namespace of %d", info->proc_name, self->child_pid_all_ns_stopped1);
	}
}

TEST_F(current_nsset, one_shot_setns)
{
	unsigned flags = 0;
	int i;
	pid_t pid;

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];

		if (self->child_ns_fds_all_ns_stopped1[i] < 0)
			continue;

		flags |= info->clone_flag;
		TH_LOG("Adding %s namespace of %d to list of namespaces to attach to", info->proc_name, self->child_pid_all_ns_stopped1);
	}

	ASSERT_EQ(setns(self->child_pidfd_all_ns_stopped1, flags), 0) {
		TH_LOG("%m - Failed to setns to namespaces of %d", self->child_pid_all_ns_stopped1);
	}

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		int nsfd;

		if (self->child_ns_fds_all_ns_stopped1[i] < 0)
			continue;

		/* Verify that we have changed to the correct namespaces. */
		if (info->clone_flag == CLONE_NEWPID)
			nsfd = self->ns_fds[i];
		else
			nsfd = self->child_ns_fds_all_ns_stopped1[i];
		ASSERT_EQ(in_same_namespace(nsfd, pid, info->proc_name), 1) {
			TH_LOG("setns failed to place us correctly into %s namespace of %d", info->proc_name, self->child_pid_all_ns_stopped1);
		}
		TH_LOG("Managed to correctly setns to %s namespace of %d", info->proc_name, self->child_pid_all_ns_stopped1);
	}
}

TEST_F(current_nsset, no_foul_play)
{
	unsigned flags = 0;
	int i;

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];

		if (self->child_ns_fds_all_ns_stopped1[i] < 0)
			continue;

		flags |= info->clone_flag;
		if (info->clone_flag) /* No use logging pid_for_children. */
			TH_LOG("Adding %s namespace of %d to list of namespaces to attach to", info->proc_name, self->child_pid_all_ns_stopped1);
	}

	ASSERT_EQ(setns(self->child_pidfd_all_ns_stopped1, flags), 0) {
		TH_LOG("%m - Failed to setns to namespaces of %d", self->child_pid_all_ns_stopped1);
	}


	/*
	 * Can't setns to a user namespace outside of our hierarchy since we
	 * don't have caps in there and didn't create it. That means that under
	 * no circumstances should we be able to setns to any of the other
	 * ones since they aren't owned by our user namespace.
	 */
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];

		if (self->child_ns_fds_all_ns_stopped1[i] < 0)
			continue;

		if (!info->clone_flag)
			continue;

		ASSERT_NE(setns(self->child_pidfd_all_ns_stopped2, info->clone_flag), 0) {
			TH_LOG("Managed to setns to %s namespace of %d", info->proc_name, self->child_pid_all_ns_stopped2);
		}
		TH_LOG("%m - Correctly failed to setns to %s namespace of %d", info->proc_name, self->child_pid_all_ns_stopped2);
	}
}

TEST_HARNESS_MAIN
