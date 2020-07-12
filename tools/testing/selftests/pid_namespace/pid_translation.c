#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/wait.h>

#include "../clone3/clone3_selftests.h"
#include "../kselftest_harness.h"
#include "../pidfd/pidfd.h"

static pid_t clone_new_pidns(void)
{
	struct clone_args args = {
		.flags		= CLONE_NEWPID | CLONE_NEWUSER,
		.exit_signal	= SIGCHLD,
	};

	return sys_clone3(&args, sizeof(struct clone_args));
}

static ssize_t write_nointr(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

static int write_file(const char *path, const void *buf, size_t count)
{
	int fd;
	ssize_t ret;

	fd = open(path, O_WRONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0)
		return -1;

	ret = write_nointr(fd, buf, count);
	close(fd);
	if (ret < 0 || (size_t)ret != count)
		return -1;

	return 0;
}

static int write_mapping(uid_t uid, gid_t gid)
{
	char map[100];

	if (write_file("/proc/self/setgroups", "deny", sizeof("deny") - 1) &&
	    errno != ENOENT)
		return -1;

	snprintf(map, sizeof(map), "0 %d 1", uid);
	if (write_file("/proc/self/uid_map", map, strlen(map)))
		return -1;


	snprintf(map, sizeof(map), "0 %d 1", gid);
	if (write_file("/proc/self/gid_map", map, strlen(map)))
		return -1;

	if (setgid(0))
		return -1;

	if (setuid(0))
		return -1;

	return 0;
}

FIXTURE(translate_pid)
{
	uid_t uid;
	gid_t gid;
	pid_t pid_pidns;
	pid_t pid_sibling;
	pid_t pid;
	pid_t self;
};

FIXTURE_SETUP(translate_pid)
{
	self->uid = getuid();
	self->gid = getgid();
	self->self = getpid();

	self->pid_pidns = clone_new_pidns();
	EXPECT_GT(self->pid_pidns, 0);

	if (self->pid_pidns == 0) {
		if (write_mapping(self->uid, self->gid))
			_exit(EXIT_FAILURE);
		_exit(EXIT_SUCCESS);
	}

	ASSERT_EQ(wait_for_pid(self->pid_pidns), 0);
}

FIXTURE_TEARDOWN(translate_pid)
{
}

TEST_F(translate_pid, log)
{
	printf("%d\n", self->uid);
	printf("%d\n", self->gid);
}

TEST_HARNESS_MAIN
