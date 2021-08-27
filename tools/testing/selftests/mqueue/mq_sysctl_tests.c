// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/mount.h>
#include <mqueue.h>
#include <sys/wait.h>
#include <string.h>

#include "../kselftest_harness.h"

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

static int create_and_enter_userns(void)
{
	uid_t uid;
	gid_t gid;
	char map[100];

	uid = getuid();
	gid = getgid();

	if (unshare(CLONE_NEWUSER))
		return -1;

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

static int prepare_unpriv_mountns(void)
{
	if (create_and_enter_userns())
		return -1;

	if (unshare(CLONE_NEWNS))
		return -1;

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0))
		return -1;

	if (unshare(CLONE_NEWIPC))
		return -1;

	return 0;
}

static int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (!WIFEXITED(status))
		return -1;

	return WEXITSTATUS(status);
}

static int get_mq_queues_max(void)
{
	int fd;
	char buf[16];
	int val = -1;

	fd = open("/proc/sys/fs/mqueue/queues_max", O_RDONLY);
	if (fd >= 0) {
		if (read(fd, buf, sizeof(buf)) > 0)
			val = atoi(buf);

		close(fd);
		return val;
	}
	return val;
}

TEST(mqueue_sysctl)
{
	pid_t pid;
	int qmax1, qmax2;
	int dirfd;
	char tmpdir[] = "/mqueue_sysctl_XXXXXX";

	if (!mkdtemp(tmpdir))
		SKIP(return, "create temp dir failed");

	/* read and stash the original sysctl value */
	qmax1 = get_mq_queues_max();
	ASSERT_GE(qmax1, 0);

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		ASSERT_EQ(prepare_unpriv_mountns(), 0);

		ASSERT_EQ(mount("none", tmpdir, "mqueue", MS_NOATIME, NULL), 0);

		/* modify the sysctl value in new ipc namesapce */
		ASSERT_EQ(write_file("/proc/sys/fs/mqueue/queues_max", "1", 1), 0);

		ASSERT_GE(mq_open("/new_ns1",  O_RDWR | O_CREAT, 0644, NULL), 0);

		/* mq_open() should fail as exceeding of queues_max */
		ASSERT_EQ(mq_open("/new_ns2",  O_RDWR | O_CREAT, 0644, NULL), -1);

		ASSERT_EQ(mq_unlink("/new_ns1"), 0);
		ASSERT_EQ(umount(tmpdir), 0);

		exit(0);
	}

	ASSERT_EQ(wait_for_pid(pid), 0);

	qmax2 = get_mq_queues_max();
	ASSERT_EQ(qmax1, qmax2);

	remove(tmpdir);
}

TEST_HARNESS_MAIN
