// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>

#include "internal.h"
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

static int map_ids(pid_t pid, unsigned long nsid, unsigned long hostid,
		   unsigned long range)
{
	char map[100], procfile[256];

	snprintf(procfile, sizeof(procfile), "/proc/%d/setgroups", pid);
	if (write_file(procfile, "deny", sizeof("deny") - 1) &&
	    errno != ENOENT)
		return -1;

	snprintf(procfile, sizeof(procfile), "/proc/%d/uid_map", pid);
	snprintf(map, sizeof(map), "%lu %lu %lu", nsid, hostid, range);
	if (write_file(procfile, map, strlen(map)))
		return -1;


	snprintf(procfile, sizeof(procfile), "/proc/%d/gid_map", pid);
	snprintf(map, sizeof(map), "%lu %lu %lu", nsid, hostid, range);
	if (write_file(procfile, map, strlen(map)))
		return -1;

	return 0;
}

#define __STACK_SIZE (8 * 1024 * 1024)
static pid_t do_clone(int (*fn)(void *), void *arg, int flags)
{
	void *stack;

	stack = malloc(__STACK_SIZE);
	if (!stack)
		return -ENOMEM;

#ifdef __ia64__
	return __clone2(fn, stack, __STACK_SIZE, flags | SIGCHLD, arg, NULL);
#else
	return clone(fn, stack + __STACK_SIZE, flags | SIGCHLD, arg, NULL);
#endif
}

static int get_userns_fd_cb(void *data)
{
	return kill(getpid(), SIGSTOP);
}

static int get_userns_fd(unsigned long nsid, unsigned long hostid,
			 unsigned long range)
{
	int ret;
	pid_t pid;
	char path[256];

	pid = do_clone(get_userns_fd_cb, NULL, CLONE_NEWUSER | CLONE_NEWNS);
	if (pid < 0)
		return -errno;

	ret = map_ids(pid, nsid, hostid, range);
	if (ret < 0)
		return ret;

	snprintf(path, sizeof(path), "/proc/%d/ns/user", pid);
	ret = open(path, O_RDONLY | O_CLOEXEC);
	kill(pid, SIGKILL);
	return ret;
}

struct run_as_data {
	int userns;
	int (*f)(void *data);
	void *data;
};

static int run_in_cb(void *data)
{
	struct run_as_data *rad = data;

	if (setns(rad->userns, CLONE_NEWUSER) < 0) {
		perror("setns");
		return 1;
	}

	if (setuid(100010)) {
		perror("setuid");
		return 1;
	}

	if (setgid(100010)) {
		perror("setgid");
		return 1;
	}

	return rad->f(rad->data);
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

static int run_in(int userns, int (*f)(void *), void *f_data)
{
	pid_t pid;
	struct run_as_data data;

	data.userns = userns;
	data.f = f;
	data.data = f_data;
	pid = do_clone(run_in_cb, &data, 0);
	if (pid < 0)
		return -errno;

	return wait_for_pid(pid);
}

FIXTURE(ext4_xattr) {};

FIXTURE_SETUP(ext4_xattr)
{
	int fd;

	fd = open("/tmp/idmap_mounts.ext4", O_CREAT | O_WRONLY, 0600);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(ftruncate(fd, 640 * 1024), 0);
	ASSERT_EQ(close(fd), 0);
	ASSERT_EQ(system("mkfs.ext4 /tmp/idmap_mounts.ext4"), 0);
	ASSERT_EQ(mkdir("/tmp/ext4", 0777), 0);
	ASSERT_EQ(system("mount -o loop -t ext4 /tmp/idmap_mounts.ext4 /tmp/ext4"), 0);
}

FIXTURE_TEARDOWN(ext4_xattr)
{
	umount("/tmp/ext4/dest");
	umount("/tmp/ext4");
	rmdir("/tmp/ext4");
	unlink("/tmp/idmap_mounts.ext4");
}

struct getacl_should_be_data {
	char path[256];
	uid_t uid;
};

static int getacl_should_be_uid(void *data)
{
	struct getacl_should_be_data *ssb = data;
	char cmd[512];
	int ret;

	snprintf(cmd, sizeof(cmd), "getfacl %s | grep user:%u:rwx", ssb->path, ssb->uid);
	ret = system(cmd);
	if (ret < 0) {
		perror("system");
		return -1;
	}
	if (!WIFEXITED(ret))
		return -1;
	return WEXITSTATUS(ret);
}

static int ls_path(void *data)
{
	char cmd[PATH_MAX];
	char *path = data;
	int ret;

	snprintf(cmd, sizeof(cmd), "ls %s", path);
	ret = system(cmd);
	if (ret < 0) {
		perror("system");
		return -1;
	}
	if (!WIFEXITED(ret))
		return -1;
	return WEXITSTATUS(ret);
}

TEST_F(ext4_xattr, setattr_didnt_work)
{
	int mount_fd, ret;
	struct mount_attr attr = {};
	struct getacl_should_be_data ssb;

	ASSERT_EQ(mkdir("/tmp/ext4/source", 0777), 0);
	ASSERT_EQ(mkdir("/tmp/ext4/dest", 0777), 0);

	mount_fd = sys_open_tree(-EBADF, "/tmp/ext4/source",
				 OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
	ASSERT_GE(mount_fd, 0);

	ASSERT_EQ(sys_move_mount(mount_fd, "", -EBADF, "/tmp/ext4/dest",
				 MOVE_MOUNT_F_EMPTY_PATH), 0);

	attr.attr_set = MOUNT_ATTR_IDMAP;
	attr.userns = get_userns_fd(100010, 100020, 5);
	ASSERT_GE(attr.userns, 0);
	ret = sys_mount_setattr(mount_fd, "", AT_EMPTY_PATH | AT_RECURSIVE,
				    &attr, sizeof(attr));
	ASSERT_EQ(close(mount_fd), 0);
	ASSERT_EQ(ret, 0);

	ASSERT_EQ(mkdir("/tmp/ext4/source/foo", 0700), 0);
	ASSERT_EQ(chown("/tmp/ext4/source/foo", 100010, 100010), 0);

	ASSERT_EQ(system("setfacl -m u:100010:rwx /tmp/ext4/source/foo"), 0);
	EXPECT_EQ(system("getfacl /tmp/ext4/source/foo | grep user:100010:rwx"), 0);
	EXPECT_EQ(system("getfacl /tmp/ext4/dest/foo | grep user:100020:rwx"), 0);

	snprintf(ssb.path, sizeof(ssb.path), "/tmp/ext4/source/foo");
	ssb.uid = 4294967295;
	EXPECT_EQ(run_in(attr.userns, getacl_should_be_uid, &ssb), 0);

	snprintf(ssb.path, sizeof(ssb.path), "/tmp/ext4/dest/foo");
	ssb.uid = 100010;
	EXPECT_EQ(run_in(attr.userns, getacl_should_be_uid, &ssb), 0);

	/*
	 * now, dir is owned by someone else in the user namespace, but we can
	 * still read it because of acls
	 */
	ASSERT_EQ(chown("/tmp/ext4/source/foo", 100012, 100012), 0);
	EXPECT_EQ(run_in(attr.userns, ls_path, "/tmp/ext4/dest/foo"), 0);

	/*
	 * if we delete the acls, the ls should fail because it's 700.
	 */
	ASSERT_EQ(system("setfacl --remove-all /tmp/ext4/source/foo"), 0);
	EXPECT_NE(run_in(attr.userns, ls_path, "/tmp/ext4/dest/foo"), 0);
}

TEST_HARNESS_MAIN
