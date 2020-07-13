// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <stdbool.h>
#include <stdarg.h>

#include "../kselftest_harness.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_RELATIME
#define MS_RELATIME (1 << 21)
#endif

#ifndef MS_STRICTATIME
#define MS_STRICTATIME (1 << 24)
#endif

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif

#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID 0x00000002
#endif

#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC 0x00000008
#endif

#ifndef MOUNT_ATTR_NODIRATIME
#define MOUNT_ATTR_NODIRATIME 0x00000080
#endif

#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME 0x00000070
#endif

#ifndef MOUNT_ATTR_RELATIME
#define MOUNT_ATTR_RELATIME 0x00000000
#endif

#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME 0x00000010
#endif

#ifndef MOUNT_ATTR_STRICTATIME
#define MOUNT_ATTR_STRICTATIME 0x00000020
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

#ifndef MAKE_PROPAGATION_SHARED
#define MAKE_PROPAGATION_SHARED 4
#endif

#define DEFAULT_THREADS 4
#define ptr_to_int(p) ((int)((intptr_t)(p)))
#define int_to_ptr(u) ((void *)((intptr_t)(u)))

#ifndef __NR_mount_setattr
	#if defined __alpha__
		#define __NR_mount_setattr 550
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_mount_setattr 4440
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_mount_setattr 6440
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_mount_setattr 5440
		#endif
	#elif defined __ia64__
		#define __NR_mount_setattr (440 + 1024)
	#else
		#define __NR_mount_setattr 440
#endif

struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
};
#endif

static inline int sys_mount_setattr(int dfd, const char *path, unsigned int flags,
				    struct mount_attr *attr, size_t size)
{
	return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
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

	return 0;
}

static int read_mnt_flags(const char *path)
{
	int ret;
	struct statvfs stat;
	unsigned int mnt_flags;

	ret = statvfs(path, &stat);
	if (ret != 0)
		return -EINVAL;

	if (stat.f_flag &
	    ~(ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC | ST_NOATIME |
	      ST_NODIRATIME | ST_RELATIME | ST_SYNCHRONOUS | ST_MANDLOCK))
		return -EINVAL;

	mnt_flags = 0;
	if (stat.f_flag & ST_RDONLY)
		mnt_flags |= MS_RDONLY;
	if (stat.f_flag & ST_NOSUID)
		mnt_flags |= MS_NOSUID;
	if (stat.f_flag & ST_NODEV)
		mnt_flags |= MS_NODEV;
	if (stat.f_flag & ST_NOEXEC)
		mnt_flags |= MS_NOEXEC;
	if (stat.f_flag & ST_NOATIME)
		mnt_flags |= MS_NOATIME;
	if (stat.f_flag & ST_NODIRATIME)
		mnt_flags |= MS_NODIRATIME;
	if (stat.f_flag & ST_RELATIME)
		mnt_flags |= MS_RELATIME;
	if (stat.f_flag & ST_SYNCHRONOUS)
		mnt_flags |= MS_SYNCHRONOUS;
	if (stat.f_flag & ST_MANDLOCK)
		mnt_flags |= ST_MANDLOCK;

	return mnt_flags;
}

static char *get_field(char *src, int nfields)
{
	int i;
	char *p = src;

	for (i = 0; i < nfields; i++) {
		while (*p && *p != ' ' && *p != '\t')
			p++;

		if (!*p)
			break;

		p++;
	}

	return p;
}

static void null_endofword(char *word)
{
	while (*word && *word != ' ' && *word != '\t')
		word++;
	*word = '\0';
}

static bool is_shared_mount(const char *path)
{
	size_t len = 0;
	char *line = NULL;
	FILE *f = NULL;

	f = fopen("/proc/self/mountinfo", "re");
	if (!f)
		return false;

	while (getline(&line, &len, f) != -1) {
		char *opts, *target;

		target = get_field(line, 4);
		if (!target)
			continue;

		opts = get_field(target, 2);
		if (!opts)
			continue;

		null_endofword(target);

		if (strcmp(target, path) != 0)
			continue;

		null_endofword(opts);
		if (strstr(opts, "shared:"))
			return true;
	}

	free(line);
	fclose(f);

	return false;
}

static void *mount_setattr_thread(void *data)
{
	struct mount_attr attr = {
		.attr_set	= MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID,
		.attr_clr	= 0,
		.propagation	= MAKE_PROPAGATION_SHARED,
	};

	if (sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)))
		pthread_exit(int_to_ptr(-1));

	pthread_exit(int_to_ptr(0));
}

FIXTURE(mount_setattr) {
};

FIXTURE_SETUP(mount_setattr)
{
	ASSERT_EQ(prepare_unpriv_mountns(), 0);

	(void)umount2("/mnt", MNT_DETACH);
	(void)umount2("/tmp", MNT_DETACH);

	ASSERT_EQ(mount("testing", "/tmp", "tmpfs", MS_NOATIME | MS_NODEV,
			"size=100000,mode=700"), 0);

	ASSERT_EQ(mkdir("/tmp/B", 0777), 0);

	ASSERT_EQ(mount("testing", "/tmp/B", "tmpfs", MS_NOATIME | MS_NODEV,
			"size=100000,mode=700"), 0);

	ASSERT_EQ(mkdir("/tmp/B/BB", 0777), 0);

	ASSERT_EQ(mount("testing", "/tmp/B/BB", "tmpfs", MS_NOATIME | MS_NODEV,
			"size=100000,mode=700"), 0);

	ASSERT_EQ(mount("testing", "/mnt", "tmpfs", MS_NOATIME | MS_NODEV,
			"size=100000,mode=700"), 0);

	ASSERT_EQ(mkdir("/mnt/A", 0777), 0);

	ASSERT_EQ(mount("testing", "/mnt/A", "tmpfs", MS_NOATIME | MS_NODEV,
			"size=100000,mode=700"), 0);

	ASSERT_EQ(mkdir("/mnt/A/AA", 0777), 0);

	ASSERT_EQ(mount("/tmp", "/mnt/A/AA", NULL, MS_BIND | MS_REC, NULL), 0);

	ASSERT_EQ(mkdir("/mnt/B", 0777), 0);

	ASSERT_EQ(mount("testing", "/mnt/B", "ramfs",
			MS_NOATIME | MS_NODEV | MS_NOSUID, 0), 0);

	ASSERT_EQ(mkdir("/mnt/B/BB", 0777), 0);

	ASSERT_EQ(mount("testing", "/tmp/B/BB", "devpts",
			MS_RELATIME | MS_NOEXEC | MS_RDONLY, 0), 0);
}

FIXTURE_TEARDOWN(mount_setattr)
{
	(void)umount2("/mnt/A", MNT_DETACH);
	(void)umount2("/tmp", MNT_DETACH);
}

TEST_F(mount_setattr, invalid_attributes)
{
	struct mount_attr invalid_attr = {
		.attr_set = (1U << 31),
	};

	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &invalid_attr,
				    sizeof(invalid_attr)), 0);

	invalid_attr.attr_set	= 0;
	invalid_attr.attr_clr	= (1U << 31);
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &invalid_attr,
				    sizeof(invalid_attr)), 0);

	invalid_attr.attr_clr		= 0;
	invalid_attr.propagation	= (1U << 31);
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &invalid_attr,
				    sizeof(invalid_attr)), 0);

	invalid_attr.attr_set		= (1U << 31);
	invalid_attr.attr_clr		= (1U << 31);
	invalid_attr.propagation	= (1U << 31);
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &invalid_attr,
				    sizeof(invalid_attr)), 0);

	ASSERT_NE(sys_mount_setattr(-1, "mnt/A", AT_RECURSIVE, &invalid_attr,
				    sizeof(invalid_attr)), 0);
}

TEST_F(mount_setattr, extensibility)
{
	unsigned int old_flags = 0, new_flags = 0, expected_flags = 0;
	char *s = "dummy";
	struct mount_attr invalid_attr = {};
	struct mount_attr_large {
		struct mount_attr attr1;
		struct mount_attr attr2;
	} large_attr = {};

	old_flags = read_mnt_flags("/mnt/A");
	ASSERT_GT(old_flags, 0);

	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, NULL,
				    sizeof(invalid_attr)), 0);
	ASSERT_EQ(errno, EFAULT);

	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, (void *)s,
				    sizeof(invalid_attr)), 0);
	ASSERT_EQ(errno, EINVAL);

	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &invalid_attr, 0), 0);
	ASSERT_EQ(errno, EINVAL);

	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &invalid_attr,
				    sizeof(invalid_attr) / 2), 0);
	ASSERT_EQ(errno, EINVAL);

	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &invalid_attr,
				    sizeof(invalid_attr) / 2), 0);
	ASSERT_EQ(errno, EINVAL);

	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE,
				    (void *)&large_attr, sizeof(large_attr)), 0);

	large_attr.attr2.attr_set = MOUNT_ATTR_RDONLY;
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE,
				    (void *)&large_attr, sizeof(large_attr)), 0);

	large_attr.attr2.attr_set = 0;
	large_attr.attr1.attr_set = MOUNT_ATTR_RDONLY;
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE,
				    (void *)&large_attr, sizeof(large_attr)), 0);

	expected_flags = old_flags;
	expected_flags |= MS_RDONLY;

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);
}

TEST_F(mount_setattr, basic)
{
	unsigned int old_flags = 0, new_flags = 0, expected_flags = 0;
	struct mount_attr attr = {
		.attr_set	= MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_RELATIME,
		.attr_clr	= MOUNT_ATTR__ATIME,
	};

	old_flags = read_mnt_flags("/mnt/A");
	ASSERT_GT(old_flags, 0);

	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", 0, &attr, sizeof(attr)), 0);

	expected_flags = old_flags;
	expected_flags |= MS_RDONLY;
	expected_flags |= MS_NOEXEC;
	expected_flags &= ~MS_NOATIME;
	expected_flags |= MS_RELATIME;

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, old_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, old_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, old_flags);
}

TEST_F(mount_setattr, basic_recursive)
{
	int fd;
	unsigned int old_flags = 0, new_flags = 0, expected_flags = 0;
	struct mount_attr attr = {
		.attr_set	= MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_RELATIME,
		.attr_clr	= MOUNT_ATTR__ATIME,
	};

	old_flags = read_mnt_flags("/mnt/A");
	ASSERT_GT(old_flags, 0);

	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	expected_flags = old_flags;
	expected_flags |= MS_RDONLY;
	expected_flags |= MS_NOEXEC;
	expected_flags &= ~MS_NOATIME;
	expected_flags |= MS_RELATIME;

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	memset(&attr, 0, sizeof(attr));
	attr.attr_clr = MOUNT_ATTR_RDONLY;
	attr.propagation = MAKE_PROPAGATION_SHARED;
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	expected_flags &= ~MS_RDONLY;
	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A"), true);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA"), true);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA/B"), true);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA/B/BB"), true);

	fd = open("/mnt/A/AA/B/b", O_RDWR | O_CLOEXEC | O_CREAT | O_EXCL, 0777);
	ASSERT_GE(fd, 0);

	/*
	 * We're holding a fd open for writing so this needs to fail somewhere
	 * in the middle and the mount options need to be unchanged.
	 */
	attr.attr_set = MOUNT_ATTR_RDONLY;
	ASSERT_LT(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A"), true);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA"), true);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA/B"), true);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA/B/BB"), true);

	EXPECT_EQ(close(fd), 0);
}

TEST_F(mount_setattr, mount_has_writers)
{
	int fd, dfd;
	unsigned int old_flags = 0, new_flags = 0;
	struct mount_attr attr = {
		.attr_set	= MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_RELATIME,
		.attr_clr	= MOUNT_ATTR__ATIME,
		.propagation	= MAKE_PROPAGATION_SHARED,
	};

	old_flags = read_mnt_flags("/mnt/A");
	ASSERT_GT(old_flags, 0);

	fd = open("/mnt/A/AA/B/b", O_RDWR | O_CLOEXEC | O_CREAT | O_EXCL, 0777);
	ASSERT_GE(fd, 0);

	/*
	 * We're holding a fd open to a mount somwhere in the middle so this
	 * needs to fail somewhere in the middle. After this the mount options
	 * need to be unchanged.
	 */
	ASSERT_LT(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, old_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A"), false);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, old_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA"), false);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, old_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA/B"), false);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, old_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA/B/BB"), false);

	dfd = open("/mnt/A/AA/B", O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(dfd, 0);
	EXPECT_EQ(fsync(dfd), 0);
	EXPECT_EQ(close(dfd), 0);

	EXPECT_EQ(fsync(fd), 0);
	EXPECT_EQ(close(fd), 0);

	/* All writers are gone so this should succeed. */
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);
}

TEST_F(mount_setattr, mixed_mount_options)
{
	unsigned int old_flags1 = 0, old_flags2 = 0, new_flags = 0, expected_flags = 0;
	struct mount_attr attr = {
		.attr_clr = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC | MOUNT_ATTR__ATIME,
		.attr_set = MOUNT_ATTR_RELATIME,
	};

	old_flags1 = read_mnt_flags("/mnt/B");
	ASSERT_GT(old_flags1, 0);

	old_flags2 = read_mnt_flags("/mnt/B/BB");
	ASSERT_GT(old_flags2, 0);

	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/B", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	expected_flags = old_flags2;
	expected_flags &= ~(MS_RDONLY | MS_NOEXEC | MS_NOATIME | MS_NOSUID);
	expected_flags |= MS_RELATIME;

	new_flags = read_mnt_flags("/mnt/B");
	ASSERT_EQ(new_flags, expected_flags);

	expected_flags = old_flags2;
	expected_flags &= ~(MS_RDONLY | MS_NOEXEC | MS_NOATIME | MS_NOSUID);
	expected_flags |= MS_RELATIME;

	new_flags = read_mnt_flags("/mnt/B/BB");
	ASSERT_EQ(new_flags, expected_flags);
}

TEST_F(mount_setattr, time_changes)
{
	unsigned int old_flags = 0, new_flags = 0, expected_flags = 0;
	struct mount_attr attr = {
		.attr_set	= MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOATIME,
	};

	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	attr.attr_set = MOUNT_ATTR_STRICTATIME;
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	attr.attr_set = MOUNT_ATTR_STRICTATIME | MOUNT_ATTR_NOATIME;
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	attr.attr_set = MOUNT_ATTR_STRICTATIME | MOUNT_ATTR_NOATIME;
	attr.attr_clr = MOUNT_ATTR__ATIME;
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	attr.attr_set = 0;
	attr.attr_clr = MOUNT_ATTR_STRICTATIME;
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	attr.attr_clr = MOUNT_ATTR_NOATIME;
	ASSERT_NE(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	old_flags = read_mnt_flags("/mnt/A");
	ASSERT_GT(old_flags, 0);

	attr.attr_set = MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOATIME;
	attr.attr_clr = MOUNT_ATTR__ATIME;
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	expected_flags = old_flags;
	expected_flags |= MS_NOATIME;
	expected_flags |= MS_NODIRATIME;

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	memset(&attr, 0, sizeof(attr));
	attr.attr_set &= ~MOUNT_ATTR_NOATIME;
	attr.attr_set |= MOUNT_ATTR_RELATIME;
	attr.attr_clr |= MOUNT_ATTR__ATIME;
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	expected_flags &= ~MS_NOATIME;
	expected_flags |= MS_RELATIME;

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	memset(&attr, 0, sizeof(attr));
	attr.attr_set &= ~MOUNT_ATTR_RELATIME;
	attr.attr_set |= MOUNT_ATTR_STRICTATIME;
	attr.attr_clr |= MOUNT_ATTR__ATIME;
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	expected_flags &= ~MS_RELATIME;

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	memset(&attr, 0, sizeof(attr));
	attr.attr_set &= ~MOUNT_ATTR_STRICTATIME;
	attr.attr_set |= MOUNT_ATTR_NOATIME;
	attr.attr_clr |= MOUNT_ATTR__ATIME;
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	expected_flags |= MS_NOATIME;
	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	memset(&attr, 0, sizeof(attr));
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	memset(&attr, 0, sizeof(attr));
	attr.attr_clr = MOUNT_ATTR_NODIRATIME;
	ASSERT_EQ(sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	expected_flags &= ~MS_NODIRATIME;

	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);
}

TEST_F(mount_setattr, multi_threaded)
{
	int i, j, nthreads, ret = 0;
	unsigned int old_flags = 0, new_flags = 0, expected_flags = 0;
	pthread_attr_t pattr;
	pthread_t threads[DEFAULT_THREADS];

	old_flags = read_mnt_flags("/mnt/A");
	ASSERT_GT(old_flags, 0);

	/* Try to change mount options from multiple threads. */
	nthreads = get_nprocs_conf();
	if (nthreads > DEFAULT_THREADS)
		nthreads = DEFAULT_THREADS;

	pthread_attr_init(&pattr);
	for (i = 0; i < nthreads; i++)
		ASSERT_EQ(pthread_create(&threads[i], &pattr, mount_setattr_thread, NULL), 0);

	for (j = 0; j < i; j++) {
		void *retptr = NULL;

		EXPECT_EQ(pthread_join(threads[j], &retptr), 0);

		ret += ptr_to_int(retptr);
		EXPECT_EQ(ret, 0);
	}
	pthread_attr_destroy(&pattr);

	ASSERT_EQ(ret, 0);

	expected_flags = old_flags;
	expected_flags |= MS_RDONLY;
	expected_flags |= MS_NOSUID;
	new_flags = read_mnt_flags("/mnt/A");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A"), true);

	new_flags = read_mnt_flags("/mnt/A/AA");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA"), true);

	new_flags = read_mnt_flags("/mnt/A/AA/B");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA/B"), true);

	new_flags = read_mnt_flags("/mnt/A/AA/B/BB");
	ASSERT_EQ(new_flags, expected_flags);

	ASSERT_EQ(is_shared_mount("/mnt/A/AA/B/BB"), true);
}

TEST_F(mount_setattr, wrong_user_namespace)
{
	int ret;
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_RDONLY,
	};

	EXPECT_EQ(create_and_enter_userns(), 0);
	ret = sys_mount_setattr(-1, "/mnt/A", AT_RECURSIVE, &attr, sizeof(attr));
	ASSERT_LT(ret, 0);
	ASSERT_EQ(errno, EPERM);
}

TEST_F(mount_setattr, wrong_mount_namespace)
{
	int fd, ret;
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_RDONLY,
	};

	fd = open("/mnt/A", O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(fd, 0);

	ASSERT_EQ(unshare(CLONE_NEWNS), 0);

	ret = sys_mount_setattr(fd, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof(attr));
	ASSERT_LT(ret, 0);
	ASSERT_EQ(errno, EINVAL);
}

TEST_HARNESS_MAIN
