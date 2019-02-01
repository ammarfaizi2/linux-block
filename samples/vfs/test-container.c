/* Container test.
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <linux/mount.h>
#include <linux/unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <keyutils.h>

/* Hope -1 isn't a syscall */
#ifndef __NR_fsopen
#define __NR_fsopen -1
#endif
#ifndef __NR_fsmount
#define __NR_fsmount -1
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig -1
#endif
#ifndef __NR_move_mount
#define __NR_move_mount -1
#endif


#define E(x) do { if ((x) == -1) { perror(#x); exit(1); } } while(0)

static void check_messages(int fd)
{
	char buf[4096];
	int err, n;

	err = errno;

	for (;;) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0)
			break;
		n -= 2;

		switch (buf[0]) {
		case 'e':
			fprintf(stderr, "Error: %*.*s\n", n, n, buf + 2);
			break;
		case 'w':
			fprintf(stderr, "Warning: %*.*s\n", n, n, buf + 2);
			break;
		case 'i':
			fprintf(stderr, "Info: %*.*s\n", n, n, buf + 2);
			break;
		}
	}

	errno = err;
}

static __attribute__((noreturn))
void mount_error(int fd, const char *s)
{
	check_messages(fd);
	fprintf(stderr, "%s: %m\n", s);
	exit(1);
}

#define CONTAINER_NEW_FS_NS		0x00000001 /* Dup current fs namespace */
#define CONTAINER_NEW_EMPTY_FS_NS	0x00000002 /* Provide new empty fs namespace */
#define CONTAINER_NEW_CGROUP_NS		0x00000004 /* Dup current cgroup namespace [priv] */
#define CONTAINER_NEW_UTS_NS		0x00000008 /* Dup current uts namespace */
#define CONTAINER_NEW_IPC_NS		0x00000010 /* Dup current ipc namespace */
#define CONTAINER_NEW_USER_NS		0x00000020 /* Dup current user namespace */
#define CONTAINER_NEW_PID_NS		0x00000040 /* Dup current pid namespace */
#define CONTAINER_NEW_NET_NS		0x00000080 /* Dup current net namespace */
#define CONTAINER_KILL_ON_CLOSE		0x00000100 /* Kill all member processes when fd closed */
#define CONTAINER_FD_CLOEXEC		0x00000200 /* Close the fd on exec */
#define CONTAINER__FLAG_MASK		0x000003ff

static inline int fsopen(const char *fs_name, unsigned int flags)
{
	return syscall(__NR_fsopen, fs_name, flags);
}

static inline int fsconfig(int fsfd, unsigned int cmd,
			   const char *key, const void *val, int aux)
{
	return syscall(__NR_fsconfig, fsfd, cmd, key, val, aux);
}

static inline int fsmount(int fsfd, unsigned int flags, unsigned int attr_flags)
{
	return syscall(__NR_fsmount, fsfd, flags, attr_flags);
}

static inline int move_mount(int from_dfd, const char *from_pathname,
			     int to_dfd, const char *to_pathname,
			     unsigned int flags)
{
	return syscall(__NR_move_mount,
		       from_dfd, from_pathname,
		       to_dfd, to_pathname, flags);
}

static inline int container_create(const char *name, unsigned int mask)
{
	return syscall(__NR_container_create, name, mask, 0, 0, 0);
}

static inline int fork_into_container(int containerfd)
{
	return syscall(__NR_fork_into_container, containerfd);
}

#define E_fsconfig(fd, cmd, key, val, aux)				\
	do {								\
		if (fsconfig(fd, cmd, key, val, aux) == -1)		\
			mount_error(fd, key ?: "create");		\
	} while (0)

/*
 * The container init process.
 */
static __attribute__((noreturn))
void container_init(void)
{
	if (0) {
		/* Do a bit of debugging on the container. */
		struct dirent **dlist;
		struct stat st;
		char buf[4096];
		int n, i;

		printf("hello!\n");
		n = scandir("/", &dlist, NULL, alphasort);
		if (n == -1) {
			perror("scandir");
			exit(1);
		}

		for (i = 0; i < n; i++) {
			struct dirent *p = dlist[i];

			if (p)
				printf("- %u %s\n", p->d_type, p->d_name);
		}

		n = readlink("/bin", buf, sizeof(buf) - 1);
		if (n == -1) {
			perror("readlink");
			exit(1);
		}

		buf[n] = 0;
		printf("/bin -> %s\n", buf);

		if (stat("/lib64/ld-linux-x86-64.so.2", &st) == -1) {
			perror("stat");
			exit(1);
		}

		printf("mode %o\n", st.st_mode);
	}

	if (keyctl_join_session_keyring(NULL) == -1) {
		perror("keyctl/join");
		exit(1);
	}

	setenv("PS1", "container>", 1);
	execl("/bin/bash", "bash", NULL);
	perror("execl");
	exit(1);
}

/*
 * The container manager process.
 */
int main(int argc, char *argv[])
{
	pid_t pid;
	int fsfd, mfd, cfd, ws;

	if (argc != 2) {
		fprintf(stderr, "Format: test-container <root-dev>\n");
		exit(2);
	}

	cfd = container_create("foo-test",
			       CONTAINER_NEW_EMPTY_FS_NS |
			       //CONTAINER_NEW_UTS_NS |
			       //CONTAINER_NEW_IPC_NS |
			       //CONTAINER_NEW_USER_NS |
			       CONTAINER_NEW_PID_NS |
			       CONTAINER_KILL_ON_CLOSE |
			       CONTAINER_FD_CLOEXEC);
	if (cfd == -1) {
		perror("container_create");
		exit(1);
	}

	system("cat /proc/containers");

	/* Open the filesystem that's going to form the container root. */
	printf("Creating root...\n");
	fsfd = fsopen("ext4", 0);
	if (fsfd == -1) {
		perror("fsopen/root");
		exit(1);
	}

	E_fsconfig(fsfd, FSCONFIG_SET_CONTAINER, NULL, NULL, cfd);
	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "source", argv[1], 0);
	E_fsconfig(fsfd, FSCONFIG_SET_FLAG, "user_xattr", NULL, 0);
	E_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);

	/* Mount the container root */
	printf("Mounting root...\n");
	mfd = fsmount(fsfd, 0, 0);
	if (mfd < 0)
		mount_error(fsfd, "fsmount/root");

	if (move_mount(mfd, "", cfd, "/",
		       MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_CONTAINER_ROOT) < 0) {
		perror("move_mount/root");
		exit(1);
	}
	E(close(fsfd));
	E(close(mfd));

	/* Mount procfs within the container */
	printf("Creating procfs...\n");
	fsfd = fsopen("proc", 0);
	if (fsfd == -1) {
		perror("fsopen/proc");
		exit(1);
	}

	E_fsconfig(fsfd, FSCONFIG_SET_CONTAINER, NULL, NULL, cfd);
	E_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);

	printf("Mounting procfs...\n");
	mfd = fsmount(fsfd, 0, 0);
	if (mfd < 0)
		mount_error(fsfd, "fsmount/proc");
	if (move_mount(mfd, "", cfd, "proc", MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		perror("move_mount/proc");
		exit(1);
	}
	E(close(fsfd));
	E(close(mfd));

	/* Start the 'init' process. */
	printf("Forking...\n");
	switch ((pid = fork_into_container(cfd))) {
	case -1:
		perror("fork_into_container");
		exit(1);
	case 0:
		close(cfd);
		container_init();
	default:
		if (waitpid(pid, &ws, 0) < 0) {
			perror("waitpid");
			exit(1);
		}
	}
	E(close(cfd));
	exit(0);
}
