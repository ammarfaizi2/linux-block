/* Test the fsinfo() system call
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define _GNU_SOURCE
#define _ATFILE_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <sys/syscall.h>
#include <linux/fsinfo.h>
#include <linux/socket.h>
#include <linux/fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#ifndef __NR_fsinfo
#define __NR_fsinfo -1
#endif

static __attribute__((unused))
ssize_t fsinfo(int dfd, const char *filename, struct fsinfo_params *params,
	       void *buffer, size_t buf_size)
{
	return syscall(__NR_fsinfo, dfd, filename, params, buffer, buf_size);
}

static char tree_buf[4096];
static char bar_buf[4096];

/*
 * Get an fsinfo attribute in a statically allocated buffer.
 */
static void get_attr(unsigned int mnt_id, enum fsinfo_attribute attr,
		     void *buf, size_t buf_size)
{
	struct fsinfo_params params = {
		.at_flags	= AT_FSINFO_MOUNTID_PATH,
		.request	= attr,
	};
	char file[32];
	long ret;

	sprintf(file, "%u", mnt_id);

	memset(buf, 0xbd, buf_size);

	ret = fsinfo(AT_FDCWD, file, &params, buf, buf_size);
	if (ret == -1) {
		fprintf(stderr, "mount-%s: %m\n", file);
		exit(1);
	}
}

/*
 * Get an fsinfo attribute in a dynamically allocated buffer.
 */
static void *get_attr_alloc(unsigned int mnt_id, enum fsinfo_attribute attr,
			    unsigned int Nth, size_t *_size)
{
	struct fsinfo_params params = {
		.at_flags	= AT_FSINFO_MOUNTID_PATH,
		.request	= attr,
		.Nth		= Nth,
	};
	size_t buf_size = 4096;
	char file[32];
	void *r;
	long ret;

	sprintf(file, "%u", mnt_id);

	for (;;) {
		r = malloc(buf_size);
		if (!r) {
			perror("malloc");
			exit(1);
		}
		memset(r, 0xbd, buf_size);

		ret = fsinfo(AT_FDCWD, file, &params, r, buf_size);
		if (ret == -1) {
			fprintf(stderr, "mount-%s: %m\n", file);
			exit(1);
		}

		if (ret <= buf_size) {
			*_size = ret;
			break;
		}
		buf_size = (ret + 4096 - 1) & ~(4096 - 1);
	}

	return r;
}

/*
 * Display a mount and then recurse through its children.
 */
static void display_mount(unsigned int mnt_id, unsigned int depth, char *path)
{
	struct fsinfo_mount_child *children;
	struct fsinfo_mount_info info;
	struct fsinfo_ids ids;
	unsigned int d;
	size_t ch_size, p_size;
	int i, n, s;

	get_attr(mnt_id, FSINFO_ATTR_MOUNT_INFO, &info, sizeof(info));
	get_attr(mnt_id, FSINFO_ATTR_IDS, &ids, sizeof(ids));
	if (depth > 0)
		printf("%s", tree_buf);

	s = strlen(path);
	printf("%s", !s ? "\"\"" : path);
	if (!s)
		s += 2;
	s += depth;
	if (s < 38)
		s = 38 - s;
	else
		s = 1;
	printf("%*.*s", s, s, "");

	printf("%10u %10u %s %x:%x",
	       info.mnt_id, info.notify_counter,
	       ids.f_fs_name, ids.f_dev_major, ids.f_dev_minor);
	putchar('\n');

	children = get_attr_alloc(mnt_id, FSINFO_ATTR_MOUNT_CHILDREN, 0, &ch_size);
	n = ch_size / sizeof(children[0]) - 1;

	bar_buf[depth + 1] = '|';
	if (depth > 0) {
		tree_buf[depth - 4 + 1] = bar_buf[depth - 4 + 1];
		tree_buf[depth - 4 + 2] = ' ';
	}

	tree_buf[depth + 0] = ' ';
	tree_buf[depth + 1] = '\\';
	tree_buf[depth + 2] = '_';
	tree_buf[depth + 3] = ' ';
	tree_buf[depth + 4] = 0;
	d = depth + 4;

	for (i = 0; i < n; i++) {
		if (i == n - 1)
			bar_buf[depth + 1] = ' ';
		path = get_attr_alloc(mnt_id, FSINFO_ATTR_MOUNT_SUBMOUNT, i, &p_size);
		display_mount(children[i].mnt_id, d, path + 1);
		free(path);
	}

	free(children);
	if (depth > 0) {
		tree_buf[depth - 4 + 1] = '\\';
		tree_buf[depth - 4 + 2] = '_';
	}
	tree_buf[depth] = 0;
}

/*
 * Find the ID of whatever is at the nominated path.
 */
static unsigned int lookup_mnt_by_path(const char *path)
{
	struct fsinfo_mount_info mnt;
	struct fsinfo_params params = {
		.request = FSINFO_ATTR_MOUNT_INFO,
	};

	if (fsinfo(AT_FDCWD, path, &params, &mnt, sizeof(mnt)) == -1) {
		perror(path);
		exit(1);
	}

	return mnt.mnt_id;
}

/*
 *
 */
int main(int argc, char **argv)
{
	unsigned int mnt_id;
	char *path;
	bool use_mnt_id = false;
	int opt;

	while ((opt = getopt(argc, argv, "M"))) {
		switch (opt) {
		case 'M':
			use_mnt_id = true;
			continue;
		}
		break;
	}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 0:
		mnt_id = lookup_mnt_by_path("/");
		path = "ROOT";
		break;
	case 1:
		path = argv[0];
		if (use_mnt_id) {
			mnt_id = strtoul(argv[0], NULL, 0);
			break;
		}

		mnt_id = lookup_mnt_by_path(argv[0]);
		break;
	default:
		printf("Format: test-mntinfo\n");
		printf("Format: test-mntinfo <path>\n");
		printf("Format: test-mntinfo -M <mnt_id>\n");
		exit(2);
	}

	printf("MOUNT                                 MOUNT ID   NOTIFY#    TYPE & DEVICE\n");
	printf("------------------------------------- ---------- ---------- ---------------\n");
	display_mount(mnt_id, 0, path);
	return 0;
}
