/* Test the fsinfo() system call
 *
 * Copyright (C) 2015 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define _GNU_SOURCE
#define _ATFILE_SOURCE
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
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <sys/stat.h>

#define __NR_fsinfo 326

static __attribute__((unused))
ssize_t fsinfo(int dfd, const char *filename, unsigned flags,
	       unsigned request, void *buffer)
{
	return syscall(__NR_fsinfo, dfd, filename, flags, request, buffer);
}

static void dump_fsinfo(struct fsinfo *f)
{
	printf("mask  : %x\n", f->f_mask);
	printf("dev   : %02x:%02x\n", f->f_dev_major, f->f_dev_minor);
	printf("fs    : type=%x name=%s\n", f->f_fstype, f->f_fs_name);
	printf("ioc   : %llx\n", (unsigned long long)f->f_supported_ioc_flags);
	printf("nameln: %u\n", f->f_namelen);
	printf("flags : %llx\n", (unsigned long long)f->f_flags);
	printf("times : range=%llx-%llx\n",
	       (unsigned long long)f->f_min_time,
	       (unsigned long long)f->f_max_time);

#define print_time(G) \
	printf(#G"time : gran=%gs\n",			\
	       (f->f_##G##time_gran_mantissa *		\
		pow(10., f->f_##G##time_gran_exponent)))
	print_time(a);
	print_time(b);
	print_time(c);
	print_time(m);


	if (f->f_mask & FSINFO_BLOCKS_INFO)
		printf("blocks: n=%llu fr=%llu av=%llu\n",
		       (unsigned long long)f->f_blocks,
		       (unsigned long long)f->f_bfree,
		       (unsigned long long)f->f_bavail);

	if (f->f_mask & FSINFO_FILES_INFO)
		printf("files : n=%llu fr=%llu av=%llu\n",
		       (unsigned long long)f->f_files,
		       (unsigned long long)f->f_ffree,
		       (unsigned long long)f->f_favail);

	if (f->f_mask & FSINFO_BSIZE)
		printf("bsize : %u\n", f->f_bsize);

	if (f->f_mask & FSINFO_FRSIZE)
		printf("frsize: %u\n", f->f_frsize);

	if (f->f_mask & FSINFO_FSID)
		printf("fsid  : %llx\n", (unsigned long long)f->f_fsid);

	if (f->f_mask & FSINFO_VOLUME_ID) {
		int printable = 1, loop;
		printf("volid : ");
		for (loop = 0; loop < sizeof(f->f_volume_id); loop++)
			if (!isprint(f->f_volume_id[loop]))
				printable = 0;
		if (printable) {
			printf("'%.*s'", 16, f->f_volume_id);
		} else {
			for (loop = 0; loop < sizeof(f->f_volume_id); loop++) {
				if (loop % 4 == 0 && loop != 0)
					printf(" ");
				printf("%02x", f->f_volume_id[loop]);
			}
		}
		printf("\n");
	}

	if (f->f_mask & FSINFO_VOLUME_UUID)
		printf("uuid  : "
		       "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
		       "-%02x%02x%02x%02x%02x%02x\n",
		       f->f_volume_uuid[ 0], f->f_volume_uuid[ 1],
		       f->f_volume_uuid[ 2], f->f_volume_uuid[ 3],
		       f->f_volume_uuid[ 4], f->f_volume_uuid[ 5],
		       f->f_volume_uuid[ 6], f->f_volume_uuid[ 7],
		       f->f_volume_uuid[ 8], f->f_volume_uuid[ 9],
		       f->f_volume_uuid[10], f->f_volume_uuid[11],
		       f->f_volume_uuid[12], f->f_volume_uuid[13],
		       f->f_volume_uuid[14], f->f_volume_uuid[15]);
	if (f->f_mask & FSINFO_VOLUME_NAME)
		printf("volume: '%s'\n", f->f_volume_name);
	if (f->f_mask & FSINFO_DOMAIN_NAME)
		printf("domain: '%s'\n", f->f_domain_name);
}

static void dump_hex(unsigned long long *data, int from, int to)
{
	unsigned offset, print_offset = 1, col = 0;

	from /= 8;
	to = (to + 7) / 8;

	for (offset = from; offset < to; offset++) {
		if (print_offset) {
			printf("%04x: ", offset * 8);
			print_offset = 0;
		}
		printf("%016llx", data[offset]);
		col++;
		if ((col & 3) == 0) {
			printf("\n");
			print_offset = 1;
		} else {
			printf(" ");
		}
	}

	if (!print_offset)
		printf("\n");
}

int main(int argc, char **argv)
{
	struct fsinfo f;
	int ret, raw = 0, atflag = AT_SYMLINK_NOFOLLOW;

	for (argv++; *argv; argv++) {
		if (strcmp(*argv, "-F") == 0) {
			atflag |= AT_FORCE_ATTR_SYNC;
			continue;
		}
		if (strcmp(*argv, "-L") == 0) {
			atflag &= ~AT_SYMLINK_NOFOLLOW;
			continue;
		}
		if (strcmp(*argv, "-A") == 0) {
			atflag |= AT_NO_AUTOMOUNT;
			continue;
		}
		if (strcmp(*argv, "-R") == 0) {
			raw = 1;
			continue;
		}

		memset(&f, 0xbd, sizeof(f));
		ret = fsinfo(AT_FDCWD, *argv, atflag, 0, &f);
		printf("fsinfo(%s) = %d\n", *argv, ret);
		if (ret < 0) {
			perror(*argv);
			exit(1);
		}

		if (raw)
			dump_hex((unsigned long long *)&f, 0, sizeof(f));

		dump_fsinfo(&f);
	}
	return 0;
}
