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

static bool debug = 0;

static __attribute__((unused))
ssize_t fsinfo(int dfd, const char *filename, struct fsinfo_params *params,
	       void *buffer, size_t buf_size)
{
	return syscall(__NR_fsinfo, dfd, filename, params, buffer, buf_size);
}

struct fsinfo_attr_info {
	unsigned char	type;
	unsigned char	flags;
	unsigned short	size;
};

#define __FSINFO_STRUCT		0
#define __FSINFO_STRING		1
#define __FSINFO_OVER		2
#define __FSINFO_STRUCT_ARRAY	3
#define __FSINFO_0		0
#define __FSINFO_N		0x0001
#define __FSINFO_NM		0x0002

#define _Z(T, F, S) { .type = __FSINFO_##T, .flags = __FSINFO_##F, .size = S }
#define FSINFO_STRING(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRING, 0, 0)
#define FSINFO_STRUCT(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRUCT, 0, sizeof(struct fsinfo_##Y))
#define FSINFO_STRING_N(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRING, N, 0)
#define FSINFO_STRUCT_N(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRUCT, N, sizeof(struct fsinfo_##Y))
#define FSINFO_STRING_NM(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRING, NM, 0)
#define FSINFO_STRUCT_NM(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRUCT, NM, sizeof(struct fsinfo_##Y))
#define FSINFO_OVERLARGE(X,Y)	 [FSINFO_ATTR_##X] = _Z(OVER, 0, 0)
#define FSINFO_STRUCT_ARRAY(X,Y) [FSINFO_ATTR_##X] = _Z(STRUCT_ARRAY, 0, sizeof(struct fsinfo_##Y))

static const struct fsinfo_attr_info fsinfo_buffer_info[FSINFO_ATTR__NR] = {
	FSINFO_STRUCT		(STATFS,		statfs),
	FSINFO_STRUCT		(FSINFO,		fsinfo),
	FSINFO_STRUCT		(IDS,			ids),
	FSINFO_STRUCT		(LIMITS,		limits),
	FSINFO_STRUCT		(CAPABILITIES,		capabilities),
	FSINFO_STRUCT		(SUPPORTS,		supports),
	FSINFO_STRUCT		(TIMESTAMP_INFO,	timestamp_info),
	FSINFO_STRING		(VOLUME_ID,		volume_id),
	FSINFO_STRUCT		(VOLUME_UUID,		volume_uuid),
	FSINFO_STRING		(VOLUME_NAME,		volume_name),
	FSINFO_STRING		(NAME_ENCODING,		name_encoding),
	FSINFO_STRING		(NAME_CODEPAGE,		name_codepage),
	FSINFO_STRUCT		(PARAM_DESCRIPTION,	param_description),
	FSINFO_STRUCT_N		(PARAM_SPECIFICATION,	param_specification),
	FSINFO_STRUCT_N		(PARAM_ENUM,		param_enum),
	FSINFO_OVERLARGE	(PARAMETERS,		-),
	FSINFO_OVERLARGE	(LSM_PARAMETERS,	-),
	FSINFO_STRUCT		(MOUNT_INFO,		mount_info),
	FSINFO_STRING		(MOUNT_DEVNAME,		mount_devname),
	FSINFO_STRUCT_ARRAY	(MOUNT_CHILDREN,	mount_child),
	FSINFO_STRING_N		(MOUNT_SUBMOUNT,	mount_submount),
	FSINFO_STRING_N		(SERVER_NAME,		server_name),
	FSINFO_STRUCT_NM	(SERVER_ADDRESS,	server_address),
	FSINFO_STRING		(CELL_NAME,		cell_name),
	FSINFO_STRUCT		(SB_NOTIFICATIONS,	sb_notifications),
};

#define FSINFO_NAME(X,Y) [FSINFO_ATTR_##X] = #Y
static const char *fsinfo_attr_names[FSINFO_ATTR__NR] = {
	FSINFO_NAME		(STATFS,		statfs),
	FSINFO_NAME		(FSINFO,		fsinfo),
	FSINFO_NAME		(IDS,			ids),
	FSINFO_NAME		(LIMITS,		limits),
	FSINFO_NAME		(CAPABILITIES,		capabilities),
	FSINFO_NAME		(SUPPORTS,		supports),
	FSINFO_NAME		(TIMESTAMP_INFO,	timestamp_info),
	FSINFO_NAME		(VOLUME_ID,		volume_id),
	FSINFO_NAME		(VOLUME_UUID,		volume_uuid),
	FSINFO_NAME		(VOLUME_NAME,		volume_name),
	FSINFO_NAME		(NAME_ENCODING,		name_encoding),
	FSINFO_NAME		(NAME_CODEPAGE,		name_codepage),
	FSINFO_NAME		(PARAM_DESCRIPTION,	param_description),
	FSINFO_NAME		(PARAM_SPECIFICATION,	param_specification),
	FSINFO_NAME		(PARAM_ENUM,		param_enum),
	FSINFO_NAME		(PARAMETERS,		parameters),
	FSINFO_NAME		(LSM_PARAMETERS,	lsm_parameters),
	FSINFO_NAME		(MOUNT_INFO,		mount_info),
	FSINFO_NAME		(MOUNT_DEVNAME,		mount_devname),
	FSINFO_NAME		(MOUNT_CHILDREN,	mount_children),
	FSINFO_NAME		(MOUNT_SUBMOUNT,	mount_submount),
	FSINFO_NAME		(SERVER_NAME,		server_name),
	FSINFO_NAME		(SERVER_ADDRESS,	server_address),
	FSINFO_NAME		(CELL_NAME,		cell_name),
	FSINFO_NAME		(SB_NOTIFICATIONS,	sb_notifications),
};

union reply {
	char buffer[4096];
	struct fsinfo_statfs statfs;
	struct fsinfo_fsinfo fsinfo;
	struct fsinfo_ids ids;
	struct fsinfo_limits limits;
	struct fsinfo_supports supports;
	struct fsinfo_capabilities caps;
	struct fsinfo_timestamp_info timestamps;
	struct fsinfo_volume_uuid uuid;
	struct fsinfo_mount_info mount_info;
	struct fsinfo_mount_child mount_children[1];
	struct fsinfo_server_address srv_addr;
	struct fsinfo_sb_notifications sb_notifications;
};

static void dump_hex(unsigned int *data, int from, int to)
{
	unsigned offset, print_offset = 1, col = 0;

	from /= 4;
	to = (to + 3) / 4;

	for (offset = from; offset < to; offset++) {
		if (print_offset) {
			printf("%04x: ", offset * 8);
			print_offset = 0;
		}
		printf("%08x", data[offset]);
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

static void dump_attr_STATFS(union reply *r, int size)
{
	struct fsinfo_statfs *f = &r->statfs;

	printf("\n");
	printf("\tblocks: n=%llu fr=%llu av=%llu\n",
	       (unsigned long long)f->f_blocks.lo,
	       (unsigned long long)f->f_bfree.lo,
	       (unsigned long long)f->f_bavail.lo);

	printf("\tfiles : n=%llu fr=%llu av=%llu\n",
	       (unsigned long long)f->f_files.lo,
	       (unsigned long long)f->f_ffree.lo,
	       (unsigned long long)f->f_favail.lo);
	printf("\tbsize : %llu\n", f->f_bsize);
	printf("\tfrsize: %llu\n", f->f_frsize);
	printf("\tmntfl : %llx\n", (unsigned long long)f->mnt_attrs);
}

static void dump_attr_FSINFO(union reply *r, int size)
{
	struct fsinfo_fsinfo *f = &r->fsinfo;

	printf("max_attr=%u max_cap=%u\n", f->max_attr, f->max_cap);
}

static void dump_attr_IDS(union reply *r, int size)
{
	struct fsinfo_ids *f = &r->ids;

	printf("\n");
	printf("\tdev   : %02x:%02x\n", f->f_dev_major, f->f_dev_minor);
	printf("\tfs    : type=%x name=%s\n", f->f_fstype, f->f_fs_name);
	printf("\tfsid  : %llx\n", (unsigned long long)f->f_fsid);
	printf("\tsbid  : %llx\n", (unsigned long long)f->f_sb_id);
}

static void dump_attr_LIMITS(union reply *r, int size)
{
	struct fsinfo_limits *f = &r->limits;

	printf("\n");
	printf("\tmax file size: %llx%016llx\n",
	       (unsigned long long)f->max_file_size.hi,
	       (unsigned long long)f->max_file_size.lo);
	printf("\tmax ino:       %llx%016llx\n",
	       (unsigned long long)f->max_ino.hi,
	       (unsigned long long)f->max_ino.lo);
	printf("\tmax ids      : u=%llx g=%llx p=%llx\n",
	       (unsigned long long)f->max_uid,
	       (unsigned long long)f->max_gid,
	       (unsigned long long)f->max_projid);
	printf("\tmax dev      : maj=%x min=%x\n",
	       f->max_dev_major, f->max_dev_minor);
	printf("\tmax links    : %llx\n",
	       (unsigned long long)f->max_hard_links);
	printf("\tmax xattr    : n=%x b=%llx\n",
	       f->max_xattr_name_len,
	       (unsigned long long)f->max_xattr_body_len);
	printf("\tmax len      : file=%x sym=%x\n",
	       f->max_filename_len, f->max_symlink_len);
}

static void dump_attr_SUPPORTS(union reply *r, int size)
{
	struct fsinfo_supports *f = &r->supports;

	printf("\n");
	printf("\tstx_attr=%llx\n", (unsigned long long)f->stx_attributes);
	printf("\tstx_mask=%x\n", f->stx_mask);
	printf("\tioc_flags=%x\n", f->ioc_flags);
	printf("\twin_fattrs=%x\n", f->win_file_attrs);
}

#define FSINFO_CAP_NAME(C) [FSINFO_CAP_##C] = #C
static const char *fsinfo_cap_names[FSINFO_CAP__NR] = {
	FSINFO_CAP_NAME(IS_KERNEL_FS),
	FSINFO_CAP_NAME(IS_BLOCK_FS),
	FSINFO_CAP_NAME(IS_FLASH_FS),
	FSINFO_CAP_NAME(IS_NETWORK_FS),
	FSINFO_CAP_NAME(IS_AUTOMOUNTER_FS),
	FSINFO_CAP_NAME(IS_MEMORY_FS),
	FSINFO_CAP_NAME(AUTOMOUNTS),
	FSINFO_CAP_NAME(ADV_LOCKS),
	FSINFO_CAP_NAME(MAND_LOCKS),
	FSINFO_CAP_NAME(LEASES),
	FSINFO_CAP_NAME(UIDS),
	FSINFO_CAP_NAME(GIDS),
	FSINFO_CAP_NAME(PROJIDS),
	FSINFO_CAP_NAME(STRING_USER_IDS),
	FSINFO_CAP_NAME(GUID_USER_IDS),
	FSINFO_CAP_NAME(WINDOWS_ATTRS),
	FSINFO_CAP_NAME(USER_QUOTAS),
	FSINFO_CAP_NAME(GROUP_QUOTAS),
	FSINFO_CAP_NAME(PROJECT_QUOTAS),
	FSINFO_CAP_NAME(XATTRS),
	FSINFO_CAP_NAME(JOURNAL),
	FSINFO_CAP_NAME(DATA_IS_JOURNALLED),
	FSINFO_CAP_NAME(O_SYNC),
	FSINFO_CAP_NAME(O_DIRECT),
	FSINFO_CAP_NAME(VOLUME_ID),
	FSINFO_CAP_NAME(VOLUME_UUID),
	FSINFO_CAP_NAME(VOLUME_NAME),
	FSINFO_CAP_NAME(VOLUME_FSID),
	FSINFO_CAP_NAME(IVER_ALL_CHANGE),
	FSINFO_CAP_NAME(IVER_DATA_CHANGE),
	FSINFO_CAP_NAME(IVER_MONO_INCR),
	FSINFO_CAP_NAME(DIRECTORIES),
	FSINFO_CAP_NAME(SYMLINKS),
	FSINFO_CAP_NAME(HARD_LINKS),
	FSINFO_CAP_NAME(HARD_LINKS_1DIR),
	FSINFO_CAP_NAME(DEVICE_FILES),
	FSINFO_CAP_NAME(UNIX_SPECIALS),
	FSINFO_CAP_NAME(RESOURCE_FORKS),
	FSINFO_CAP_NAME(NAME_CASE_INDEP),
	FSINFO_CAP_NAME(NAME_NON_UTF8),
	FSINFO_CAP_NAME(NAME_HAS_CODEPAGE),
	FSINFO_CAP_NAME(SPARSE),
	FSINFO_CAP_NAME(NOT_PERSISTENT),
	FSINFO_CAP_NAME(NO_UNIX_MODE),
	FSINFO_CAP_NAME(HAS_ATIME),
	FSINFO_CAP_NAME(HAS_BTIME),
	FSINFO_CAP_NAME(HAS_CTIME),
	FSINFO_CAP_NAME(HAS_MTIME),
};

static void dump_attr_CAPABILITIES(union reply *r, int size)
{
	struct fsinfo_capabilities *f = &r->caps;
	int i;

	for (i = 0; i < sizeof(f->capabilities); i++)
		printf("%02x", f->capabilities[i]);
	printf("\n");
	for (i = 0; i < FSINFO_CAP__NR; i++)
		if (f->capabilities[i / 8] & (1 << (i % 8)))
			printf("\t- %s\n", fsinfo_cap_names[i]);
}

static void print_time(struct fsinfo_timestamp_one *t, char stamp)
{
	printf("\t%ctime : gran=%gs range=%llx-%llx\n",
	       stamp,
	       t->gran_mantissa * pow(10., t->gran_exponent),
	       (long long)t->minimum,
	       (long long)t->maximum);
}

static void dump_attr_TIMESTAMP_INFO(union reply *r, int size)
{
	struct fsinfo_timestamp_info *f = &r->timestamps;

	printf("\n");
	print_time(&f->atime, 'a');
	print_time(&f->mtime, 'm');
	print_time(&f->ctime, 'c');
	print_time(&f->btime, 'b');
}

static void dump_attr_VOLUME_UUID(union reply *r, int size)
{
	struct fsinfo_volume_uuid *f = &r->uuid;

	printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
	       "-%02x%02x%02x%02x%02x%02x\n",
	       f->uuid[ 0], f->uuid[ 1],
	       f->uuid[ 2], f->uuid[ 3],
	       f->uuid[ 4], f->uuid[ 5],
	       f->uuid[ 6], f->uuid[ 7],
	       f->uuid[ 8], f->uuid[ 9],
	       f->uuid[10], f->uuid[11],
	       f->uuid[12], f->uuid[13],
	       f->uuid[14], f->uuid[15]);
}

static void dump_attr_SERVER_ADDRESS(union reply *r, int size)
{
	struct fsinfo_server_address *f = &r->srv_addr;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	char buf[1024];

	switch (f->address.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)&f->address;
		if (!inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)))
			break;
		printf("IPv4: %s\n", buf);
		return;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)&f->address;
		if (!inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)))
			break;
		printf("IPv6: %s\n", buf);
		return;
	}

	printf("family=%u\n", f->address.ss_family);
}

static void dump_attr_MOUNT_INFO(union reply *r, int size)
{
	struct fsinfo_mount_info *f = &r->mount_info;

	printf("\n");
	printf("\tsb_id   : %llx\n", (unsigned long long)f->f_sb_id);
	printf("\tmnt_id  : %x\n", f->mnt_id);
	printf("\tparent  : %x\n", f->parent_id);
	printf("\tgroup   : %x\n", f->group_id);
	printf("\tattr    : %x\n", f->attr);
	printf("\tnotifs  : %x\n", f->notify_counter);
}

static void dump_attr_MOUNT_CHILDREN(union reply *r, int size)
{
	struct fsinfo_mount_child *f = r->mount_children;
	int i = 0;

	printf("\n");
	for (; size >= sizeof(*f); size -= sizeof(*f), f++)
		printf("\t[%u] %8x %8x\n", i++, f->mnt_id, f->notify_counter);
}

static void dump_attr_SB_NOTIFICATIONS(union reply *r, int size)
{
	struct fsinfo_sb_notifications *f = &r->sb_notifications;

	printf("\n");
	printf("\twatch_id: %llx\n", (unsigned long long)f->watch_id);
	printf("\tnotifs  : %llx\n", (unsigned long long)f->notify_counter);
}

/*
 *
 */
typedef void (*dumper_t)(union reply *r, int size);

#define FSINFO_DUMPER(N) [FSINFO_ATTR_##N] = dump_attr_##N
static const dumper_t fsinfo_attr_dumper[FSINFO_ATTR__NR] = {
	FSINFO_DUMPER(STATFS),
	FSINFO_DUMPER(FSINFO),
	FSINFO_DUMPER(IDS),
	FSINFO_DUMPER(LIMITS),
	FSINFO_DUMPER(SUPPORTS),
	FSINFO_DUMPER(CAPABILITIES),
	FSINFO_DUMPER(TIMESTAMP_INFO),
	FSINFO_DUMPER(VOLUME_UUID),
	FSINFO_DUMPER(MOUNT_INFO),
	FSINFO_DUMPER(MOUNT_CHILDREN),
	FSINFO_DUMPER(SERVER_ADDRESS),
	FSINFO_DUMPER(SB_NOTIFICATIONS),
};

static void dump_fsinfo(enum fsinfo_attribute attr,
			struct fsinfo_attr_info about,
			union reply *r, int size)
{
	dumper_t dumper = fsinfo_attr_dumper[attr];
	unsigned int len;

	if (!dumper) {
		printf("<no dumper>\n");
		return;
	}

	len = about.size;
	if (about.type == __FSINFO_STRUCT && size < len) {
		printf("<short data %u/%u>\n", size, len);
		return;
	}

	dumper(r, size);
}

static void dump_params(struct fsinfo_attr_info about, union reply *r, int size)
{
	int len;
	char *p = r->buffer, *e = p + size;
	bool is_key = true;

	while (p < e) {
		len = 0;
		while (p[0] & 0x80) {
			len <<= 7;
			len |= *p++ & 0x7f;
		}

		len <<= 7;
		len |= *p++;
		if (len > e - p)
			break;
		if (is_key || len)
			printf("%s%*.*s", is_key ? "[PARM] " : "= ", len, len, p);
		if (is_key)
			putchar(' ');
		else
			putchar('\n');
		p += len;
		is_key = !is_key;
	}
}

/*
 * Try one subinstance of an attribute.
 */
static int try_one(const char *file, struct fsinfo_params *params, bool raw)
{
	struct fsinfo_attr_info about;
	union reply *r;
	size_t buf_size = 4096;
	char *p;
	int ret;

	for (;;) {
		r = malloc(buf_size);
		if (!r) {
			perror("malloc");
			exit(1);
		}
		memset(r->buffer, 0xbd, buf_size);

		errno = 0;
		ret = fsinfo(AT_FDCWD, file, params, r->buffer, buf_size);
		if (params->request >= FSINFO_ATTR__NR) {
			if (ret == -1 && errno == EOPNOTSUPP)
				exit(0);
			fprintf(stderr, "Unexpected error for too-large command %u: %m\n",
				params->request);
			exit(1);
		}
		if (ret == -1)
			break;

		if (ret <= buf_size)
			break;
		buf_size = (ret + 4096 - 1) & ~(4096 - 1);
	}

	if (debug)
		printf("fsinfo(%s,%s,%u,%u) = %d: %m\n",
		       file, fsinfo_attr_names[params->request],
		       params->Nth, params->Mth, ret);

	about = fsinfo_buffer_info[params->request];
	if (ret == -1) {
		if (errno == ENODATA) {
			if (!(about.flags & (__FSINFO_N | __FSINFO_NM)) &&
			    params->Nth == 0 && params->Mth == 0) {
				fprintf(stderr,
					"Unexpected ENODATA (%u[%u][%u])\n",
					params->request, params->Nth, params->Mth);
				exit(1);
			}
			return (params->Mth == 0) ? 2 : 1;
		}
		if (errno == EOPNOTSUPP) {
			if (params->Nth > 0 || params->Mth > 0) {
				fprintf(stderr,
					"Should return -ENODATA (%u[%u][%u])\n",
					params->request, params->Nth, params->Mth);
				exit(1);
			}
			//printf("\e[33m%s\e[m: <not supported>\n",
			//       fsinfo_attr_names[attr]);
			return 2;
		}
		perror(file);
		exit(1);
	}

	if (raw) {
		if (ret > 4096)
			ret = 4096;
		dump_hex((unsigned int *)r->buffer, 0, ret);
		return 0;
	}

	switch (params->request) {
	case FSINFO_ATTR_PARAMETERS:
	case FSINFO_ATTR_LSM_PARAMETERS:
		if (ret == 0)
			return 0;
	}

	switch (about.flags & (__FSINFO_N | __FSINFO_NM)) {
	case 0:
		printf("\e[33m%s\e[m: ",
		       fsinfo_attr_names[params->request]);
		break;
	case __FSINFO_N:
		printf("\e[33m%s[%u]\e[m: ",
		       fsinfo_attr_names[params->request],
		       params->Nth);
		break;
	case __FSINFO_NM:
		printf("\e[33m%s[%u][%u]\e[m: ",
		       fsinfo_attr_names[params->request],
		       params->Nth, params->Mth);
		break;
	}

	switch (about.type) {
	case __FSINFO_STRUCT:
		dump_fsinfo(params->request, about, r, ret);
		return 0;

	case __FSINFO_STRING:
		if (ret >= 4096) {
			ret = 4096;
			r->buffer[4092] = '.';
			r->buffer[4093] = '.';
			r->buffer[4094] = '.';
			r->buffer[4095] = 0;
		} else {
			r->buffer[ret] = 0;
		}
		for (p = r->buffer; *p; p++) {
			if (!isprint(*p)) {
				printf("<non-printable>\n");
				continue;
			}
		}
		printf("%s\n", r->buffer);
		return 0;

	case __FSINFO_OVER:
		if (params->request == FSINFO_ATTR_PARAMETERS ||
		    params->request == FSINFO_ATTR_LSM_PARAMETERS)
			dump_params(about, r, ret);
		return 0;

	case __FSINFO_STRUCT_ARRAY:
		dump_fsinfo(params->request, about, r, ret);
		return 0;

	default:
		fprintf(stderr, "Fishy about %u %u,%u,%u\n",
			params->request, about.type, about.flags, about.size);
		exit(1);
	}
}

/*
 *
 */
int main(int argc, char **argv)
{
	struct fsinfo_params params = {
		.at_flags = AT_SYMLINK_NOFOLLOW,
	};
	unsigned int attr;
	int raw = 0, opt, Nth, Mth;

	while ((opt = getopt(argc, argv, "Madlr"))) {
		switch (opt) {
		case 'M':
			params.at_flags = AT_FSINFO_MOUNTID_PATH;
			continue;
		case 'a':
			params.at_flags |= AT_NO_AUTOMOUNT;
			params.at_flags &= ~AT_FSINFO_MOUNTID_PATH;
			continue;
		case 'd':
			debug = true;
			continue;
		case 'l':
			params.at_flags &= ~AT_SYMLINK_NOFOLLOW;
			params.at_flags &= ~AT_FSINFO_MOUNTID_PATH;
			continue;
		case 'r':
			raw = 1;
			continue;
		}
		break;
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		printf("Format: test-fsinfo [-adlr] <file>\n");
		printf("Format: test-fsinfo [-dr] -M <mnt_id>\n");
		exit(2);
	}

	for (attr = 0; attr <= FSINFO_ATTR__NR; attr++) {
		switch (attr) {
		case FSINFO_ATTR_PARAM_DESCRIPTION:
		case FSINFO_ATTR_PARAM_SPECIFICATION:
		case FSINFO_ATTR_PARAM_ENUM:
			/* See test-fs-query.c instead */
			continue;
		}

		Nth = 0;
		do {
			Mth = 0;
			do {
				params.request = attr;
				params.Nth = Nth;
				params.Mth = Mth;

				switch (try_one(argv[0], &params, raw)) {
				case 0:
					continue;
				case 1:
					goto done_M;
				case 2:
					goto done_N;
				}
			} while (++Mth < 100);

		done_M:
			if (Mth >= 100) {
				fprintf(stderr, "Fishy: Mth == %u\n", Mth);
				break;
			}

		} while (++Nth < 100);

	done_N:
		if (Nth >= 100) {
			fprintf(stderr, "Fishy: Nth == %u\n", Nth);
			break;
		}
	}

	return 0;
}
