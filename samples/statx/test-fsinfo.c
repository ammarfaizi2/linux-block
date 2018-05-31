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
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/fsinfo.h>
#include <linux/socket.h>
#include <sys/stat.h>

static __attribute__((unused))
ssize_t fsinfo(int dfd, const char *filename, struct fsinfo_params *params,
	       void *buffer, size_t buf_size)
{
	return syscall(__NR_fsinfo, dfd, filename, params, buffer, buf_size);
}

#define FSINFO_STRING(N)	 [fsinfo_attr_##N] = 0x00
#define FSINFO_STRUCT(N)	 [fsinfo_attr_##N] = sizeof(struct fsinfo_##N)/sizeof(__u32)
#define FSINFO_STRING_N(N)	 [fsinfo_attr_##N] = 0x40
#define FSINFO_STRUCT_N(N)	 [fsinfo_attr_##N] = 0x40 | sizeof(struct fsinfo_##N)/sizeof(__u32)
#define FSINFO_STRUCT_NM(N)	 [fsinfo_attr_##N] = 0x80 | sizeof(struct fsinfo_##N)/sizeof(__u32)
static const __u8 fsinfo_buffer_sizes[fsinfo_attr__nr] = {
	FSINFO_STRUCT		(statfs),
	FSINFO_STRUCT		(fsinfo),
	FSINFO_STRUCT		(ids),
	FSINFO_STRUCT		(limits),
	FSINFO_STRUCT		(supports),
	FSINFO_STRUCT		(capabilities),
	FSINFO_STRUCT		(timestamp_info),
	FSINFO_STRING		(volume_id),
	FSINFO_STRUCT		(volume_uuid),
	FSINFO_STRING		(volume_name),
	FSINFO_STRING		(cell_name),
	FSINFO_STRING		(domain_name),
	FSINFO_STRING		(realm_name),
	FSINFO_STRING_N		(server_name),
	FSINFO_STRUCT_NM	(server_address),
	FSINFO_STRING_N		(parameter),
	FSINFO_STRING_N		(source),
	FSINFO_STRING		(name_encoding),
	FSINFO_STRING		(name_codepage),
	FSINFO_STRUCT		(io_size),
};

#define FSINFO_NAME(N) [fsinfo_attr_##N] = #N
static const char *fsinfo_attr_names[fsinfo_attr__nr] = {
	FSINFO_NAME(statfs),
	FSINFO_NAME(fsinfo),
	FSINFO_NAME(ids),
	FSINFO_NAME(limits),
	FSINFO_NAME(supports),
	FSINFO_NAME(capabilities),
	FSINFO_NAME(timestamp_info),
	FSINFO_NAME(volume_id),
	FSINFO_NAME(volume_uuid),
	FSINFO_NAME(volume_name),
	FSINFO_NAME(cell_name),
	FSINFO_NAME(domain_name),
	FSINFO_NAME(realm_name),
	FSINFO_NAME(server_name),
	FSINFO_NAME(server_address),
	FSINFO_NAME(parameter),
	FSINFO_NAME(source),
	FSINFO_NAME(name_encoding),
	FSINFO_NAME(name_codepage),
	FSINFO_NAME(io_size),
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
	struct fsinfo_server_address srv_addr;
	struct fsinfo_io_size io_size;
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

static void dump_attr_statfs(union reply *r, int size)
{
	struct fsinfo_statfs *f = &r->statfs;

	printf("\n");
	printf("\tblocks: n=%llu fr=%llu av=%llu\n",
	       (unsigned long long)f->f_blocks,
	       (unsigned long long)f->f_bfree,
	       (unsigned long long)f->f_bavail);

	printf("\tfiles : n=%llu fr=%llu av=%llu\n",
	       (unsigned long long)f->f_files,
	       (unsigned long long)f->f_ffree,
	       (unsigned long long)f->f_favail);
	printf("\tbsize : %u\n", f->f_bsize);
	printf("\tfrsize: %u\n", f->f_frsize);
}

static void dump_attr_fsinfo(union reply *r, int size)
{
	struct fsinfo_fsinfo *f = &r->fsinfo;

	printf("max_attr=%u max_cap=%u\n", f->max_attr, f->max_cap);
}

static void dump_attr_ids(union reply *r, int size)
{
	struct fsinfo_ids *f = &r->ids;

	printf("\n");
	printf("\tdev   : %02x:%02x\n", f->f_dev_major, f->f_dev_minor);
	printf("\tfs    : type=%x name=%s\n", f->f_fstype, f->f_fs_name);
	printf("\tflags : %llx\n", (unsigned long long)f->f_flags);
	printf("\tfsid  : %llx\n", (unsigned long long)f->f_fsid);
}

static void dump_attr_limits(union reply *r, int size)
{
	struct fsinfo_limits *f = &r->limits;

	printf("\n");
	printf("\tmax file size: %llx\n", f->max_file_size);
	printf("\tmax ids      : u=%llx g=%llx p=%llx\n",
	       f->max_uid, f->max_gid, f->max_projid);
	printf("\tmax dev      : maj=%x min=%x\n",
	       f->max_dev_major, f->max_dev_minor);
	printf("\tmax links    : %x\n", f->max_hard_links);
	printf("\tmax xattr    : n=%x b=%x\n",
	       f->max_xattr_name_len, f->max_xattr_body_len);
	printf("\tmax len      : file=%x sym=%x\n",
	       f->max_filename_len, f->max_symlink_len);
}

static void dump_attr_supports(union reply *r, int size)
{
	struct fsinfo_supports *f = &r->supports;

	printf("\n");
	printf("\tstx_attr=%llx\n", f->stx_attributes);
	printf("\tstx_mask=%x\n", f->stx_mask);
	printf("\tioc_flags=%x\n", f->ioc_flags);
	printf("\twin_fattrs=%x\n", f->win_file_attrs);
}

#define FSINFO_CAP_NAME(C) [fsinfo_cap_##C] = #C
static const char *fsinfo_cap_names[fsinfo_cap__nr] = {
	FSINFO_CAP_NAME(is_kernel_fs),
	FSINFO_CAP_NAME(is_block_fs),
	FSINFO_CAP_NAME(is_flash_fs),
	FSINFO_CAP_NAME(is_network_fs),
	FSINFO_CAP_NAME(is_automounter_fs),
	FSINFO_CAP_NAME(automounts),
	FSINFO_CAP_NAME(adv_locks),
	FSINFO_CAP_NAME(mand_locks),
	FSINFO_CAP_NAME(leases),
	FSINFO_CAP_NAME(uids),
	FSINFO_CAP_NAME(gids),
	FSINFO_CAP_NAME(projids),
	FSINFO_CAP_NAME(id_names),
	FSINFO_CAP_NAME(id_guids),
	FSINFO_CAP_NAME(windows_attrs),
	FSINFO_CAP_NAME(user_quotas),
	FSINFO_CAP_NAME(group_quotas),
	FSINFO_CAP_NAME(project_quotas),
	FSINFO_CAP_NAME(xattrs),
	FSINFO_CAP_NAME(journal),
	FSINFO_CAP_NAME(data_is_journalled),
	FSINFO_CAP_NAME(o_sync),
	FSINFO_CAP_NAME(o_direct),
	FSINFO_CAP_NAME(volume_id),
	FSINFO_CAP_NAME(volume_uuid),
	FSINFO_CAP_NAME(volume_name),
	FSINFO_CAP_NAME(volume_fsid),
	FSINFO_CAP_NAME(cell_name),
	FSINFO_CAP_NAME(domain_name),
	FSINFO_CAP_NAME(realm_name),
	FSINFO_CAP_NAME(iver_all_change),
	FSINFO_CAP_NAME(iver_data_change),
	FSINFO_CAP_NAME(iver_mono_incr),
	FSINFO_CAP_NAME(symlinks),
	FSINFO_CAP_NAME(hard_links),
	FSINFO_CAP_NAME(hard_links_1dir),
	FSINFO_CAP_NAME(device_files),
	FSINFO_CAP_NAME(unix_specials),
	FSINFO_CAP_NAME(resource_forks),
	FSINFO_CAP_NAME(name_case_indep),
	FSINFO_CAP_NAME(name_non_utf8),
	FSINFO_CAP_NAME(name_has_codepage),
	FSINFO_CAP_NAME(sparse),
	FSINFO_CAP_NAME(not_persistent),
	FSINFO_CAP_NAME(no_unix_mode),
	FSINFO_CAP_NAME(has_atime),
	FSINFO_CAP_NAME(has_btime),
	FSINFO_CAP_NAME(has_ctime),
	FSINFO_CAP_NAME(has_mtime),
};

static void dump_attr_capabilities(union reply *r, int size)
{
	struct fsinfo_capabilities *f = &r->caps;
	int i;

	for (i = 0; i < sizeof(f->capabilities); i++)
		printf("%02x", f->capabilities[i]);
	printf("\n");
	for (i = 0; i < fsinfo_cap__nr; i++)
		if (f->capabilities[i / 8] & (1 << (i % 8)))
			printf("\t- %s\n", fsinfo_cap_names[i]);
}

static void dump_attr_timestamp_info(union reply *r, int size)
{
	struct fsinfo_timestamp_info *f = &r->timestamps;

	printf("range=%llx-%llx\n",
	       (unsigned long long)f->minimum_timestamp,
	       (unsigned long long)f->maximum_timestamp);

#define print_time(G) \
	printf("\t"#G"time : gran=%gs\n",			\
	       (f->G##time_gran_mantissa *		\
		pow(10., f->G##time_gran_exponent)))
	print_time(a);
	print_time(b);
	print_time(c);
	print_time(m);
}

static void dump_attr_volume_uuid(union reply *r, int size)
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

static void dump_attr_server_address(union reply *r, int size)
{
	struct fsinfo_server_address *f = &r->srv_addr;

	printf("family=%u\n", f->address.ss_family);
}

static void dump_attr_io_size(union reply *r, int size)
{
	struct fsinfo_io_size *f = &r->io_size;

	printf("dio_size=%u\n", f->dio_size_gran);
}

/*
 *
 */
typedef void (*dumper_t)(union reply *r, int size);

#define FSINFO_DUMPER(N) [fsinfo_attr_##N] = dump_attr_##N
static const dumper_t fsinfo_attr_dumper[fsinfo_attr__nr] = {
	FSINFO_DUMPER(statfs),
	FSINFO_DUMPER(fsinfo),
	FSINFO_DUMPER(ids),
	FSINFO_DUMPER(limits),
	FSINFO_DUMPER(supports),
	FSINFO_DUMPER(capabilities),
	FSINFO_DUMPER(timestamp_info),
	FSINFO_DUMPER(volume_uuid),
	FSINFO_DUMPER(server_address),
	FSINFO_DUMPER(io_size),
};

static void dump_fsinfo(enum fsinfo_attribute attr, __u8 about,
			union reply *r, int size)
{
	dumper_t dumper = fsinfo_attr_dumper[attr];
	unsigned int len;

	if (!dumper) {
		printf("<no dumper>\n");
		return;
	}

	len = (about & 0x3f) * sizeof(__u32);
	if (size < len) {
		printf("<short data %u/%u>\n", size, len);
		return;
	}

	dumper(r, size);
}

/*
 * Try one subinstance of an attribute.
 */
static int try_one(const char *file, struct fsinfo_params *params, bool raw)
{
	union reply r;
	char *p;
	int ret;
	__u8 about;

	memset(&r.buffer, 0xbd, sizeof(r.buffer));

	errno = 0;
	ret = fsinfo(AT_FDCWD, file, params, r.buffer, sizeof(r.buffer));
	if (params->request >= fsinfo_attr__nr) {
		if (ret == -1 && errno == EOPNOTSUPP)
			exit(0);
		fprintf(stderr, "Unexpected error for too-large command %u: %m\n",
			params->request);
		exit(1);
	}

	//printf("fsinfo(%s,%s,%u,%u) = %d: %m\n",
	//       file, fsinfo_attr_names[params->request],
	//       params->Nth, params->Mth, ret);

	about = fsinfo_buffer_sizes[params->request];
	if (ret == -1) {
		if (errno == ENODATA) {
			switch (about & 0xc0) {
			case 0x00:
				if (params->Nth == 0 && params->Mth == 0) {
					fprintf(stderr,
						"Unexpected ENODATA1 (%u[%u][%u])\n",
						params->request, params->Nth, params->Mth);
					exit(1);
				}
				break;
			case 0x40:
				if (params->Nth == 0 && params->Mth == 0) {
					fprintf(stderr,
						"Unexpected ENODATA2 (%u[%u][%u])\n",
						params->request, params->Nth, params->Mth);
					exit(1);
				}
				break;
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
		dump_hex((unsigned int *)&r.buffer, 0, ret);
		return 0;
	}

	switch (about & 0xc0) {
	case 0x00:
		printf("\e[33m%s\e[m: ",
		       fsinfo_attr_names[params->request]);
		break;
	case 0x40:
		printf("\e[33m%s[%u]\e[m: ",
		       fsinfo_attr_names[params->request],
		       params->Nth);
		break;
	case 0x80:
		printf("\e[33m%s[%u][%u]\e[m: ",
		       fsinfo_attr_names[params->request],
		       params->Nth, params->Mth);
		break;
	}

	switch (about) {
		/* Struct */
	case 0x01 ... 0x3f:
	case 0x41 ... 0x7f:
	case 0x81 ... 0xbf:
		dump_fsinfo(params->request, about, &r, ret);
		return 0;

		/* String */
	case 0x00:
	case 0x40:
	case 0x80:
		if (ret >= 4096) {
			ret = 4096;
			r.buffer[4092] = '.';
			r.buffer[4093] = '.';
			r.buffer[4094] = '.';
			r.buffer[4095] = 0;
		} else {
			r.buffer[ret] = 0;
		}
		for (p = r.buffer; *p; p++) {
			if (!isprint(*p)) {
				printf("<non-printable>\n");
				continue;
			}
		}
		printf("%s\n", r.buffer);
		return 0;

	default:
		fprintf(stderr, "Fishy about %u %02x\n", params->request, about);
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

	while ((opt = getopt(argc, argv, "alr"))) {
		switch (opt) {
		case 'a':
			params.at_flags |= AT_NO_AUTOMOUNT;
			continue;
		case 'l':
			params.at_flags &= ~AT_SYMLINK_NOFOLLOW;
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
		printf("Format: test-fsinfo [-alr] <file>\n");
		exit(2);
	}

	for (attr = 0; attr <= fsinfo_attr__nr; attr++) {
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
