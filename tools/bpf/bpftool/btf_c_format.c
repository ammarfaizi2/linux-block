// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2019 Mellanox */

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uapi/linux/btf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include "main.h"

/* supported int types */
static int btf_int2c_check(const struct btf_type *t)
{
	 /* Bitfields are not supported for now */
	if (BTF_INT_OFFSET(t->info))
		return EINVAL;

	 /* bool is not supported for now */
	if (BTF_INT_ENCODING(t->info) == BTF_INT_BOOL)
		return EINVAL;

	if (BTF_INT_ENCODING(t->info) == BTF_INT_CHAR)
		return t->size == 1 ? 0 : EINVAL;

	return 0;
}

#define BTF_C_MAX_TYPE_SZIE 32

static void btf_int2c_str(const struct btf_type *t, char *str)
{
	unsigned char ts;

	if (BTF_INT_ENCODING(t->info) == BTF_INT_CHAR) {
		snprintf(str, BTF_C_MAX_TYPE_SZIE, "char");
		return;
	}
	ts = t->size * 8;

	/* e.g: __u32 */
	snprintf(str, BTF_C_MAX_TYPE_SZIE, "__u%d", ts);
}

static void btf_struct2c_str(const struct btf *btf, const struct btf_type *t, char *str)
{
	const char *tname = btf__name_by_offset(btf, t->name_off);

	snprintf(str, BTF_C_MAX_TYPE_SZIE, "%s %s",
		 BTF_INFO_KIND(t->info) == BTF_KIND_UNION ? "union" : "struct",
		 tname);
}

static void btf_type2c_str(const struct btf *btf, const struct btf_type *t, char *str)
{
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_INT:
		btf_int2c_str(t, str);
		return;
	case BTF_KIND_ENUM:
		snprintf(str, BTF_C_MAX_TYPE_SZIE,
			 "enum %s", btf__name_by_offset(btf, t->name_off));
		return;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		btf_struct2c_str(btf, t, str);
		return;
	default:
		snprintf(str, BTF_C_MAX_TYPE_SZIE,
			 "<anon> %s", btf__name_by_offset(btf, t->name_off));
		return;
	}
}

static int btf_int2c(const struct btf *btf, struct btf_type *t)
{
	const char *tname = btf__name_by_offset(btf, t->name_off);
	int err = btf_int2c_check(t);
	char ctype[BTF_C_MAX_TYPE_SZIE];

	if (err) {
		fprintf(stderr,
			"unsupported BTF_KIND_INT (%s) info: 0x%x, size %d, offset: %d, bits: %d\n",
			tname, t->info, t->size, BTF_INT_OFFSET(t->info), BTF_INT_BITS(t->info));
		return err;
	}

	if (!strcmp(tname, "\0"))
		return 0;
	/* name is valid, typedef */
	btf_int2c_str(t, ctype);
	fprintf(stdout, "typedef %s %s;\n", ctype, tname);
	return 0;
}

static int btf_struct_member_2c(const struct btf *btf, struct btf_member *m)
{
	const char *mname = btf__name_by_offset(btf, m->name_off);
	const struct btf_type *t = btf__type_by_id(btf, m->type);
	char ctype[BTF_C_MAX_TYPE_SZIE];

	btf_type2c_str(btf, t, ctype);
	fprintf(stdout, "\t%s %s;\n", ctype, mname);
	return 0;
}

static int btf_struct2c(const struct btf *btf, struct btf_type *t)
{
	struct btf_member *m = (struct btf_member *)(t + 1);
	__u16 vlen = BTF_INFO_VLEN(t->info);
	char ctype[BTF_C_MAX_TYPE_SZIE];
	int i, err;

	btf_struct2c_str(btf, t, ctype);

	fprintf(stdout, "%s {\n", ctype);

	for (i = 0; i < vlen; i++) {
		err = btf_struct_member_2c(btf, m);
		if (err)
			return err;
		m++;
	}
	fprintf(stdout, "};\n");
	return 0;
}

static int btf_enum2c(const struct btf *btf, struct btf_type *t)
{
	const char *tname = btf__name_by_offset(btf, t->name_off);
	struct btf_enum *m = (struct btf_enum *)(t + 1);
	__u16 vlen = BTF_INFO_VLEN(t->info);
	int i;

	fprintf(stdout, "enum %s {\n", tname);
	for (i = 0; i < vlen; i++) {
		fprintf(stdout, "\t%s = %d,\n", btf__name_by_offset(btf, m->name_off), m->val);
		m++;
	}
	fprintf(stdout, "};\n");
	return 0;
}

static int btf_type2c(struct btf *btf, struct btf_type *t)
{
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_INT:
		return btf_int2c(btf, t);
	case BTF_KIND_ENUM:
		return btf_enum2c(btf, t);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return btf_struct2c(btf, t);
	default:
		fprintf(stderr, "Unsupported BTF_KIND:%u\n", BTF_INFO_KIND(t->info));
		return EINVAL;
	}
}

int btf_dump_c_format(struct btf *btf)
{
	return btf__walk_types(btf, btf_type2c);
}
