/* Filesystem parameter description and parser
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_FS_PARSER_H
#define _LINUX_FS_PARSER_H

#include <linux/fs_context.h>

struct path;

struct constant_table {
	const char	*name;
	int		value;
};

/*
 * The type of parameter expected.
 */
enum fs_parameter_type {
	__fs_param_wasnt_defined,
	fs_param_is_flag,
	fs_param_is_bool,
	fs_param_is_u32,
	fs_param_is_u32_octal,
	fs_param_is_u32_hex,
	fs_param_is_s32,
	fs_param_is_u64,
	fs_param_is_enum,
	fs_param_is_string,
	fs_param_is_blob,
	fs_param_is_blockdev,
	fs_param_is_path,
	fs_param_is_fd,
	nr__fs_parameter_type,
};

/*
 * Specification of the type of value a parameter wants.
 *
 * Note that the fsparam_flag(), fsparam_string(), fsparam_u32(), ... macros
 * should be used to generate elements of this type.
 */
struct fs_parameter_spec {
	const char		*name;
	u8			opt;	/* Option number (returned by fs_parse()) */
	enum fs_parameter_type	type:8;	/* The desired parameter type */
	unsigned short		flags;
#define fs_param_v_optional	0x0001	/* The value is optional */
#define fs_param_neg_with_no	0x0002	/* "noxxx" is negative param */
#define fs_param_neg_with_empty	0x0004	/* "xxx=" is negative param */
#define fs_param_deprecated	0x0008	/* The param is deprecated */
};

struct fs_parameter_enum {
	u8		opt;		/* Option number (as fs_parameter_spec::opt) */
	char		name[14];
	u8		value;
};

struct fs_parameter_description {
	const char	name[16];		/* Name for logging purposes */
	const struct fs_parameter_spec *specs;	/* List of param specifications */
	const struct fs_parameter_enum *enums;	/* Enum values */
};

/*
 * Result of parse.
 */
struct fs_parse_result {
	bool			negated;	/* T if param was "noxxx" */
	bool			has_value;	/* T if value supplied to param */
	union {
		bool		boolean;	/* For spec_bool */
		int		int_32;		/* For spec_s32/spec_enum */
		unsigned int	uint_32;	/* For spec_u32{,_octal,_hex}/spec_enum */
		u64		uint_64;	/* For spec_u64 */
	};
};

extern int fs_parse(struct fs_context *fc,
		    const struct fs_parameter_description *desc,
		    struct fs_parameter *value,
		    struct fs_parse_result *result);
extern int fs_lookup_param(struct fs_context *fc,
			   struct fs_parameter *param,
			   bool want_bdev,
			   struct path *_path);

extern int __lookup_constant(const struct constant_table tbl[], size_t tbl_size,
			     const char *name, int not_found);
#define lookup_constant(t, n, nf) __lookup_constant(t, ARRAY_SIZE(t), (n), (nf))

#ifdef CONFIG_VALIDATE_FS_PARSER
extern bool validate_constant_table(const struct constant_table *tbl, size_t tbl_size,
				    int low, int high, int special);
extern bool fs_validate_description(const struct fs_parameter_description *desc);
#else
static inline bool validate_constant_table(const struct constant_table *tbl, size_t tbl_size,
					   int low, int high, int special)
{ return true; }
static inline bool fs_validate_description(const struct fs_parameter_description *desc)
{ return true; }
#endif

/*
 * Utility macro to allow varargs macros to be productive in themselves rather
 * than merely being used to wrap a varargs function.
 */
#define __wrap19(Q,A, ...)	A
#define __wrap18(Q,A, ...)	A __wrap19(Q, _##Q##__VA_ARGS__)
#define __wrap17(Q,A, ...)	A __wrap18(Q, _##Q##__VA_ARGS__)
#define __wrap16(Q,A, ...)	A __wrap17(Q, _##Q##__VA_ARGS__)
#define __wrap15(Q,A, ...)	A __wrap16(Q, _##Q##__VA_ARGS__)
#define __wrap14(Q,A, ...)	A __wrap15(Q, _##Q##__VA_ARGS__)
#define __wrap13(Q,A, ...)	A __wrap14(Q, _##Q##__VA_ARGS__)
#define __wrap12(Q,A, ...)	A __wrap13(Q, _##Q##__VA_ARGS__)
#define __wrap11(Q,A, ...)	A __wrap12(Q, _##Q##__VA_ARGS__)
#define __wrap10(Q,A, ...)	A __wrap11(Q, _##Q##__VA_ARGS__)
#define __wrap09(Q,A, ...)	A __wrap10(Q, _##Q##__VA_ARGS__)
#define __wrap08(Q,A, ...)	A __wrap09(Q, _##Q##__VA_ARGS__)
#define __wrap07(Q,A, ...)	A __wrap08(Q, _##Q##__VA_ARGS__)
#define __wrap06(Q,A, ...)	A __wrap07(Q, _##Q##__VA_ARGS__)
#define __wrap05(Q,A, ...)	A __wrap06(Q, _##Q##__VA_ARGS__)
#define __wrap04(Q,A, ...)	A __wrap05(Q, _##Q##__VA_ARGS__)
#define __wrap03(Q,A, ...)	A __wrap04(Q, _##Q##__VA_ARGS__)
#define __wrap02(Q,A, ...)	A __wrap03(Q, _##Q##__VA_ARGS__)
#define __wrap01(Q,A, ...)	A __wrap02(Q, _##Q##__VA_ARGS__)
#define __wrap00(Q,A, ...)	A __wrap01(Q, _##Q##__VA_ARGS__)
#define __wrap(Q, ...)		  __wrap00(Q, _##Q##__VA_ARGS__)

/*
 * Hooks for __wrap() to OR together a list of parameter flags
 */
#define _fsp_flag_
#define _fsp_flag_NEGATE_WITH_NO	| fs_param_neg_with_no
#define _fsp_flag_NEGATE_WITH_EMPTY	| fs_param_neg_with_empty
#define _fsp_flag_OPTIONAL		| fs_param_v_optional
#define _fsp_flag_IS_DEPRECATED		| fs_param_deprecated

/*
 * Parameter type, name, index and flags element constructors.  Use as:
 *
 *  fsparam_xxxx("foo", Opt_foo[,NEGATE_WITH_NO][,NEGATE_WITH_EMPTY][,OPTIONAL][,DEPRECATED])
 */
#define __fsparam(TYPE, NAME, OPT, ...) \
	{ \
		.name = NAME, \
		.opt = OPT, \
		.type = TYPE, \
		.flags = 0 __wrap(fsp_flag_, __VA_ARGS__) \
	}

#define fsparam_flag(NAME, OPT, ...)	__fsparam(fs_param_is_flag, NAME, OPT, ## __VA_ARGS__)
#define fsparam_bool(NAME, OPT, ...)	__fsparam(fs_param_is_bool, NAME, OPT, ## __VA_ARGS__)
#define fsparam_u32(NAME, OPT, ...)	__fsparam(fs_param_is_u32, NAME, OPT, ## __VA_ARGS__)
#define fsparam_u32oct(NAME, OPT, ...)	__fsparam(fs_param_is_u32_octal, NAME, OPT, ## __VA_ARGS__)
#define fsparam_u32hex(NAME, OPT, ...)	__fsparam(fs_param_is_u32_hex, NAME, OPT, ## __VA_ARGS__)
#define fsparam_s32(NAME, OPT, ...)	__fsparam(fs_param_is_s32, NAME, OPT, ## __VA_ARGS__)
#define fsparam_u64(NAME, OPT, ...)	__fsparam(fs_param_is_u64, NAME, OPT, ## __VA_ARGS__)
#define fsparam_enum(NAME, OPT, ...)	__fsparam(fs_param_is_enum, NAME, OPT, ## __VA_ARGS__)
#define fsparam_string(NAME, OPT, ...)	__fsparam(fs_param_is_string, NAME, OPT, ## __VA_ARGS__)
#define fsparam_blob(NAME, OPT, ...)	__fsparam(fs_param_is_blob, NAME, OPT, ## __VA_ARGS__)
#define fsparam_bdev(NAME, OPT, ...)	__fsparam(fs_param_is_blockdev, NAME, OPT, ## __VA_ARGS__)
#define fsparam_path(NAME, OPT, ...)	__fsparam(fs_param_is_path, NAME, OPT, ## __VA_ARGS__)
#define fsparam_fd(NAME, OPT, ...)	__fsparam(fs_param_is_fd, NAME, OPT, ## __VA_ARGS__)


#endif /* _LINUX_FS_PARSER_H */
