// SPDX-License-Identifier: GPL-2.0
/*
 * Filesystem parameterisation.
 *
 * Copyright (C) 2007 Oracle.  All rights reserved.
 * Copyright (C) 2018 Red Hat, Inc.  All rights reserved.
 */

#include <linux/mount.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include "ctree.h"
#include "volumes.h"
#include "btrfs_inode.h"
#include "rcu-string.h"

enum btrfs_param {
	Opt_acl,
	Opt_alloc_start,
	Opt_autodefrag,
	Opt_barrier,
	Opt_check_integrity,
	Opt_check_integrity_including_extent_data,
	Opt_check_integrity_print_mask,
	Opt_clear_cache,
	Opt_commit_interval,
	Opt_compress,
	Opt_compress_force,
	Opt_datacow,
	Opt_datasum,
	Opt_degraded,
	Opt_device,
	Opt_discard,
	Opt_enospc_debug,
	Opt_fatal_errors,
	Opt_flushoncommit,
	Opt_fragment,
	Opt_inode_cache,
	Opt_max_inline,
	Opt_metadata_ratio,
	Opt_nologreplay,
	Opt_nossd,
	Opt_recovery,
	Opt_ref_verify,
	Opt_rescan_uuid_tree,
	Opt_skip_balance,
	Opt_source,
	Opt_space_cache,
	Opt_ssd,
	Opt_ssd_spread,
	Opt_subvol,
	Opt_subvolid,
	Opt_subvolrootid,
	Opt_thread_pool,
	Opt_treelog,
	Opt_usebackuproot,
	Opt_user_subvol_rm_allowed,
	nr__btrfs_params
};

enum {
	Opt_compress__zlib	= 0, /* Arg is optional; default is 0 */
	Opt_compress__zlib_1,
	Opt_compress__zlib_2,
	Opt_compress__zlib_3,
	Opt_compress__zlib_4,
	Opt_compress__zlib_5,
	Opt_compress__zlib_6,
	Opt_compress__zlib_7,
	Opt_compress__zlib_8,
	Opt_compress__zlib_9,
	Opt_compress__lzo,
	Opt_compress__zstd,
	Opt_compress__no,
};

enum btrfs_space_cache {
	Opt_space_cache__v1	= 0,	/* Arg is optional; default is 0 */
	Opt_space_cache__v2,
	Opt_space_cache__no,
};

enum {
	Opt_fatal_errors__bug,
	Opt_fatal_errors__panic,
};

enum {
	Opt_fragment__all,
	Opt_fragment__data,
	Opt_fragment__metadata,
};

static const struct fs_parameter_spec btrfs_param_specs[] = {
	fsparam_flag_no("acl",			Opt_acl),
	__fsparam(fs_param_is_string, "alloc_start", Opt_alloc_start,
		  fs_param_deprecated),
	fsparam_flag_no("autodefrag",		Opt_autodefrag),
	fsparam_flag_no("barrier",		Opt_barrier),
	fsparam_flag  ("check_int",		Opt_check_integrity),
	fsparam_flag  ("check_int_data",	Opt_check_integrity_including_extent_data),
	fsparam_u32   ("check_int_print_mask",	Opt_check_integrity_print_mask),
	fsparam_flag  ("clear_cache",		Opt_clear_cache),
	fsparam_u32   ("commit",		Opt_commit_interval),
	__fsparam(fs_param_is_enum, "compress",	Opt_compress,
		  fs_param_v_optional),
	__fsparam(fs_param_is_enum, "compress-force", Opt_compress_force,
		  fs_param_v_optional),
	fsparam_flag_no("datacow",		Opt_datacow),
	fsparam_flag_no("datasum",		Opt_datasum),
	fsparam_flag  ("degraded",		Opt_degraded),
	fsparam_string("device",		Opt_device),
	fsparam_flag_no("discard",		Opt_discard),
	fsparam_flag_no("enospc_debug",		Opt_enospc_debug),
	fsparam_enum  ("fatal_errors",		Opt_fatal_errors),
	fsparam_flag_no("flushoncommit",	Opt_flushoncommit),
	fsparam_enum  ("fragment",		Opt_fragment),
	fsparam_flag_no("inode_cache",		Opt_inode_cache),
	fsparam_string("max_inline",		Opt_max_inline),
	fsparam_u32   ("metadata_ratio",	Opt_metadata_ratio),
	fsparam_flag  ("nologreplay",		Opt_nologreplay),
	fsparam_flag  ("nossd",			Opt_nossd),
	fsparam_flag_no("recovery",		Opt_recovery),
	fsparam_flag  ("ref_verify",		Opt_ref_verify),
	fsparam_flag  ("rescan_uuid_tree",	Opt_rescan_uuid_tree),
	fsparam_flag  ("skip_balance",		Opt_skip_balance),
	fsparam_string("source",		Opt_source),
	__fsparam(fs_param_is_enum, "space_cache", Opt_space_cache,
		  fs_param_neg_with_no|fs_param_v_optional),
	fsparam_flag  ("ssd",			Opt_ssd),
	fsparam_flag  ("ssd_spread",		Opt_ssd_spread),
	__fsparam(fs_param_is_string, "subvol", Opt_subvol,
		  fs_param_v_optional),
	fsparam_u64   ("subvolid",		Opt_subvolid),
	__fsparam(fs_param_is_s32, "subvolrootid", Opt_subvolrootid,
		  fs_param_deprecated),
	fsparam_u32   ("thread_pool",		Opt_thread_pool),
	fsparam_flag_no("treelog",		Opt_treelog),
	fsparam_flag  ("usebackuproot",		Opt_usebackuproot),
	fsparam_flag  ("user_subvol_rm_allowed", Opt_user_subvol_rm_allowed),
	{}
};

static const struct fs_parameter_enum btrfs_param_enums[] = {
	{ Opt_fragment,		"all",		Opt_fragment__all },
	{ Opt_fragment,		"data",		Opt_fragment__data },
	{ Opt_fragment,		"metadata",	Opt_fragment__metadata },
	{ Opt_compress,		"zlib",		Opt_compress__zlib },
	{ Opt_compress,		"zlib:1",	Opt_compress__zlib_1 },
	{ Opt_compress,		"zlib:2",	Opt_compress__zlib_2 },
	{ Opt_compress,		"zlib:3",	Opt_compress__zlib_3 },
	{ Opt_compress,		"zlib:4",	Opt_compress__zlib_4 },
	{ Opt_compress,		"zlib:5",	Opt_compress__zlib_5 },
	{ Opt_compress,		"zlib:6",	Opt_compress__zlib_6 },
	{ Opt_compress,		"zlib:7",	Opt_compress__zlib_7 },
	{ Opt_compress,		"zlib:8",	Opt_compress__zlib_8 },
	{ Opt_compress,		"zlib:9",	Opt_compress__zlib_9 },
	{ Opt_compress,		"lzo",		Opt_compress__lzo },
	{ Opt_compress,		"zstd",		Opt_compress__zstd },
	{ Opt_compress,		"no",		Opt_compress__no },
	{ Opt_compress_force,	"zlib",		Opt_compress__zlib },
	{ Opt_compress_force,	"zlib:1",	Opt_compress__zlib_1 },
	{ Opt_compress_force,	"zlib:2",	Opt_compress__zlib_2 },
	{ Opt_compress_force,	"zlib:3",	Opt_compress__zlib_3 },
	{ Opt_compress_force,	"zlib:4",	Opt_compress__zlib_4 },
	{ Opt_compress_force,	"zlib:5",	Opt_compress__zlib_5 },
	{ Opt_compress_force,	"zlib:6",	Opt_compress__zlib_6 },
	{ Opt_compress_force,	"zlib:7",	Opt_compress__zlib_7 },
	{ Opt_compress_force,	"zlib:8",	Opt_compress__zlib_8 },
	{ Opt_compress_force,	"zlib:9",	Opt_compress__zlib_9 },
	{ Opt_compress_force,	"lzo",		Opt_compress__lzo },
	{ Opt_compress_force,	"zstd",		Opt_compress__zstd },
	{ Opt_compress_force,	"no",		Opt_compress__no },
	{ Opt_space_cache,	"v1",		Opt_space_cache__v1 },
	{ Opt_space_cache,	"v2",		Opt_space_cache__v2 },
	{ Opt_fatal_errors,	"bug",		Opt_fatal_errors__bug },
	{ Opt_fatal_errors,	"panic",	Opt_fatal_errors__panic },
	{}
};

const struct fs_parameter_description btrfs_fs_parameters = {
	.name		= "btrfs",
	.specs		= btrfs_param_specs,
	.enums		= btrfs_param_enums,
};

#define btrfs_mparam_set(ctx, opt)				\
	do {							\
		ctx->mount_opt |= BTRFS_MOUNT_##opt;		\
		ctx->mount_opt_mask |= BTRFS_MOUNT_##opt;	\
	} while (0)

#define btrfs_mparam_clear(ctx, opt)				\
	do {							\
		ctx->mount_opt &= ~BTRFS_MOUNT_##opt;		\
		ctx->mount_opt_mask |= BTRFS_MOUNT_##opt;	\
	} while (0)

struct btrfs_flag_map {
	u8			bit;
#define BTRFS_FLAG_MAP_PRESENT	0x80	/* There is a rule here */
};

#define mount_opt(x)     { BTRFS_MOUNT_##x | BTRFS_FLAG_MAP_PRESENT }

static const struct btrfs_flag_map btrfs_flag_map[nr__btrfs_params] = {
	[Opt_barrier]		= mount_opt(BARRIER),
	[Opt_check_integrity]	= mount_opt(CHECK_INTEGRITY),
	[Opt_check_integrity_including_extent_data] =
	mount_opt(CHECK_INTEGRITY_INCLUDING_EXTENT_DATA),
	[Opt_clear_cache]	= mount_opt(CLEAR_CACHE),
	[Opt_compress]		= mount_opt(COMPRESS),
	[Opt_compress_force]	= mount_opt(FORCE_COMPRESS),
	[Opt_datacow]		= mount_opt(DATACOW),
	[Opt_datasum]		= mount_opt(DATASUM),
	[Opt_autodefrag]		= mount_opt(AUTO_DEFRAG),
	[Opt_degraded]		= mount_opt(DEGRADED),
	[Opt_discard]		= mount_opt(DISCARD),
	[Opt_enospc_debug]	= mount_opt(ENOSPC_DEBUG),
	[Opt_flushoncommit]	= mount_opt(FLUSHONCOMMIT),
	[Opt_inode_cache]	= mount_opt(INODE_MAP_CACHE),
	[Opt_nologreplay]	= mount_opt(NOLOGREPLAY),
	[Opt_nossd]		= mount_opt(NOSSD),
	[Opt_ref_verify]	= mount_opt(REF_VERIFY),
	[Opt_rescan_uuid_tree]	= mount_opt(RESCAN_UUID_TREE),
	[Opt_skip_balance]	= mount_opt(SKIP_BALANCE),
	[Opt_ssd]		= mount_opt(SSD),
	[Opt_ssd_spread]	= mount_opt(SSD_SPREAD),
	[Opt_treelog]		= mount_opt(TREELOG),
	[Opt_usebackuproot]	= mount_opt(USEBACKUPROOT),
	[Opt_user_subvol_rm_allowed] = mount_opt(USER_SUBVOL_RM_ALLOWED),
};

/*
 * Implicit rules of option relationships.
 *
 * "implies" means turning on option $key turns on $target; turning off $target
 * turns off $key.  Note that we don't automatically calculate transitivity,
 * but rather transitive relationships must be explicitly listed.
 *
 * "contradicts" means turning on option $key turns off $target and vice versa.
 *
 * The op is mentioned specifically just in case we want to add other options
 * later.
 */
struct btrfs_implicit_rule {
	u8	key;
	u8	target;
};

#define _(key, op, target_key) { key, target_key }
static const struct btrfs_implicit_rule btrfs_opt_dependencies[] = {
	_(Opt_datasum,		DEPENDS_ON,	Opt_datacow),
	_(Opt_compress,		DEPENDS_ON,	Opt_datacow),
	_(Opt_compress,		DEPENDS_ON,	Opt_datasum),
	_(Opt_compress_force,	DEPENDS_ON,	Opt_datacow),
	_(Opt_compress_force,	DEPENDS_ON,	Opt_datasum),
	_(Opt_compress_force,	DEPENDS_ON,	Opt_compress),
	_(Opt_ssd_spread,	DEPENDS_ON,	Opt_ssd),
	_(Opt_check_integrity_including_extent_data, DEPENDS_ON, Opt_check_integrity),
};

static const struct btrfs_implicit_rule btrfs_opt_contradictions[] = {
	_(Opt_ssd,		CONTRADICTS,	Opt_nossd),
	_(Opt_ssd_spread,	CONTRADICTS,	Opt_nossd),
	_(Opt_nossd,		CONTRADICTS,	Opt_ssd),
	_(Opt_nossd,		CONTRADICTS,	Opt_ssd_spread),
};

/*
 * Parse the mount options into a summary of what is explicitly changed.
 *
 * This is slightly complicated for BtrFS compared to something like NFS as we
 * superblock creation process starts by reading the configuration from disk
 * and then applies any parameter changes on top of that.
 *
 * This means that we need to track what changes we're going to make and how
 * they interact - but we have to bear in mind that parameters are not
 * commutative.
 */
static int btrfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct btrfs_fs_context *ctx = fc->fs_private;
	unsigned int mask;
	char **devs;
	bool enabled;
	int opt, i;
	u8 bit;

	pr_notice("PARM[%s] = %s\n", param->key, param->string);

	opt = fs_parse(fc, &btrfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;
	enabled = !result.negated;
	__set_bit(opt, ctx->specified);

	/* Do some initial weeding out of options that might not be or might no
	 * longer be supported.
	 */
	switch (opt) {
	case Opt_source:
	case Opt_device:
	case Opt_subvol:
	case Opt_subvolid:
	case Opt_subvolrootid:
		if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE)
			return invalf(fc, "btrfs: %s prohibited for remount",
				      param->key);
		break;
#ifndef CONFIG_BTRFS_FS_POSIX_ACL
	case Opt_acl:
		if (!enabled)
			return 0;
		return invalf(fc, "btrfs: Support for 'acl' not compiled in!");
#endif
	case Opt_compress:
	case Opt_compress_force:
		if (result.uint_32 == Opt_compress__no) {
			result.negated = true;
			enabled = false;
		}
		break;
	case Opt_space_cache:
		if (result.negated)
			result.uint_32 = Opt_space_cache__no;
		break;
	case Opt_recovery:
		if (enabled) {
			warnf(fc, "btrfs: 'recovery' is deprecated, use 'usebackuproot' instead");
			opt = Opt_usebackuproot;
		} else {
			btrfs_set_opt(ctx->mount_opt_mask, NOLOGREPLAY);
			btrfs_set_opt(ctx->mount_opt, NOLOGREPLAY);
		}
		break;
#ifndef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	case Opt_check_integrity_including_extent_data:
	case Opt_check_integrity:
	case Opt_check_integrity_print_mask:
		return invalf(fc, "btrfs: Support for 'check_int*' not compiled in!");
#endif
#ifndef CONFIG_BTRFS_FS_REF_VERIFY
	case Opt_ref_verify:
		return 0;
#endif
#ifndef CONFIG_BTRFS_DEBUG
	case Opt_fragment:
		return invalf(fc, "btrfs: Support for 'fragment' not compiled in!");
#endif
	}

	/* Map simple option-switching flags into 1-bit changes. */
	bit = btrfs_flag_map[opt].bit;
	if (bit) {
		bit &= ~BTRFS_FLAG_MAP_PRESENT;
		mask = 1 << bit;
		ctx->mount_opt_mask |= mask;
		ctx->mount_opt_explicit |= mask;
		ctx->mount_opt &= ~mask;
		if (enabled)
			ctx->mount_opt |= mask;
	}

	if (enabled) {
		/* Turn on all the options that this one depends on. */
		for (i = 0; i < ARRAY_SIZE(btrfs_opt_dependencies); i++) {
			unsigned int target = btrfs_opt_dependencies[i].target;

			if (btrfs_opt_dependencies[i].key != opt)
				continue;
			bit = btrfs_flag_map[target].bit;
			bit &= ~BTRFS_FLAG_MAP_PRESENT;
			mask = 1 << bit;
			if (!(ctx->mount_opt & mask))
				ctx->mount_opt_explicit &= ~mask;
			ctx->mount_opt_mask |= mask;
			ctx->mount_opt |= mask;
		}

		/* Turn off all contradictory options. */
		for (i = 0; i < ARRAY_SIZE(btrfs_opt_contradictions); i++) {
			unsigned int target = btrfs_opt_contradictions[i].target;

			if (btrfs_opt_contradictions[i].key != opt)
				continue;
			bit = btrfs_flag_map[target].bit;
			bit &= ~BTRFS_FLAG_MAP_PRESENT;
			mask = 1 << bit;
			if (!(ctx->mount_opt & mask))
				ctx->mount_opt_explicit &= ~mask;
			ctx->mount_opt_mask |= mask;
			ctx->mount_opt &= ~mask;
		}
	} else {
		/* Cancel all options that would implicitly turn this on */
		for (i = 0; i < ARRAY_SIZE(btrfs_opt_dependencies); i++) {
			unsigned int dep = btrfs_opt_dependencies[i].key;

			if (btrfs_opt_dependencies[i].target != opt)
				continue;
			bit = btrfs_flag_map[dep].bit;
			bit &= ~BTRFS_FLAG_MAP_PRESENT;
			mask = 1 << bit;
			if (ctx->mount_opt & mask)
				ctx->mount_opt_explicit &= ~mask;
			ctx->mount_opt_mask |= mask;
			ctx->mount_opt &= ~mask;
		}
	}

	switch (opt) {
	case Opt_source:
		if (fc->source)
			return invalf(fc, "btrfs: Multiple sources specified");
		fc->source = param->string;
		param->string = NULL;
		break;

	case Opt_device:
		devs = krealloc(ctx->devices,
				sizeof(char *) * (ctx->nr_devices + 1),
				GFP_KERNEL);
		if (!devs)
			return -ENOMEM;
		devs[ctx->nr_devices] = param->string;
		param->string = NULL;
		ctx->devices = devs;
		ctx->nr_devices++;
		break;

	case Opt_subvol:
		kfree(ctx->subvol_name);
		ctx->subvol_name = param->string; /* NULL if negative */
		param->string = NULL;
		break;
	case Opt_subvolid:
		/* we want the original fs_tree */
		if (result.uint_64 == 0)
			ctx->subvol_objectid = BTRFS_FS_TREE_OBJECTID;
		else
			ctx->subvol_objectid = result.uint_64;
		break;
	case Opt_subvolrootid:
		break;

	case Opt_compress:
	case Opt_compress_force:
		switch (result.uint_32) {
		case Opt_compress__zlib_1 ... Opt_compress__zlib_9:
			ctx->compress_type = BTRFS_COMPRESS_ZLIB;
			ctx->compress_level =
				result.uint_32 - Opt_compress__zlib_1 + 1;
			break;
		case Opt_compress__zlib:
			ctx->compress_type = BTRFS_COMPRESS_ZLIB;
			ctx->compress_level = BTRFS_ZLIB_DEFAULT_LEVEL;
			break;
		case Opt_compress__lzo:
			ctx->compress_type = BTRFS_COMPRESS_LZO;
			break;
		case Opt_compress__zstd:
			ctx->compress_type = BTRFS_COMPRESS_ZSTD;
			break;
		case Opt_compress__no:
			ctx->compress_type = BTRFS_COMPRESS_NONE;
			break;
		}
		break;

	case Opt_thread_pool:
		if (result.uint_32 == 0)
			return invalf(fc, "btrfs: %s: Bad value", param->key);
		ctx->thread_pool_size = result.uint_32;
		break;
	case Opt_max_inline:
		ctx->max_inline = memparse(param->string, NULL);
		break;
	case Opt_alloc_start:
		infof(fc, "btrfs: Option alloc_start is obsolete, ignored");
		break;
	case Opt_metadata_ratio:
		ctx->metadata_ratio = result.uint_32;
		infof(fc, "btrfs: metadata ratio %u", ctx->metadata_ratio);
		break;

	case Opt_space_cache:
		btrfs_set_opt(ctx->mount_opt_mask, SPACE_CACHE);
		btrfs_set_opt(ctx->mount_opt_mask, FREE_SPACE_TREE);
		switch (result.uint_32) {
		case Opt_space_cache__no:
			btrfs_set_opt(ctx->mount_opt_explicit, SPACE_CACHE);
			btrfs_set_opt(ctx->mount_opt_explicit, FREE_SPACE_TREE);
			btrfs_clear_opt(ctx->mount_opt, SPACE_CACHE);
			btrfs_clear_opt(ctx->mount_opt, FREE_SPACE_TREE);
			break;
		case Opt_space_cache__v1:
			btrfs_set_opt(ctx->mount_opt_explicit, SPACE_CACHE);
			btrfs_set_opt(ctx->mount_opt, SPACE_CACHE);
			btrfs_clear_opt(ctx->mount_opt_explicit, FREE_SPACE_TREE);
			btrfs_clear_opt(ctx->mount_opt, FREE_SPACE_TREE);
			break;
		case Opt_space_cache__v2:
			btrfs_clear_opt(ctx->mount_opt_explicit, SPACE_CACHE);
			btrfs_clear_opt(ctx->mount_opt, SPACE_CACHE);
			btrfs_set_opt(ctx->mount_opt_explicit, FREE_SPACE_TREE);
			btrfs_set_opt(ctx->mount_opt, FREE_SPACE_TREE);
			break;
		}
		break;

	case Opt_acl:
		if (enabled)
			fc->sb_flags |= SB_POSIXACL;
		else
			fc->sb_flags &= ~SB_POSIXACL;
		fc->sb_flags_mask |= SB_POSIXACL;
		break;

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	case Opt_check_integrity_print_mask:
		ctx->check_integrity_print_mask = result.uint_32;
		break;
#endif

	case Opt_fatal_errors:
		ctx->mount_opt_explicit |= BTRFS_MOUNT_PANIC_ON_FATAL_ERROR;
		switch (result.uint_32) {
		case Opt_fatal_errors__bug:
			ctx->mount_opt &= ~BTRFS_MOUNT_PANIC_ON_FATAL_ERROR;
			break;
		case Opt_fatal_errors__panic:
			ctx->mount_opt |= BTRFS_MOUNT_PANIC_ON_FATAL_ERROR;
			break;
		}
		break;
	case Opt_commit_interval:
		if (result.uint_32 == 0) {
			infof(fc, "btrfs: Using default commit interval %us",
			      BTRFS_DEFAULT_COMMIT_INTERVAL);
			result.uint_32 = BTRFS_DEFAULT_COMMIT_INTERVAL;
		} else if (result.uint_32 > 300) {
			warnf(fc, "btrfs: Excessive commit interval %u",
			      result.uint_32);
		}
		ctx->commit_interval = result.uint_32;
		break;

#ifdef CONFIG_BTRFS_DEBUG
	case Opt_fragment:
		mask = 0;
		switch (result.uint_32) {
		case Opt_fragment__all:
			mask  = BTRFS_MOUNT_FRAGMENT_DATA;
			mask |= BTRFS_MOUNT_FRAGMENT_METADATA;
			break;
		case Opt_fragment__metadata:
			mask = BTRFS_MOUNT_FRAGMENT_METADATA;
			break;
		case Opt_fragment__data:
			mask |= BTRFS_MOUNT_FRAGMENT_DATA;
			break;
		}
		ctx->mount_opt |= mask;
		ctx->mount_opt_mask |= mask;
		ctx->mount_opt_explicit |= mask;
		break;
#endif
	default:
		break;
	}

	return 0;
}

int btrfs_validate(struct fs_context *fc)
{
	struct btrfs_fs_context *ctx = fc->fs_private;

	if (btrfs_raw_test_opt(ctx->mount_opt_mask, NOLOGREPLAY) &&
	    btrfs_raw_test_opt(ctx->mount_opt, NOLOGREPLAY) &&
	    !(fc->sb_flags & SB_RDONLY))
		return invalf(fc, "nologreplay must be used with ro mount option");
	return 0;
}

static int btrfs_dup_context(struct fs_context *fc, struct fs_context *src_fc)
{
	struct btrfs_fs_context *ctx, *src = src_fc->fs_private;
	int i;

	ctx = kmemdup(src, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ctx->subvol_name = NULL;
	ctx->devices = NULL;
	ctx->root_mnt = NULL;

	if (src->subvol_name) {
		ctx->subvol_name = kstrdup(src->subvol_name, GFP_KERNEL);
		if (!ctx->subvol_name)
			goto nomem_ctx;
	}

	if (ctx->nr_devices) {
		ctx->devices = kcalloc(ctx->nr_devices, sizeof(char *), GFP_KERNEL);
		if (!ctx->devices)
			goto nomem_sub;
		for (i = 0; i < ctx->nr_devices; i++) {
			ctx->devices[i] = kstrdup(src->devices[i], GFP_KERNEL);
			if (!ctx->devices[i])
				goto nomem_devs;
		}
	}

	if (src_fc->source) {
		fc->source = kstrdup(src_fc->source, GFP_KERNEL);
		if (!fc->source)
			goto nomem_devs;
	}

	fc->fs_private = ctx;
	return 0;

nomem_devs:
	for (i = 0; i < ctx->nr_devices; i++)
		kfree(ctx->devices[i]);
	kfree(ctx->devices);
nomem_sub:
	kfree(ctx->subvol_name);
nomem_ctx:
	kfree(ctx);
	return -ENOMEM;
}

static void btrfs_free_context(struct fs_context *fc)
{
	struct btrfs_fs_context *ctx = fc->fs_private;
	struct btrfs_fs_info *info = fc->s_fs_info;
	int i;

	if (info)
		free_fs_info(info);
	if (ctx) {
		mntput(ctx->root_mnt);
		if (ctx->devices) {
			for (i = 0; i < ctx->nr_devices; i++)
				kfree(ctx->devices[i]);
			kfree(ctx->devices);
		}
		kfree(ctx->subvol_name);
		kfree(ctx);
	}
}

static struct fs_context_operations btrfs_context_ops = {
	.free		= btrfs_free_context,
	.dup		= btrfs_dup_context,
	.parse_param	= btrfs_parse_param,
	.get_tree	= btrfs_get_tree,
	.reconfigure	= btrfs_reconfigure,
};

/*
 * Set up the filesystem configuration context.
 */
int btrfs_init_fs_context(struct fs_context *fc)
{
	struct btrfs_fs_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	fc->ops = &btrfs_context_ops;
	fc->fs_private = ctx;
	return 0;
}

static const char *btrfs_options[32] = {
	[BTRFS_MOUNT_AUTO_DEFRAG]		= "auto defrag",
	[BTRFS_MOUNT_BARRIER]			= "barriers",
	[BTRFS_MOUNT_DATACOW]			= "datacow",
	[BTRFS_MOUNT_DATASUM]			= "datasum",
	[BTRFS_MOUNT_DEGRADED]			= "degraded mounts",
	[BTRFS_MOUNT_DISCARD]			= "discard",
	[BTRFS_MOUNT_FLUSHONCOMMIT]       	= "flush-on-commit",
	[BTRFS_MOUNT_FREE_SPACE_TREE]		= "free space tree",
	[BTRFS_MOUNT_INODE_MAP_CACHE]		= "inode map caching",
	[BTRFS_MOUNT_NOLOGREPLAY]		= "no log replay at mount time",
	[BTRFS_MOUNT_REF_VERIFY]		= "ref verification",
	[BTRFS_MOUNT_SPACE_CACHE]		= "disk space caching",
	[BTRFS_MOUNT_SSD]			= "ssd optimizations",
	[BTRFS_MOUNT_SSD_SPREAD]		= "spread ssd allocation scheme",
	[BTRFS_MOUNT_TREELOG]           	= "tree log",
};

/*
 * Apply the configuration to a superblock.
 */
void btrfs_apply_configuration(struct fs_context *fc, struct super_block *sb)
{
	struct btrfs_fs_context *ctx = fc->fs_private;
	struct btrfs_fs_info *info = sb->s_fs_info;
	unsigned int changes = (ctx->mount_opt ^ info->mount_opt) & ctx->mount_opt_mask;
	unsigned int explicit_changes = changes & ctx->mount_opt_explicit;
	unsigned int implicit_changes = changes & ~ctx->mount_opt_explicit;
	unsigned int mask, tmp;
	int i;

	for (tmp = explicit_changes; tmp; tmp &= ~(1 << i)) {
		i = __ffs(tmp);
		if (!btrfs_options[i])
			continue;
		if (ctx->mount_opt & (1 << i ))
			btrfs_info(info, "Enabling %s", btrfs_options[i]);
		else
			btrfs_info(info, "Disabling %s", btrfs_options[i]);
	}

	for (tmp = implicit_changes; tmp; tmp &= ~(1 << i)) {
		i = __ffs(tmp);
		if (!btrfs_options[i])
			continue;
		if (ctx->mount_opt & (1 << i ))
			btrfs_info(info, "Implicitly enabling %s", btrfs_options[i]);
		else
			btrfs_info(info, "Implicitly disabling %s", btrfs_options[i]);
	}

	if (btrfs_raw_test_opt(changes, COMPRESS) ||
	    btrfs_raw_test_opt(changes, FORCE_COMPRESS)) {
		if (btrfs_raw_test_opt(ctx->mount_opt, COMPRESS))
			btrfs_info(info, "Enabling %s%s compression, level %d",
				   btrfs_raw_test_opt(changes, FORCE_COMPRESS) ?
				   "Forced " : "",
				   btrfs_compress_type2str(ctx->compress_type),
				   ctx->compress_level);
		else if (btrfs_raw_test_opt(explicit_changes, COMPRESS))
			btrfs_info(info, "Disabling compression");
		else
			btrfs_info(info, "Implicitly disabling compression");
	}

	if (test_bit(Opt_max_inline, ctx->specified)) {
		u64 max_inline = min_t(u64, ctx->max_inline, info->sectorsize);

		ctx->max_inline = max_inline;
		if (max_inline != info->max_inline)
			btrfs_info(info, "max_inline at %llu", ctx->max_inline);
	}

	if (test_bit(Opt_metadata_ratio, ctx->specified) &&
	    ctx->metadata_ratio != info->metadata_ratio)
		btrfs_info(info, "Metadata ratio %u", info->metadata_ratio);

	if (btrfs_raw_test_opt(ctx->mount_opt & explicit_changes, CLEAR_CACHE))
		btrfs_info(info, "Force clearing of disk cache");
	if (btrfs_raw_test_opt(ctx->mount_opt & explicit_changes, USEBACKUPROOT))
		btrfs_info(info, "Trying to use backup root at mount time");

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	switch (ctx->mount_opt & explicit_changes &
		((1 << BTRFS_MOUNT_CHECK_INTEGRITY) |
		 (1 << BTRFS_MOUNT_CHECK_INTEGRITY_INCLUDING_EXTENT_DATA))) {
	case (1 << BTRFS_MOUNT_CHECK_INTEGRITY):
		btrfs_info(info, "Enabling check integrity");
		break;
	case ((1 << BTRFS_MOUNT_CHECK_INTEGRITY) |
	      (1 << BTRFS_MOUNT_CHECK_INTEGRITY_INCLUDING_EXTENT_DATA)):
		btrfs_info(info, "Enabling check integrity including extent data");
		break;
	}
	if (test_bit(Opt_check_integrity_print_mask, ctx->specified) &&
	    ctx->check_integrity_print_mask != info->check_integrity_print_mask)
		btrfs_info(info, "check_integrity_print_mask 0x%x",
			   ctx->check_integrity_print_mask);
#endif

#ifdef CONFIG_BTRFS_DEBUG
	switch (ctx->mount_opt & explicit_changes &
		((1 << BTRFS_MOUNT_FRAGMENT_DATA) |
		 (1 << BTRFS_MOUNT_FRAGMENT_METADATA))) {
	case 0:
		break;
	case (1 << BTRFS_MOUNT_FRAGMENT_DATA):
		btrfs_info(info, "fragmenting data");
		break;
	case (1 << BTRFS_MOUNT_FRAGMENT_METADATA):
		btrfs_info(info, "fragmenting metadata");
		break;
	default:
		btrfs_info(info, "fragmenting all space");
		break;
	}
#endif

	/* Actually apply the options */
	mask = changes;
	mask &= ~(1 << BTRFS_MOUNT_INODE_MAP_CACHE);
	tmp = READ_ONCE(info->mount_opt);
	tmp &= ~mask;
	tmp |= ctx->mount_opt & mask;

	info->compress_level = ctx->compress_level;
	info->compress_type = ctx->compress_type;
	WRITE_ONCE(info->mount_opt, tmp);

	if (btrfs_raw_test_opt(explicit_changes, INODE_MAP_CACHE)) {
		if (btrfs_test_opt(info, INODE_MAP_CACHE)) {
			btrfs_set_pending((info), SET_INODE_MAP_CACHE);
			btrfs_clear_pending((info), CLEAR_INODE_MAP_CACHE);
		} else {
			btrfs_set_pending((info), CLEAR_INODE_MAP_CACHE);
			btrfs_clear_pending((info), SET_INODE_MAP_CACHE);
		}
	}

	if (test_bit(Opt_commit_interval, ctx->specified))
		info->commit_interval = ctx->commit_interval;
	if (test_bit(Opt_thread_pool, ctx->specified))
		info->thread_pool_size = ctx->thread_pool_size;
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	if (test_bit(Opt_check_integrity_print_mask, ctx->specified))
		info->check_integrity_print_mask = ctx->check_integrity_print_mask;
#endif
	if (test_bit(Opt_metadata_ratio, ctx->specified))
		info->metadata_ratio = info->metadata_ratio;
	if (test_bit(Opt_max_inline, ctx->specified))
		info->max_inline = ctx->max_inline;
}

/*
 * Display the options for /proc/mounts
 */
int btrfs_show_options(struct seq_file *seq, struct dentry *dentry)
{
	struct btrfs_fs_info *info = btrfs_sb(dentry->d_sb);
	const char *compress_type;

	if (btrfs_test_opt(info, DEGRADED))
		seq_puts(seq, ",degraded");
	if (!btrfs_test_opt(info, DATASUM))
		seq_puts(seq, ",nodatasum");
	if (!btrfs_test_opt(info, DATACOW))
		seq_puts(seq, ",nodatacow");
	if (!btrfs_test_opt(info, BARRIER))
		seq_puts(seq, ",nobarrier");
	if (info->max_inline != BTRFS_DEFAULT_MAX_INLINE)
		seq_printf(seq, ",max_inline=%llu", info->max_inline);
	if (info->thread_pool_size !=  min_t(unsigned long,
					     num_online_cpus() + 2, 8))
		seq_printf(seq, ",thread_pool=%u", info->thread_pool_size);
	if (btrfs_test_opt(info, COMPRESS)) {
		compress_type = btrfs_compress_type2str(info->compress_type);
		if (btrfs_test_opt(info, FORCE_COMPRESS))
			seq_printf(seq, ",compress-force=%s", compress_type);
		else
			seq_printf(seq, ",compress=%s", compress_type);
		if (info->compress_level)
			seq_printf(seq, ":%d", info->compress_level);
	}
	if (btrfs_test_opt(info, NOSSD))
		seq_puts(seq, ",nossd");
	if (btrfs_test_opt(info, SSD_SPREAD))
		seq_puts(seq, ",ssd_spread");
	else if (btrfs_test_opt(info, SSD))
		seq_puts(seq, ",ssd");
	if (!btrfs_test_opt(info, TREELOG))
		seq_puts(seq, ",notreelog");
	if (btrfs_test_opt(info, NOLOGREPLAY))
		seq_puts(seq, ",nologreplay");
	if (btrfs_test_opt(info, FLUSHONCOMMIT))
		seq_puts(seq, ",flushoncommit");
	if (btrfs_test_opt(info, DISCARD))
		seq_puts(seq, ",discard");
	if (!(info->sb->s_flags & SB_POSIXACL))
		seq_puts(seq, ",noacl");
	if (btrfs_test_opt(info, SPACE_CACHE))
		seq_puts(seq, ",space_cache");
	else if (btrfs_test_opt(info, FREE_SPACE_TREE))
		seq_puts(seq, ",space_cache=v2");
	else
		seq_puts(seq, ",nospace_cache");
	if (btrfs_test_opt(info, RESCAN_UUID_TREE))
		seq_puts(seq, ",rescan_uuid_tree");
	if (btrfs_test_opt(info, CLEAR_CACHE))
		seq_puts(seq, ",clear_cache");
	if (btrfs_test_opt(info, USER_SUBVOL_RM_ALLOWED))
		seq_puts(seq, ",user_subvol_rm_allowed");
	if (btrfs_test_opt(info, ENOSPC_DEBUG))
		seq_puts(seq, ",enospc_debug");
	if (btrfs_test_opt(info, AUTO_DEFRAG))
		seq_puts(seq, ",autodefrag");
	if (btrfs_test_opt(info, INODE_MAP_CACHE))
		seq_puts(seq, ",inode_cache");
	if (btrfs_test_opt(info, SKIP_BALANCE))
		seq_puts(seq, ",skip_balance");
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	if (btrfs_test_opt(info, CHECK_INTEGRITY_INCLUDING_EXTENT_DATA))
		seq_puts(seq, ",check_int_data");
	else if (btrfs_test_opt(info, CHECK_INTEGRITY))
		seq_puts(seq, ",check_int");
	if (info->check_integrity_print_mask)
		seq_printf(seq, ",check_int_print_mask=%d",
				info->check_integrity_print_mask);
#endif
	if (info->metadata_ratio)
		seq_printf(seq, ",metadata_ratio=%u", info->metadata_ratio);
	if (btrfs_test_opt(info, PANIC_ON_FATAL_ERROR))
		seq_puts(seq, ",fatal_errors=panic");
	if (info->commit_interval != BTRFS_DEFAULT_COMMIT_INTERVAL)
		seq_printf(seq, ",commit=%u", info->commit_interval);
#ifdef CONFIG_BTRFS_DEBUG
	if (btrfs_test_opt(info, FRAGMENT_DATA))
		seq_puts(seq, ",fragment=data");
	if (btrfs_test_opt(info, FRAGMENT_METADATA))
		seq_puts(seq, ",fragment=metadata");
#endif
	if (btrfs_test_opt(info, REF_VERIFY))
		seq_puts(seq, ",ref_verify");
	seq_printf(seq, ",subvolid=%llu",
		  BTRFS_I(d_inode(dentry))->root->root_key.objectid);
	seq_puts(seq, ",subvol=");
	seq_dentry(seq, dentry, " \t\n\\");
	return 0;
}
