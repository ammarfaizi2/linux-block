// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/parser.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "compression.h"
#include "volumes.h"

enum {
	Opt_acl, Opt_noacl,
	Opt_clear_cache,
	Opt_commit_interval,
	Opt_compress,
	Opt_compress_force,
	Opt_compress_force_type,
	Opt_compress_type,
	Opt_degraded,
	Opt_device,
	Opt_fatal_errors,
	Opt_flushoncommit, Opt_noflushoncommit,
	Opt_inode_cache, Opt_noinode_cache,
	Opt_max_inline,
	Opt_barrier, Opt_nobarrier,
	Opt_datacow, Opt_nodatacow,
	Opt_datasum, Opt_nodatasum,
	Opt_defrag, Opt_nodefrag,
	Opt_discard, Opt_nodiscard,
	Opt_nologreplay,
	Opt_norecovery,
	Opt_ratio,
	Opt_rescan_uuid_tree,
	Opt_skip_balance,
	Opt_space_cache, Opt_no_space_cache,
	Opt_space_cache_version,
	Opt_ssd, Opt_nossd,
	Opt_ssd_spread, Opt_nossd_spread,
	Opt_subvol,
	Opt_subvol_empty,
	Opt_subvolid,
	Opt_thread_pool,
	Opt_treelog, Opt_notreelog,
	Opt_usebackuproot,
	Opt_user_subvol_rm_allowed,

	/* Deprecated options */
	Opt_alloc_start,
	Opt_recovery,
	Opt_subvolrootid,

	/* Debugging options */
	Opt_check_integrity,
	Opt_check_integrity_including_extent_data,
	Opt_check_integrity_print_mask,
	Opt_enospc_debug, Opt_noenospc_debug,
#ifdef CONFIG_BTRFS_DEBUG
	Opt_fragment_data, Opt_fragment_metadata, Opt_fragment_all,
#endif
#ifdef CONFIG_BTRFS_FS_REF_VERIFY
	Opt_ref_verify,
#endif
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_clear_cache, "clear_cache"},
	{Opt_commit_interval, "commit=%u"},
	{Opt_compress, "compress"},
	{Opt_compress_type, "compress=%s"},
	{Opt_compress_force, "compress-force"},
	{Opt_compress_force_type, "compress-force=%s"},
	{Opt_degraded, "degraded"},
	{Opt_device, "device=%s"},
	{Opt_fatal_errors, "fatal_errors=%s"},
	{Opt_flushoncommit, "flushoncommit"},
	{Opt_noflushoncommit, "noflushoncommit"},
	{Opt_inode_cache, "inode_cache"},
	{Opt_noinode_cache, "noinode_cache"},
	{Opt_max_inline, "max_inline=%s"},
	{Opt_barrier, "barrier"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_datacow, "datacow"},
	{Opt_nodatacow, "nodatacow"},
	{Opt_datasum, "datasum"},
	{Opt_nodatasum, "nodatasum"},
	{Opt_defrag, "autodefrag"},
	{Opt_nodefrag, "noautodefrag"},
	{Opt_discard, "discard"},
	{Opt_nodiscard, "nodiscard"},
	{Opt_nologreplay, "nologreplay"},
	{Opt_norecovery, "norecovery"},
	{Opt_ratio, "metadata_ratio=%u"},
	{Opt_rescan_uuid_tree, "rescan_uuid_tree"},
	{Opt_skip_balance, "skip_balance"},
	{Opt_space_cache, "space_cache"},
	{Opt_no_space_cache, "nospace_cache"},
	{Opt_space_cache_version, "space_cache=%s"},
	{Opt_ssd, "ssd"},
	{Opt_nossd, "nossd"},
	{Opt_ssd_spread, "ssd_spread"},
	{Opt_nossd_spread, "nossd_spread"},
	{Opt_subvol, "subvol=%s"},
	{Opt_subvol_empty, "subvol="},
	{Opt_subvolid, "subvolid=%s"},
	{Opt_thread_pool, "thread_pool=%u"},
	{Opt_treelog, "treelog"},
	{Opt_notreelog, "notreelog"},
	{Opt_usebackuproot, "usebackuproot"},
	{Opt_user_subvol_rm_allowed, "user_subvol_rm_allowed"},

	/* Deprecated options */
	{Opt_alloc_start, "alloc_start=%s"},
	{Opt_recovery, "recovery"},
	{Opt_subvolrootid, "subvolrootid=%d"},

	/* Debugging options */
	{Opt_check_integrity, "check_int"},
	{Opt_check_integrity_including_extent_data, "check_int_data"},
	{Opt_check_integrity_print_mask, "check_int_print_mask=%u"},
	{Opt_enospc_debug, "enospc_debug"},
	{Opt_noenospc_debug, "noenospc_debug"},
#ifdef CONFIG_BTRFS_DEBUG
	{Opt_fragment_data, "fragment=data"},
	{Opt_fragment_metadata, "fragment=metadata"},
	{Opt_fragment_all, "fragment=all"},
#endif
#ifdef CONFIG_BTRFS_FS_REF_VERIFY
	{Opt_ref_verify, "ref_verify"},
#endif
	{Opt_err, NULL},
};

/*
 * Regular mount options parser.  Everything that is needed only when
 * reading in a new superblock is parsed here.
 * XXX JDM: This needs to be cleaned up for remount.
 */
int btrfs_parse_options(struct btrfs_fs_info *info, char *options,
			unsigned long new_flags)
{
	substring_t args[MAX_OPT_ARGS];
	char *p, *num;
	u64 cache_gen;
	int intarg;
	int ret = 0;
	char *compress_type;
	bool compress_force = false;
	enum btrfs_compression_type saved_compress_type;
	bool saved_compress_force;
	int no_compress = 0;

	cache_gen = btrfs_super_cache_generation(info->super_copy);
	if (btrfs_fs_compat_ro(info, FREE_SPACE_TREE))
		btrfs_set_opt(info->mount_opt, FREE_SPACE_TREE);
	else if (cache_gen)
		btrfs_set_opt(info->mount_opt, SPACE_CACHE);

	/*
	 * Even the options are empty, we still need to do extra check
	 * against new flags
	 */
	if (!options)
		goto check;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_degraded:
			btrfs_info(info, "allowing degraded mounts");
			btrfs_set_opt(info->mount_opt, DEGRADED);
			break;
		case Opt_subvol:
		case Opt_subvol_empty:
		case Opt_subvolid:
		case Opt_subvolrootid:
		case Opt_device:
			/*
			 * These are parsed by btrfs_parse_subvol_options or
			 * btrfs_parse_device_options and can be ignored here.
			 */
			break;
		case Opt_nodatasum:
			btrfs_clear_and_info(info, DATASUM,
					     "setting nodatasum");
			break;
		case Opt_datasum:
			if (!btrfs_test_opt(info, DATASUM)) {
				if (!btrfs_test_opt(info, DATACOW))
					btrfs_info(info,
						   "setting datasum, datacow enabled");
				else
					btrfs_info(info, "setting datasum");
			}
			btrfs_set_opt(info->mount_opt, DATACOW);
			btrfs_set_opt(info->mount_opt, DATASUM);
			break;
		case Opt_nodatacow:
			if (btrfs_test_opt(info, DATACOW)) {
				if (!btrfs_test_opt(info, COMPRESS) ||
				    !btrfs_test_opt(info, FORCE_COMPRESS)) {
					btrfs_info(info,
						   "setting nodatacow, compression disabled");
				} else {
					btrfs_info(info, "setting nodatacow");
				}
			}
			btrfs_clear_opt(info->mount_opt, COMPRESS);
			btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
			btrfs_clear_opt(info->mount_opt, DATACOW);
			btrfs_clear_opt(info->mount_opt, DATASUM);
			break;
		case Opt_datacow:
			btrfs_set_and_info(info, DATACOW,
					   "setting datacow");
			break;
		case Opt_compress_force:
		case Opt_compress_force_type:
			compress_force = true;
			/* Fallthrough */
		case Opt_compress:
		case Opt_compress_type:
			saved_compress_type = btrfs_test_opt(info,
							     COMPRESS) ?
				info->compress_type : BTRFS_COMPRESS_NONE;
			saved_compress_force =
				btrfs_test_opt(info, FORCE_COMPRESS);
			if (token == Opt_compress ||
			    token == Opt_compress_force ||
			    strncmp(args[0].from, "zlib", 4) == 0) {
				compress_type = "zlib";

				info->compress_type = BTRFS_COMPRESS_ZLIB;
				info->compress_level = BTRFS_ZLIB_DEFAULT_LEVEL;
				/*
				 * args[0] contains uninitialized data since
				 * for these tokens we don't expect any
				 * parameter.
				 */
				if (token != Opt_compress &&
				    token != Opt_compress_force)
					info->compress_level =
					  btrfs_compress_str2level(args[0].from);
				btrfs_set_opt(info->mount_opt, COMPRESS);
				btrfs_set_opt(info->mount_opt, DATACOW);
				btrfs_set_opt(info->mount_opt, DATASUM);
				no_compress = 0;
			} else if (strncmp(args[0].from, "lzo", 3) == 0) {
				compress_type = "lzo";
				info->compress_type = BTRFS_COMPRESS_LZO;
				btrfs_set_opt(info->mount_opt, COMPRESS);
				btrfs_set_opt(info->mount_opt, DATACOW);
				btrfs_set_opt(info->mount_opt, DATASUM);
				btrfs_set_fs_incompat(info, COMPRESS_LZO);
				no_compress = 0;
			} else if (strcmp(args[0].from, "zstd") == 0) {
				compress_type = "zstd";
				info->compress_type = BTRFS_COMPRESS_ZSTD;
				btrfs_set_opt(info->mount_opt, COMPRESS);
				btrfs_set_opt(info->mount_opt, DATACOW);
				btrfs_set_opt(info->mount_opt, DATASUM);
				btrfs_set_fs_incompat(info, COMPRESS_ZSTD);
				no_compress = 0;
			} else if (strncmp(args[0].from, "no", 2) == 0) {
				compress_type = "no";
				btrfs_clear_opt(info->mount_opt, COMPRESS);
				btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
				compress_force = false;
				no_compress++;
			} else {
				ret = -EINVAL;
				goto out;
			}

			if (compress_force) {
				btrfs_set_opt(info->mount_opt, FORCE_COMPRESS);
			} else {
				/*
				 * If we remount from compress-force=xxx to
				 * compress=xxx, we need clear FORCE_COMPRESS
				 * flag, otherwise, there is no way for users
				 * to disable forcible compression separately.
				 */
				btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
			}
			if ((btrfs_test_opt(info, COMPRESS) &&
			     (info->compress_type != saved_compress_type ||
			      compress_force != saved_compress_force)) ||
			    (!btrfs_test_opt(info, COMPRESS) &&
			     no_compress == 1)) {
				btrfs_info(info, "%s %s compression, level %d",
					   (compress_force) ? "force" : "use",
					   compress_type, info->compress_level);
			}
			compress_force = false;
			break;
		case Opt_ssd:
			btrfs_set_and_info(info, SSD,
					   "enabling ssd optimizations");
			btrfs_clear_opt(info->mount_opt, NOSSD);
			break;
		case Opt_ssd_spread:
			btrfs_set_and_info(info, SSD,
					   "enabling ssd optimizations");
			btrfs_set_and_info(info, SSD_SPREAD,
					   "using spread ssd allocation scheme");
			btrfs_clear_opt(info->mount_opt, NOSSD);
			break;
		case Opt_nossd:
			btrfs_set_opt(info->mount_opt, NOSSD);
			btrfs_clear_and_info(info, SSD,
					     "not using ssd optimizations");
			/* Fallthrough */
		case Opt_nossd_spread:
			btrfs_clear_and_info(info, SSD_SPREAD,
					     "not using spread ssd allocation scheme");
			break;
		case Opt_barrier:
			btrfs_set_and_info(info, BARRIER,
					     "turning on barriers");
			break;
		case Opt_nobarrier:
			btrfs_clear_and_info(info, BARRIER,
					   "turning off barriers");
			break;
		case Opt_thread_pool:
			ret = match_int(&args[0], &intarg);
			if (ret) {
				goto out;
			} else if (intarg == 0) {
				ret = -EINVAL;
				goto out;
			}
			info->thread_pool_size = intarg;
			break;
		case Opt_max_inline:
			num = match_strdup(&args[0]);
			if (num) {
				info->max_inline = memparse(num, NULL);
				kfree(num);

				if (info->max_inline) {
					info->max_inline = min_t(u64,
						info->max_inline,
						info->sectorsize);
				}
				btrfs_info(info, "max_inline at %llu",
					   info->max_inline);
			} else {
				ret = -ENOMEM;
				goto out;
			}
			break;
		case Opt_alloc_start:
			btrfs_info(info,
				"option alloc_start is obsolete, ignored");
			break;
		case Opt_acl:
#ifdef CONFIG_BTRFS_FS_POSIX_ACL
			info->sb->s_flags |= SB_POSIXACL;
			break;
#else
			btrfs_err(info, "support for ACL not compiled in!");
			ret = -EINVAL;
			goto out;
#endif
		case Opt_noacl:
			info->sb->s_flags &= ~SB_POSIXACL;
			break;
		case Opt_notreelog:
			btrfs_clear_and_info(info, TREELOG,
					     "disabling tree log");
			break;
		case Opt_treelog:
			btrfs_set_and_info(info, TREELOG,
					   "enabling tree log");
			break;
		case Opt_norecovery:
		case Opt_nologreplay:
			btrfs_set_and_info(info, NOLOGREPLAY,
					   "disabling log replay at mount time");
			break;
		case Opt_flushoncommit:
			btrfs_set_and_info(info, FLUSHONCOMMIT,
					   "turning on flush-on-commit");
			break;
		case Opt_noflushoncommit:
			btrfs_clear_and_info(info, FLUSHONCOMMIT,
					     "turning off flush-on-commit");
			break;
		case Opt_ratio:
			ret = match_int(&args[0], &intarg);
			if (ret)
				goto out;
			info->metadata_ratio = intarg;
			btrfs_info(info, "metadata ratio %u",
				   info->metadata_ratio);
			break;
		case Opt_discard:
			btrfs_set_and_info(info, DISCARD,
					   "turning on discard");
			break;
		case Opt_nodiscard:
			btrfs_clear_and_info(info, DISCARD,
					     "turning off discard");
			break;
		case Opt_space_cache:
		case Opt_space_cache_version:
			if (token == Opt_space_cache ||
			    strcmp(args[0].from, "v1") == 0) {
				btrfs_clear_opt(info->mount_opt,
						FREE_SPACE_TREE);
				btrfs_set_and_info(info, SPACE_CACHE,
					   "enabling disk space caching");
			} else if (strcmp(args[0].from, "v2") == 0) {
				btrfs_clear_opt(info->mount_opt,
						SPACE_CACHE);
				btrfs_set_and_info(info, FREE_SPACE_TREE,
						   "enabling free space tree");
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_rescan_uuid_tree:
			btrfs_set_opt(info->mount_opt, RESCAN_UUID_TREE);
			break;
		case Opt_no_space_cache:
			if (btrfs_test_opt(info, SPACE_CACHE)) {
				btrfs_clear_and_info(info, SPACE_CACHE,
					     "disabling disk space caching");
			}
			if (btrfs_test_opt(info, FREE_SPACE_TREE)) {
				btrfs_clear_and_info(info, FREE_SPACE_TREE,
					     "disabling free space tree");
			}
			break;
		case Opt_inode_cache:
			btrfs_set_pending_and_info(info, INODE_MAP_CACHE,
					   "enabling inode map caching");
			break;
		case Opt_noinode_cache:
			btrfs_clear_pending_and_info(info, INODE_MAP_CACHE,
					     "disabling inode map caching");
			break;
		case Opt_clear_cache:
			btrfs_set_and_info(info, CLEAR_CACHE,
					   "force clearing of disk cache");
			break;
		case Opt_user_subvol_rm_allowed:
			btrfs_set_opt(info->mount_opt, USER_SUBVOL_RM_ALLOWED);
			break;
		case Opt_enospc_debug:
			btrfs_set_opt(info->mount_opt, ENOSPC_DEBUG);
			break;
		case Opt_noenospc_debug:
			btrfs_clear_opt(info->mount_opt, ENOSPC_DEBUG);
			break;
		case Opt_defrag:
			btrfs_set_and_info(info, AUTO_DEFRAG,
					   "enabling auto defrag");
			break;
		case Opt_nodefrag:
			btrfs_clear_and_info(info, AUTO_DEFRAG,
					     "disabling auto defrag");
			break;
		case Opt_recovery:
			btrfs_warn(info,
				   "'recovery' is deprecated, use 'usebackuproot' instead");
			/* fall through */
		case Opt_usebackuproot:
			btrfs_info(info,
				   "trying to use backup root at mount time");
			btrfs_set_opt(info->mount_opt, USEBACKUPROOT);
			break;
		case Opt_skip_balance:
			btrfs_set_opt(info->mount_opt, SKIP_BALANCE);
			break;
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
		case Opt_check_integrity_including_extent_data:
			btrfs_info(info,
				   "enabling check integrity including extent data");
			btrfs_set_opt(info->mount_opt,
				      CHECK_INTEGRITY_INCLUDING_EXTENT_DATA);
			btrfs_set_opt(info->mount_opt, CHECK_INTEGRITY);
			break;
		case Opt_check_integrity:
			btrfs_info(info, "enabling check integrity");
			btrfs_set_opt(info->mount_opt, CHECK_INTEGRITY);
			break;
		case Opt_check_integrity_print_mask:
			ret = match_int(&args[0], &intarg);
			if (ret)
				goto out;
			info->check_integrity_print_mask = intarg;
			btrfs_info(info, "check_integrity_print_mask 0x%x",
				   info->check_integrity_print_mask);
			break;
#else
		case Opt_check_integrity_including_extent_data:
		case Opt_check_integrity:
		case Opt_check_integrity_print_mask:
			btrfs_err(info,
				  "support for check_integrity* not compiled in!");
			ret = -EINVAL;
			goto out;
#endif
		case Opt_fatal_errors:
			if (strcmp(args[0].from, "panic") == 0)
				btrfs_set_opt(info->mount_opt,
					      PANIC_ON_FATAL_ERROR);
			else if (strcmp(args[0].from, "bug") == 0)
				btrfs_clear_opt(info->mount_opt,
					      PANIC_ON_FATAL_ERROR);
			else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_commit_interval:
			intarg = 0;
			ret = match_int(&args[0], &intarg);
			if (ret)
				goto out;
			if (intarg == 0) {
				btrfs_info(info,
					   "using default commit interval %us",
					   BTRFS_DEFAULT_COMMIT_INTERVAL);
				intarg = BTRFS_DEFAULT_COMMIT_INTERVAL;
			} else if (intarg > 300) {
				btrfs_warn(info, "excessive commit interval %d",
					   intarg);
			}
			info->commit_interval = intarg;
			break;
#ifdef CONFIG_BTRFS_DEBUG
		case Opt_fragment_all:
			btrfs_info(info, "fragmenting all space");
			btrfs_set_opt(info->mount_opt, FRAGMENT_DATA);
			btrfs_set_opt(info->mount_opt, FRAGMENT_METADATA);
			break;
		case Opt_fragment_metadata:
			btrfs_info(info, "fragmenting metadata");
			btrfs_set_opt(info->mount_opt,
				      FRAGMENT_METADATA);
			break;
		case Opt_fragment_data:
			btrfs_info(info, "fragmenting data");
			btrfs_set_opt(info->mount_opt, FRAGMENT_DATA);
			break;
#endif
#ifdef CONFIG_BTRFS_FS_REF_VERIFY
		case Opt_ref_verify:
			btrfs_info(info, "doing ref verification");
			btrfs_set_opt(info->mount_opt, REF_VERIFY);
			break;
#endif
		case Opt_err:
			btrfs_info(info, "unrecognized mount option '%s'", p);
			ret = -EINVAL;
			goto out;
		default:
			break;
		}
	}
check:
	/*
	 * Extra check for current option against current flag
	 */
	if (btrfs_test_opt(info, NOLOGREPLAY) && !(new_flags & SB_RDONLY)) {
		btrfs_err(info,
			  "nologreplay must be used with ro mount option");
		ret = -EINVAL;
	}
out:
	if (btrfs_fs_compat_ro(info, FREE_SPACE_TREE) &&
	    !btrfs_test_opt(info, FREE_SPACE_TREE) &&
	    !btrfs_test_opt(info, CLEAR_CACHE)) {
		btrfs_err(info, "cannot disable free space tree");
		ret = -EINVAL;

	}
	if (!ret && btrfs_test_opt(info, SPACE_CACHE))
		btrfs_info(info, "disk space caching is enabled");
	if (!ret && btrfs_test_opt(info, FREE_SPACE_TREE))
		btrfs_info(info, "using free space tree");
	return ret;
}

/*
 * Parse mount options that are required early in the mount process.
 *
 * All other options will be parsed on much later in the mount process and
 * only when we need to allocate a new super block.
 */
int btrfs_parse_device_options(const char *options, fmode_t flags)
{
	substring_t args[MAX_OPT_ARGS];
	char *device_name, *opts, *orig, *p;
	struct btrfs_device *device = NULL;
	int error = 0;

	lockdep_assert_held(&uuid_mutex);

	if (!options)
		return 0;

	/*
	 * strsep changes the string, duplicate it because btrfs_parse_options
	 * gets called later
	 */
	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;
	orig = opts;

	while ((p = strsep(&opts, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		if (token == Opt_device) {
			device_name = match_strdup(&args[0]);
			if (!device_name) {
				error = -ENOMEM;
				goto out;
			}
			device = btrfs_scan_one_device(device_name, flags);
			kfree(device_name);
			if (IS_ERR(device)) {
				error = PTR_ERR(device);
				goto out;
			}
		}
	}

out:
	kfree(orig);
	return error;
}

/*
 * Parse mount options that are related to subvolume id
 *
 * The value is later passed to mount_subvol()
 */
int btrfs_parse_subvol_options(const char *options, char **subvol_name,
			       u64 *subvol_objectid)
{
	substring_t args[MAX_OPT_ARGS];
	char *opts, *orig, *p;
	int error = 0;
	u64 subvolid;

	if (!options)
		return 0;

	/*
	 * strsep changes the string, duplicate it because
	 * btrfs_parse_device_options gets called later
	 */
	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;
	orig = opts;

	while ((p = strsep(&opts, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_subvol:
			kfree(*subvol_name);
			*subvol_name = match_strdup(&args[0]);
			if (!*subvol_name) {
				error = -ENOMEM;
				goto out;
			}
			break;
		case Opt_subvolid:
			error = match_u64(&args[0], &subvolid);
			if (error)
				goto out;

			/* we want the original fs_tree */
			if (subvolid == 0)
				subvolid = BTRFS_FS_TREE_OBJECTID;

			*subvol_objectid = subvolid;
			break;
		case Opt_subvolrootid:
			pr_warn("BTRFS: 'subvolrootid' mount option is deprecated and has no effect\n");
			break;
		default:
			break;
		}
	}

out:
	kfree(orig);
	return error;
}

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
