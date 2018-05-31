/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* fsinfo() definitions.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#ifndef _UAPI_LINUX_FSINFO_H
#define _UAPI_LINUX_FSINFO_H

#include <linux/types.h>
#include <linux/socket.h>

/*
 * The filesystem attributes that can be requested.  Note that some attributes
 * may have multiple instances which can be switched in the parameter block.
 */
enum fsinfo_attribute {
	fsinfo_attr_statfs		= 0,	/* statfs()-style state */
	fsinfo_attr_fsinfo		= 1,	/* Information about fsinfo() */
	fsinfo_attr_ids			= 2,	/* Filesystem IDs */
	fsinfo_attr_limits		= 3,	/* Filesystem limits */
	fsinfo_attr_supports		= 4,	/* What's supported in statx, iocflags, ... */
	fsinfo_attr_capabilities	= 5,	/* Filesystem capabilities (bits) */
	fsinfo_attr_timestamp_info	= 6,	/* Inode timestamp info */
	fsinfo_attr_volume_id		= 7,	/* Volume ID (string) */
	fsinfo_attr_volume_uuid		= 8,	/* Volume UUID (LE uuid) */
	fsinfo_attr_volume_name		= 9,	/* Volume name (string) */
	fsinfo_attr_cell_name		= 10,	/* Cell name (string) */
	fsinfo_attr_domain_name		= 11,	/* Domain name (string) */
	fsinfo_attr_realm_name		= 12,	/* Realm name (string) */
	fsinfo_attr_server_name		= 13,	/* Name of the Nth server */
	fsinfo_attr_server_address	= 14,	/* Mth address of the Nth server */
	fsinfo_attr_parameter		= 15,	/* Nth mount parameter (string) */
	fsinfo_attr_source		= 16,	/* Nth mount source name (string) */
	fsinfo_attr_name_encoding	= 17,	/* Filename encoding (string) */
	fsinfo_attr_name_codepage	= 18,	/* Filename codepage (string) */
	fsinfo_attr_io_size		= 19,	/* Optimal I/O sizes */
	fsinfo_attr__nr
};

/*
 * Optional fsinfo() parameter structure.
 *
 * If this is not given, it is assumed that fsinfo_attr_statfs instance 0,0 is
 * desired.
 */
struct fsinfo_params {
	__u32	at_flags;	/* AT_SYMLINK_NOFOLLOW and similar flags */
	__u32	request;	/* What is being asking for (enum fsinfo_attribute) */
	__u32	Nth;		/* Instance of it (some may have multiple) */
	__u32	Mth;		/* Subinstance of Nth instance */
	__u32	__reserved[6];	/* Reserved params; all must be 0 */
};

/*
 * Information struct for fsinfo(fsinfo_attr_statfs).
 * - This gives extended filesystem information.
 */
struct fsinfo_statfs {
	__u64	f_blocks;	/* Total number of blocks in fs */
	__u64	f_bfree;	/* Total number of free blocks */
	__u64	f_bavail;	/* Number of free blocks available to ordinary user */
	__u64	f_files;	/* Total number of file nodes in fs */
	__u64	f_ffree;	/* Number of free file nodes */
	__u64	f_favail;	/* Number of free file nodes available to ordinary user */
	__u32	f_bsize;	/* Optimal block size */
	__u32	f_frsize;	/* Fragment size */
};

/*
 * Information struct for fsinfo(fsinfo_attr_ids).
 *
 * List of basic identifiers as is normally found in statfs().
 */
struct fsinfo_ids {
	char	f_fs_name[15 + 1];
	__u64	f_flags;	/* Filesystem mount flags (MS_*) */
	__u64	f_fsid;		/* Short 64-bit Filesystem ID (as statfs) */
	__u64	f_sb_id;	/* Internal superblock ID for sbnotify()/mntnotify() */
	__u32	f_fstype;	/* Filesystem type from linux/magic.h [uncond] */
	__u32	f_dev_major;	/* As st_dev_* from struct statx [uncond] */
	__u32	f_dev_minor;
};

/*
 * Information struct for fsinfo(fsinfo_attr_limits).
 *
 * List of supported filesystem limits.
 */
struct fsinfo_limits {
	__u64	max_file_size;			/* Maximum file size */
	__u64	max_uid;			/* Maximum UID supported */
	__u64	max_gid;			/* Maximum GID supported */
	__u64	max_projid;			/* Maximum project ID supported */
	__u32	max_dev_major;			/* Maximum device major representable */
	__u32	max_dev_minor;			/* Maximum device minor representable */
	__u32	max_hard_links;			/* Maximum number of hard links on a file */
	__u32	max_xattr_body_len;		/* Maximum xattr content length */
	__u32	max_xattr_name_len;		/* Maximum xattr name length */
	__u32	max_filename_len;		/* Maximum filename length */
	__u32	max_symlink_len;		/* Maximum symlink content length */
	__u32	__reserved[1];
};

/*
 * Information struct for fsinfo(fsinfo_attr_supports).
 *
 * What's supported in various masks, such as statx() attribute and mask bits
 * and IOC flags.
 */
struct fsinfo_supports {
	__u64	stx_attributes;		/* What statx::stx_attributes are supported */
	__u32	stx_mask;		/* What statx::stx_mask bits are supported */
	__u32	ioc_flags;		/* What FS_IOC_* flags are supported */
	__u32	win_file_attrs;		/* What DOS/Windows FILE_* attributes are supported */
	__u32	__reserved[1];
};

/*
 * Information struct for fsinfo(fsinfo_attr_capabilities).
 *
 * Bitmask indicating filesystem capabilities where renderable as single bits.
 */
enum fsinfo_capability {
	fsinfo_cap_is_kernel_fs		= 0,	/* fs is kernel-special filesystem */
	fsinfo_cap_is_block_fs		= 1,	/* fs is block-based filesystem */
	fsinfo_cap_is_flash_fs		= 2,	/* fs is flash filesystem */
	fsinfo_cap_is_network_fs	= 3,	/* fs is network filesystem */
	fsinfo_cap_is_automounter_fs	= 4,	/* fs is automounter special filesystem */
	fsinfo_cap_automounts		= 5,	/* fs supports automounts */
	fsinfo_cap_adv_locks		= 6,	/* fs supports advisory file locking */
	fsinfo_cap_mand_locks		= 7,	/* fs supports mandatory file locking */
	fsinfo_cap_leases		= 8,	/* fs supports file leases */
	fsinfo_cap_uids			= 9,	/* fs supports numeric uids */
	fsinfo_cap_gids			= 10,	/* fs supports numeric gids */
	fsinfo_cap_projids		= 11,	/* fs supports numeric project ids */
	fsinfo_cap_id_names		= 12,	/* fs supports user names */
	fsinfo_cap_id_guids		= 13,	/* fs supports user guids */
	fsinfo_cap_windows_attrs	= 14,	/* fs has windows attributes */
	fsinfo_cap_user_quotas		= 15,	/* fs has per-user quotas */
	fsinfo_cap_group_quotas		= 16,	/* fs has per-group quotas */
	fsinfo_cap_project_quotas	= 17,	/* fs has per-project quotas */
	fsinfo_cap_xattrs		= 18,	/* fs has xattrs */
	fsinfo_cap_journal		= 19,	/* fs has a journal */
	fsinfo_cap_data_is_journalled	= 20,	/* fs is using data journalling */
	fsinfo_cap_o_sync		= 21,	/* fs supports O_SYNC */
	fsinfo_cap_o_direct		= 22,	/* fs supports O_DIRECT */
	fsinfo_cap_volume_id		= 23,	/* fs has a volume ID */
	fsinfo_cap_volume_uuid		= 24,	/* fs has a volume UUID */
	fsinfo_cap_volume_name		= 25,	/* fs has a volume name */
	fsinfo_cap_volume_fsid		= 26,	/* fs has a volume FSID */
	fsinfo_cap_cell_name		= 27,	/* fs has a cell name */
	fsinfo_cap_domain_name		= 28,	/* fs has a domain name */
	fsinfo_cap_realm_name		= 29,	/* fs has a realm name */
	fsinfo_cap_iver_all_change	= 30,	/* i_version represents data + meta changes */
	fsinfo_cap_iver_data_change	= 31,	/* i_version represents data changes only */
	fsinfo_cap_iver_mono_incr	= 32,	/* i_version incremented monotonically */
	fsinfo_cap_symlinks		= 33,	/* fs supports symlinks */
	fsinfo_cap_hard_links		= 34,	/* fs supports hard links */
	fsinfo_cap_hard_links_1dir	= 35,	/* fs supports hard links in same dir only */
	fsinfo_cap_device_files		= 36,	/* fs supports bdev, cdev */
	fsinfo_cap_unix_specials	= 37,	/* fs supports pipe, fifo, socket */
	fsinfo_cap_resource_forks	= 38,	/* fs supports resource forks/streams */
	fsinfo_cap_name_case_indep	= 39,	/* Filename case independence is mandatory */
	fsinfo_cap_name_non_utf8	= 40,	/* fs has non-utf8 names */
	fsinfo_cap_name_has_codepage	= 41,	/* fs has a filename codepage */
	fsinfo_cap_sparse		= 42,	/* fs supports sparse files */
	fsinfo_cap_not_persistent	= 43,	/* fs is not persistent */
	fsinfo_cap_no_unix_mode		= 44,	/* fs does not support unix mode bits */
	fsinfo_cap_has_atime		= 45,	/* fs supports access time */
	fsinfo_cap_has_btime		= 46,	/* fs supports birth/creation time */
	fsinfo_cap_has_ctime		= 47,	/* fs supports change time */
	fsinfo_cap_has_mtime		= 48,	/* fs supports modification time */
	fsinfo_cap__nr
};

struct fsinfo_capabilities {
	__u8	capabilities[(fsinfo_cap__nr + 7) / 8];
};

/*
 * Information struct for fsinfo(fsinfo_attr_timestamp_info).
 */
struct fsinfo_timestamp_info {
	__s64	minimum_timestamp;	/* Minimum timestamp value in seconds */
	__s64	maximum_timestamp;	/* Maximum timestamp value in seconds */
	__u16	atime_gran_mantissa;	/* Granularity(secs) = mant * 10^exp */
	__u16	btime_gran_mantissa;
	__u16	ctime_gran_mantissa;
	__u16	mtime_gran_mantissa;
	__s8	atime_gran_exponent;
	__s8	btime_gran_exponent;
	__s8	ctime_gran_exponent;
	__s8	mtime_gran_exponent;
	__u32	__reserved[1];
};

/*
 * Information struct for fsinfo(fsinfo_attr_volume_uuid).
 */
struct fsinfo_volume_uuid {
	__u8	uuid[16];
};

/*
 * Information struct for fsinfo(fsinfo_attr_server_addresses).
 *
 * Find the Mth address of the Nth server for a network mount.
 */
struct fsinfo_server_address {
	struct __kernel_sockaddr_storage address;
};

/*
 * Information struct for fsinfo(fsinfo_attr_io_size).
 *
 * Retrieve I/O size hints for a filesystem.
 */
struct fsinfo_io_size {
	__u32		dio_size_gran;	/* Size granularity for O_DIRECT */
	__u32		dio_mem_align;	/* Memory alignment for O_DIRECT */
};

/*
 * Information struct for fsinfo(fsinfo_attr_fsinfo).
 *
 * This gives information about fsinfo() itself.
 */
struct fsinfo_fsinfo {
	__u32	max_attr;	/* Number of supported attributes (fsinfo_attr__nr) */
	__u32	max_cap;	/* Number of supported capabilities (fsinfo_cap__nr) */
};

#endif /* _UAPI_LINUX_FSINFO_H */
