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
	FSINFO_ATTR_STATFS		= 0,	/* statfs()-style state */
	FSINFO_ATTR_FSINFO		= 1,	/* Information about fsinfo() */
	FSINFO_ATTR_IDS			= 2,	/* Filesystem IDs */
	FSINFO_ATTR_LIMITS		= 3,	/* Filesystem limits */
	FSINFO_ATTR_SUPPORTS		= 4,	/* What's supported in statx, iocflags, ... */
	FSINFO_ATTR_CAPABILITIES	= 5,	/* Filesystem capabilities (bits) */
	FSINFO_ATTR_TIMESTAMP_INFO	= 6,	/* Inode timestamp info */
	FSINFO_ATTR_VOLUME_ID		= 7,	/* Volume ID (string) */
	FSINFO_ATTR_VOLUME_UUID		= 8,	/* Volume UUID (LE uuid) */
	FSINFO_ATTR_VOLUME_NAME		= 9,	/* Volume name (string) */
	FSINFO_ATTR_NAME_ENCODING	= 10,	/* Filename encoding (string) */
	FSINFO_ATTR_NAME_CODEPAGE	= 11,	/* Filename codepage (string) */
	FSINFO_ATTR_PARAM_DESCRIPTION	= 12,	/* General fs parameter description */
	FSINFO_ATTR_PARAM_SPECIFICATION	= 13,	/* Nth parameter specification */
	FSINFO_ATTR_PARAM_ENUM		= 14,	/* Nth enum-to-val */
	FSINFO_ATTR_PARAMETERS		= 15,	/* Mount parameters (large string) */
	FSINFO_ATTR_LSM_PARAMETERS	= 16,	/* LSM Mount parameters (large string) */
	FSINFO_ATTR_MOUNT_INFO		= 17,	/* Mount object information */
	FSINFO_ATTR_MOUNT_DEVNAME	= 18,	/* Mount object device name (string) */
	FSINFO_ATTR_MOUNT_CHILDREN	= 19,	/* Submount list (array) */
	FSINFO_ATTR_MOUNT_SUBMOUNT	= 20,	/* Relative path of Nth submount (string) */
	FSINFO_ATTR_SERVER_NAME		= 21,	/* Name of the Nth server (string) */
	FSINFO_ATTR_SERVER_ADDRESS	= 22,	/* Mth address of the Nth server */
	FSINFO_ATTR_CELL_NAME		= 23,	/* Cell name (string) */
	FSINFO_ATTR_SB_NOTIFICATIONS	= 24,	/* sb_notify() information */
	FSINFO_ATTR__NR
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
	__u64	__reserved[3];	/* Reserved params; all must be 0 */
};

struct fsinfo_u128 {
#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
	__u64	hi;
	__u64	lo;
#elif defined(__BYTE_ORDER) ? __BYTE_ORDER == __LITTLE_ENDIAN : defined(__LITTLE_ENDIAN)
	__u64	lo;
	__u64	hi;
#endif
};

/*
 * Information struct for fsinfo(fsinfo_attr_statfs).
 * - This gives extended filesystem information.
 */
struct fsinfo_statfs {
	struct fsinfo_u128 f_blocks;	/* Total number of blocks in fs */
	struct fsinfo_u128 f_bfree;	/* Total number of free blocks */
	struct fsinfo_u128 f_bavail;	/* Number of free blocks available to ordinary user */
	struct fsinfo_u128 f_files;	/* Total number of file nodes in fs */
	struct fsinfo_u128 f_ffree;	/* Number of free file nodes */
	struct fsinfo_u128 f_favail;	/* Number of file nodes available to ordinary user */
	__u64	f_bsize;		/* Optimal block size */
	__u64	f_frsize;		/* Fragment size */
	__u64	mnt_attrs;		/* Mount attributes (MOUNT_ATTR_*) */
};

/*
 * Information struct for fsinfo(fsinfo_attr_ids).
 *
 * List of basic identifiers as is normally found in statfs().
 */
struct fsinfo_ids {
	char	f_fs_name[15 + 1];	/* Filesystem name */
	__u64	f_fsid;			/* Short 64-bit Filesystem ID (as statfs) */
	__u64	f_sb_id;		/* Internal superblock ID for sbnotify()/mntnotify() */
	__u32	f_fstype;		/* Filesystem type from linux/magic.h [uncond] */
	__u32	f_dev_major;		/* As st_dev_* from struct statx [uncond] */
	__u32	f_dev_minor;
	__u32	__reserved[1];
};

/*
 * Information struct for fsinfo(fsinfo_attr_limits).
 *
 * List of supported filesystem limits.
 */
struct fsinfo_limits {
	struct fsinfo_u128 max_file_size;	/* Maximum file size */
	struct fsinfo_u128 max_ino;		/* Maximum inode number */
	__u64	max_uid;			/* Maximum UID supported */
	__u64	max_gid;			/* Maximum GID supported */
	__u64	max_projid;			/* Maximum project ID supported */
	__u64	max_hard_links;			/* Maximum number of hard links on a file */
	__u64	max_xattr_body_len;		/* Maximum xattr content length */
	__u32	max_xattr_name_len;		/* Maximum xattr name length */
	__u32	max_filename_len;		/* Maximum filename length */
	__u32	max_symlink_len;		/* Maximum symlink content length */
	__u32	max_dev_major;			/* Maximum device major representable */
	__u32	max_dev_minor;			/* Maximum device minor representable */
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
	FSINFO_CAP_IS_KERNEL_FS		= 0,	/* fs is kernel-special filesystem */
	FSINFO_CAP_IS_BLOCK_FS		= 1,	/* fs is block-based filesystem */
	FSINFO_CAP_IS_FLASH_FS		= 2,	/* fs is flash filesystem */
	FSINFO_CAP_IS_NETWORK_FS	= 3,	/* fs is network filesystem */
	FSINFO_CAP_IS_AUTOMOUNTER_FS	= 4,	/* fs is automounter special filesystem */
	FSINFO_CAP_IS_MEMORY_FS		= 5,	/* fs is memory-based filesystem */
	FSINFO_CAP_AUTOMOUNTS		= 6,	/* fs supports automounts */
	FSINFO_CAP_ADV_LOCKS		= 7,	/* fs supports advisory file locking */
	FSINFO_CAP_MAND_LOCKS		= 8,	/* fs supports mandatory file locking */
	FSINFO_CAP_LEASES		= 9,	/* fs supports file leases */
	FSINFO_CAP_UIDS			= 10,	/* fs supports numeric uids */
	FSINFO_CAP_GIDS			= 11,	/* fs supports numeric gids */
	FSINFO_CAP_PROJIDS		= 12,	/* fs supports numeric project ids */
	FSINFO_CAP_STRING_USER_IDS	= 13,	/* fs supports string user identifiers */
	FSINFO_CAP_GUID_USER_IDS	= 14,	/* fs supports GUID user identifiers */
	FSINFO_CAP_WINDOWS_ATTRS	= 15,	/* fs has windows attributes */
	FSINFO_CAP_USER_QUOTAS		= 16,	/* fs has per-user quotas */
	FSINFO_CAP_GROUP_QUOTAS		= 17,	/* fs has per-group quotas */
	FSINFO_CAP_PROJECT_QUOTAS	= 18,	/* fs has per-project quotas */
	FSINFO_CAP_XATTRS		= 19,	/* fs has xattrs */
	FSINFO_CAP_JOURNAL		= 20,	/* fs has a journal */
	FSINFO_CAP_DATA_IS_JOURNALLED	= 21,	/* fs is using data journalling */
	FSINFO_CAP_O_SYNC		= 22,	/* fs supports O_SYNC */
	FSINFO_CAP_O_DIRECT		= 23,	/* fs supports O_DIRECT */
	FSINFO_CAP_VOLUME_ID		= 24,	/* fs has a volume ID */
	FSINFO_CAP_VOLUME_UUID		= 25,	/* fs has a volume UUID */
	FSINFO_CAP_VOLUME_NAME		= 26,	/* fs has a volume name */
	FSINFO_CAP_VOLUME_FSID		= 27,	/* fs has a volume FSID */
	FSINFO_CAP_IVER_ALL_CHANGE	= 28,	/* i_version represents data + meta changes */
	FSINFO_CAP_IVER_DATA_CHANGE	= 29,	/* i_version represents data changes only */
	FSINFO_CAP_IVER_MONO_INCR	= 30,	/* i_version incremented monotonically */
	FSINFO_CAP_DIRECTORIES		= 31,	/* fs supports (sub)directories */
	FSINFO_CAP_SYMLINKS		= 32,	/* fs supports symlinks */
	FSINFO_CAP_HARD_LINKS		= 33,	/* fs supports hard links */
	FSINFO_CAP_HARD_LINKS_1DIR	= 34,	/* fs supports hard links in same dir only */
	FSINFO_CAP_DEVICE_FILES		= 35,	/* fs supports bdev, cdev */
	FSINFO_CAP_UNIX_SPECIALS	= 36,	/* fs supports pipe, fifo, socket */
	FSINFO_CAP_RESOURCE_FORKS	= 37,	/* fs supports resource forks/streams */
	FSINFO_CAP_NAME_CASE_INDEP	= 38,	/* Filename case independence is mandatory */
	FSINFO_CAP_NAME_NON_UTF8	= 39,	/* fs has non-utf8 names */
	FSINFO_CAP_NAME_HAS_CODEPAGE	= 40,	/* fs has a filename codepage */
	FSINFO_CAP_SPARSE		= 41,	/* fs supports sparse files */
	FSINFO_CAP_NOT_PERSISTENT	= 42,	/* fs is not persistent */
	FSINFO_CAP_NO_UNIX_MODE		= 43,	/* fs does not support unix mode bits */
	FSINFO_CAP_HAS_ATIME		= 44,	/* fs supports access time */
	FSINFO_CAP_HAS_BTIME		= 45,	/* fs supports birth/creation time */
	FSINFO_CAP_HAS_CTIME		= 46,	/* fs supports change time */
	FSINFO_CAP_HAS_MTIME		= 47,	/* fs supports modification time */
	FSINFO_CAP__NR
};

struct fsinfo_capabilities {
	__u8	capabilities[(FSINFO_CAP__NR + 7) / 8];
};

struct fsinfo_timestamp_one {
	__s64	minimum;	/* Minimum timestamp value in seconds */
	__u64	maximum;	/* Maximum timestamp value in seconds */
	__u16	gran_mantissa;	/* Granularity(secs) = mant * 10^exp */
	__s8	gran_exponent;
	__u8	reserved[5];
};

/*
 * Information struct for fsinfo(fsinfo_attr_timestamp_info).
 */
struct fsinfo_timestamp_info {
	struct fsinfo_timestamp_one	atime;	/* Access time */
	struct fsinfo_timestamp_one	mtime;	/* Modification time */
	struct fsinfo_timestamp_one	ctime;	/* Change time */
	struct fsinfo_timestamp_one	btime;	/* Birth/creation time */
};

/*
 * Information struct for fsinfo(fsinfo_attr_volume_uuid).
 */
struct fsinfo_volume_uuid {
	__u8	uuid[16];
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

/*
 * Information struct for fsinfo(fsinfo_attr_param_description).
 *
 * Query the parameter set for a filesystem.
 */
struct fsinfo_param_description {
	__u32		nr_params;		/* Number of individual parameters */
	__u32		nr_enum_names;		/* Number of enum names  */
};

/*
 * Information struct for fsinfo(fsinfo_attr_param_specification).
 *
 * Query the specification of the Nth filesystem parameter.
 */
struct fsinfo_param_specification {
	__u32		type;		/* enum fsinfo_param_specification_type */
	__u32		flags;		/* Qualifiers */
	__u32		opt;		/* Corresponding params have same ID here */
	char		name[240];
};

enum fsinfo_param_specification_type {
	FSINFO_PARAM_SPEC_NOT_DEFINED		= 0,
	FSINFO_PARAM_SPEC_IS_FLAG		= 1,
	FSINFO_PARAM_SPEC_IS_BOOL		= 2,
	FSINFO_PARAM_SPEC_IS_U32		= 3,
	FSINFO_PARAM_SPEC_IS_U32_OCTAL		= 4,
	FSINFO_PARAM_SPEC_IS_U32_HEX		= 5,
	FSINFO_PARAM_SPEC_IS_S32		= 6,
	FSINFO_PARAM_SPEC_IS_U64		= 7,
	FSINFO_PARAM_SPEC_IS_ENUM		= 8,
	FSINFO_PARAM_SPEC_IS_STRING		= 9,
	FSINFO_PARAM_SPEC_IS_BLOB		= 10,
	FSINFO_PARAM_SPEC_IS_BLOCKDEV		= 11,
	FSINFO_PARAM_SPEC_IS_PATH		= 12,
	FSINFO_PARAM_SPEC_IS_FD			= 13,
	NR__FSINFO_PARAM_SPEC
};

#define FSINFO_PARAM_SPEC_VALUE_IS_OPTIONAL	0X00000001
#define FSINFO_PARAM_SPEC_PREFIX_NO_IS_NEG	0X00000002
#define FSINFO_PARAM_SPEC_EMPTY_STRING_IS_NEG	0X00000004
#define FSINFO_PARAM_SPEC_DEPRECATED		0X00000008

/*
 * Information struct for fsinfo(fsinfo_attr_param_enum).
 *
 * Query the Nth filesystem enum parameter value name.
 */
struct fsinfo_param_enum {
	__u32		opt;		/* ->opt of the relevant parameter specification */
	char		name[252];	/* Name of the enum value */
};

/*
 * Information struct for fsinfo(FSINFO_ATTR_MOUNT_INFO).
 */
struct fsinfo_mount_info {
	__u64		f_sb_id;	/* Superblock ID */
	__u32		mnt_id;		/* Mount identifier (use with AT_FSINFO_MOUNTID_PATH) */
	__u32		parent_id;	/* Parent mount identifier */
	__u32		group_id;	/* Mount group ID */
	__u32		master_id;	/* Slave master group ID */
	__u32		from_id;	/* Slave propagated from ID */
	__u32		attr;		/* MOUNT_ATTR_* flags */
	__u32		notify_counter;	/* Number of notifications generated. */
	__u32		__reserved[1];
};

/*
 * Information struct element for fsinfo(FSINFO_ATTR_MOUNT_CHILDREN).
 * - An extra element is placed on the end representing the parent mount.
 */
struct fsinfo_mount_child {
	__u32		mnt_id;		/* Mount identifier (use with AT_FSINFO_MOUNTID_PATH) */
	__u32		notify_counter;	/* Number of notifications generated on mount. */
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
 * Information struct for fsinfo(FSINFO_ATTR_SB_NOTIFICATIONS).
 */
struct fsinfo_sb_notifications {
	__u64		watch_id;	/* Watch ID for superblock. */
	__u32		notify_counter;	/* Number of notifications. */
	__u32		__reserved[1];
};

#endif /* _UAPI_LINUX_FSINFO_H */
