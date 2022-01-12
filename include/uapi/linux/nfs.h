/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * NFS protocol definitions
 *
 * This file contains constants mostly for Version 2 of the protocol,
 * but also has a couple of NFSv3 bits in (notably the error codes).
 */
#ifndef _UAPI_LINUX_NFS_H
#define _UAPI_LINUX_NFS_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/time.h>

#define NFS_PROGRAM	100003
#define NFS_PORT	2049
#define NFS_RDMA_PORT	20049
#define NFS_MAXDATA	8192
#define NFS_MAXPATHLEN	1024
#define NFS_MAXNAMLEN	255
#define NFS_MAXGROUPS	16
#define NFS_FHSIZE	32
#define NFS_COOKIESIZE	4
#define NFS_FIFO_DEV	(-1)
#define NFSMODE_FMT	0170000
#define NFSMODE_DIR	0040000
#define NFSMODE_CHR	0020000
#define NFSMODE_BLK	0060000
#define NFSMODE_REG	0100000
#define NFSMODE_LNK	0120000
#define NFSMODE_SOCK	0140000
#define NFSMODE_FIFO	0010000

#define NFS_MNT_PROGRAM		100005
#define NFS_MNT_VERSION		1
#define NFS_MNT3_VERSION	3

#define NFS_PIPE_DIRNAME "nfs"

/* NFS ioctls */
#define NFS_IOC_FILE_STATX_GET	_IOR('N', 2, struct nfs_ioctl_nfs4_statx)
#define NFS_IOC_FILE_STATX_SET	_IOW('N', 3, struct nfs_ioctl_nfs4_statx)

#define NFS_IOC_FILE_ACCESS_GET	_IOR('N', 4, struct nfs_ioctl_nfs4_access)

/* Options for struct nfs_ioctl_nfs4_statx */
#define NFS_FA_OPTIONS_SYNC_AS_STAT			0x0000
#define NFS_FA_OPTIONS_FORCE_SYNC			0x2000 /* See statx */
#define NFS_FA_OPTIONS_DONT_SYNC			0x4000 /* See statx */

#define NFS_FA_VALID_TIME_CREATE			0x00001UL
#define NFS_FA_VALID_TIME_BACKUP			0x00002UL
#define NFS_FA_VALID_ARCHIVE				0x00004UL
#define NFS_FA_VALID_HIDDEN				0x00008UL
#define NFS_FA_VALID_SYSTEM				0x00010UL
#define NFS_FA_VALID_OWNER				0x00020UL
#define NFS_FA_VALID_OWNER_GROUP			0x00040UL
#define NFS_FA_VALID_ATIME				0x00080UL
#define NFS_FA_VALID_MTIME				0x00100UL
#define NFS_FA_VALID_CTIME				0x00200UL
#define NFS_FA_VALID_OFFLINE				0x00400UL
#define NFS_FA_VALID_MODE				0x00800UL
#define NFS_FA_VALID_NLINK				0x01000UL
#define NFS_FA_VALID_BLKSIZE				0x02000UL
#define NFS_FA_VALID_INO				0x04000UL
#define NFS_FA_VALID_DEV				0x08000UL
#define NFS_FA_VALID_RDEV				0x10000UL
#define NFS_FA_VALID_SIZE				0x20000UL
#define NFS_FA_VALID_BLOCKS				0x40000UL

#define NFS_FA_VALID_ALL_ATTR_0 ( NFS_FA_VALID_TIME_CREATE | \
		NFS_FA_VALID_TIME_BACKUP | \
		NFS_FA_VALID_ARCHIVE | \
		NFS_FA_VALID_HIDDEN | \
		NFS_FA_VALID_SYSTEM | \
		NFS_FA_VALID_OWNER | \
		NFS_FA_VALID_OWNER_GROUP | \
		NFS_FA_VALID_ATIME | \
		NFS_FA_VALID_MTIME | \
		NFS_FA_VALID_CTIME | \
		NFS_FA_VALID_OFFLINE | \
		NFS_FA_VALID_MODE | \
		NFS_FA_VALID_NLINK | \
		NFS_FA_VALID_BLKSIZE | \
		NFS_FA_VALID_INO | \
		NFS_FA_VALID_DEV | \
		NFS_FA_VALID_RDEV | \
		NFS_FA_VALID_SIZE | \
		NFS_FA_VALID_BLOCKS)

#define NFS_FA_FLAG_ARCHIVE				(1UL << 0)
#define NFS_FA_FLAG_HIDDEN				(1UL << 1)
#define NFS_FA_FLAG_SYSTEM				(1UL << 2)
#define NFS_FA_FLAG_OFFLINE				(1UL << 3)

struct nfs_ioctl_timespec {
	__s64		tv_sec;
	__s64		tv_nsec;
};

struct nfs_ioctl_nfs4_statx {
	__s32		real_fd;		/* real FD to use,
						   -1 means use current file */
	__u32		fa_options;

	__u64		fa_request[2];		/* Attributes to retrieve */
	__u64		fa_valid[2];		/* Attributes set */

	struct nfs_ioctl_timespec fa_time_backup;/* Backup time */
	struct nfs_ioctl_timespec fa_btime;     /* Birth time */
	__u64		fa_flags;		/* Flag attributes */
	/* Ordinary attributes follow */
	struct nfs_ioctl_timespec fa_atime;	/* Access time */
	struct nfs_ioctl_timespec fa_mtime;	/* Modify time */
	struct nfs_ioctl_timespec fa_ctime;	/* Change time */
	__u32		fa_owner_uid;		/* Owner User ID */
	__u32		fa_group_gid;		/* Primary Group ID */
	__u32		fa_mode;		/* Mode */
	__u32	 	fa_nlink;
	__u32		fa_blksize;
	__u32		fa_spare;		/* Alignment */
	__u64		fa_ino;
	__u32		fa_dev;
	__u32		fa_rdev;
	__s64		fa_size;
	__s64		fa_blocks;
	__u64 		fa_padding[4];
};

struct nfs_ioctl_nfs4_access {
	/* input */
	__u64		ac_flags;		/* operation flags */
	/* output */
	__u64		ac_mask;		/* NFS raw ACCESS reply mask */
};

#define NFS_AC_FLAG_EACCESS (1UL << 0)

/*
 * NFS stats. The good thing with these values is that NFSv3 errors are
 * a superset of NFSv2 errors (with the exception of NFSERR_WFLUSH which
 * no-one uses anyway), so we can happily mix code as long as we make sure
 * no NFSv3 errors are returned to NFSv2 clients.
 * Error codes that have a `--' in the v2 column are not part of the
 * standard, but seem to be widely used nevertheless.
 */
 enum nfs_stat {
	NFS_OK = 0,			/* v2 v3 v4 */
	NFSERR_PERM = 1,		/* v2 v3 v4 */
	NFSERR_NOENT = 2,		/* v2 v3 v4 */
	NFSERR_IO = 5,			/* v2 v3 v4 */
	NFSERR_NXIO = 6,		/* v2 v3 v4 */
	NFSERR_EAGAIN = 11,		/* v2 v3 */
	NFSERR_ACCES = 13,		/* v2 v3 v4 */
	NFSERR_EXIST = 17,		/* v2 v3 v4 */
	NFSERR_XDEV = 18,		/*    v3 v4 */
	NFSERR_NODEV = 19,		/* v2 v3 v4 */
	NFSERR_NOTDIR = 20,		/* v2 v3 v4 */
	NFSERR_ISDIR = 21,		/* v2 v3 v4 */
	NFSERR_INVAL = 22,		/* v2 v3 v4 */
	NFSERR_FBIG = 27,		/* v2 v3 v4 */
	NFSERR_NOSPC = 28,		/* v2 v3 v4 */
	NFSERR_ROFS = 30,		/* v2 v3 v4 */
	NFSERR_MLINK = 31,		/*    v3 v4 */
	NFSERR_OPNOTSUPP = 45,		/* v2 v3 */
	NFSERR_NAMETOOLONG = 63,	/* v2 v3 v4 */
	NFSERR_NOTEMPTY = 66,		/* v2 v3 v4 */
	NFSERR_DQUOT = 69,		/* v2 v3 v4 */
	NFSERR_STALE = 70,		/* v2 v3 v4 */
	NFSERR_REMOTE = 71,		/* v2 v3 */
	NFSERR_WFLUSH = 99,		/* v2    */
	NFSERR_BADHANDLE = 10001,	/*    v3 v4 */
	NFSERR_NOT_SYNC = 10002,	/*    v3 */
	NFSERR_BAD_COOKIE = 10003,	/*    v3 v4 */
	NFSERR_NOTSUPP = 10004,		/*    v3 v4 */
	NFSERR_TOOSMALL = 10005,	/*    v3 v4 */
	NFSERR_SERVERFAULT = 10006,	/*    v3 v4 */
	NFSERR_BADTYPE = 10007,		/*    v3 v4 */
	NFSERR_JUKEBOX = 10008,		/*    v3 v4 */
	NFSERR_SAME = 10009,		/*       v4 */
	NFSERR_DENIED = 10010,		/*       v4 */
	NFSERR_EXPIRED = 10011,		/*       v4 */
	NFSERR_LOCKED = 10012,		/*       v4 */
	NFSERR_GRACE = 10013,		/*       v4 */
	NFSERR_FHEXPIRED = 10014,	/*       v4 */
	NFSERR_SHARE_DENIED = 10015,	/*       v4 */
	NFSERR_WRONGSEC = 10016,	/*       v4 */
	NFSERR_CLID_INUSE = 10017,	/*       v4 */
	NFSERR_RESOURCE = 10018,	/*       v4 */
	NFSERR_MOVED = 10019,		/*       v4 */
	NFSERR_NOFILEHANDLE = 10020,	/*       v4 */
	NFSERR_MINOR_VERS_MISMATCH = 10021,   /* v4 */
	NFSERR_STALE_CLIENTID = 10022,	/*       v4 */
	NFSERR_STALE_STATEID = 10023,   /*       v4 */
	NFSERR_OLD_STATEID = 10024,     /*       v4 */
	NFSERR_BAD_STATEID = 10025,     /*       v4 */  
	NFSERR_BAD_SEQID = 10026,	/*       v4 */
	NFSERR_NOT_SAME = 10027,	/*       v4 */
	NFSERR_LOCK_RANGE = 10028,	/*       v4 */
	NFSERR_SYMLINK = 10029,		/*       v4 */
	NFSERR_RESTOREFH = 10030,	/*       v4 */
	NFSERR_LEASE_MOVED = 10031,	/*       v4 */
	NFSERR_ATTRNOTSUPP = 10032,	/*       v4 */
	NFSERR_NO_GRACE = 10033,	/*       v4 */
	NFSERR_RECLAIM_BAD = 10034,	/*       v4 */
	NFSERR_RECLAIM_CONFLICT = 10035,/*       v4 */
	NFSERR_BAD_XDR = 10036,		/*       v4 */
	NFSERR_LOCKS_HELD = 10037,	/*       v4 */
	NFSERR_OPENMODE = 10038,       /*       v4 */
	NFSERR_BADOWNER = 10039,       /*       v4 */
	NFSERR_BADCHAR = 10040,        /*       v4 */
	NFSERR_BADNAME = 10041,        /*       v4 */
	NFSERR_BAD_RANGE = 10042,      /*       v4 */
	NFSERR_LOCK_NOTSUPP = 10043,   /*       v4 */
	NFSERR_OP_ILLEGAL = 10044,     /*       v4 */
	NFSERR_DEADLOCK = 10045,       /*       v4 */
	NFSERR_FILE_OPEN = 10046,      /*       v4 */
	NFSERR_ADMIN_REVOKED = 10047,  /*       v4 */
	NFSERR_CB_PATH_DOWN = 10048,   /*       v4 */
};

/* NFSv2 file types - beware, these are not the same in NFSv3 */

enum nfs_ftype {
	NFNON = 0,
	NFREG = 1,
	NFDIR = 2,
	NFBLK = 3,
	NFCHR = 4,
	NFLNK = 5,
	NFSOCK = 6,
	NFBAD = 7,
	NFFIFO = 8
};

#endif /* _UAPI_LINUX_NFS_H */
