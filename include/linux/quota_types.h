/*
 * Split from <linux/quota.h>
 */
#ifndef _LINUX_QUOTA_TYPES_H
#define _LINUX_QUOTA_TYPES_H

#include <linux/rwsem.h>
#include <linux/time.h>
#include <linux/uidgid.h>
#include <linux/projid.h>

#include <uapi/linux/quota.h>

#undef USRQUOTA
#undef GRPQUOTA
#undef PRJQUOTA

enum quota_type {
	USRQUOTA = 0,		/* element used for user quotas */
	GRPQUOTA = 1,		/* element used for group quotas */
	PRJQUOTA = 2,		/* element used for project quotas */
};

/* Masks for quota types when used as a bitmask */
#define QTYPE_MASK_USR (1 << USRQUOTA)
#define QTYPE_MASK_GRP (1 << GRPQUOTA)
#define QTYPE_MASK_PRJ (1 << PRJQUOTA)

typedef __kernel_uid32_t qid_t; /* Type in which we store ids in memory */
typedef long long qsize_t;	/* Type in which we store sizes */

struct kqid {			/* Type in which we store the quota identifier */
	union {
		kuid_t uid;
		kgid_t gid;
		kprojid_t projid;
	};
	enum quota_type type;  /* USRQUOTA (uid) or GRPQUOTA (gid) or PRJQUOTA (projid) */
};

/*
 * Data for one user/group kept in memory
 */
struct mem_dqblk {
	qsize_t dqb_bhardlimit;	/* absolute limit on disk blks alloc */
	qsize_t dqb_bsoftlimit;	/* preferred limit on disk blks */
	qsize_t dqb_curspace;	/* current used space */
	qsize_t dqb_rsvspace;   /* current reserved space for delalloc*/
	qsize_t dqb_ihardlimit;	/* absolute limit on allocated inodes */
	qsize_t dqb_isoftlimit;	/* preferred inode limit */
	qsize_t dqb_curinodes;	/* current # allocated inodes */
	time64_t dqb_btime;	/* time limit for excessive disk use */
	time64_t dqb_itime;	/* time limit for excessive inode use */
};

/*
 * Data for one quotafile kept in memory
 */
struct quota_format_type;

struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;		/* Id of the dqi_format - used when turning
				 * quotas on after remount RW */
	struct list_head dqi_dirty_list;	/* List of dirty dquots [dq_list_lock] */
	unsigned long dqi_flags;	/* DFQ_ flags [dq_data_lock] */
	unsigned int dqi_bgrace;	/* Space grace time [dq_data_lock] */
	unsigned int dqi_igrace;	/* Inode grace time [dq_data_lock] */
	qsize_t dqi_max_spc_limit;	/* Maximum space limit [static] */
	qsize_t dqi_max_ino_limit;	/* Maximum inode limit [static] */
	void *dqi_priv;
};

struct super_block;

/* Mask for flags passed to userspace */
#define DQF_GETINFO_MASK (DQF_ROOT_SQUASH | DQF_SYS_FILE)
/* Mask for flags modifiable from userspace */
#define DQF_SETINFO_MASK DQF_ROOT_SQUASH

enum {
	DQF_INFO_DIRTY_B = DQF_PRIVATE,
};
#define DQF_INFO_DIRTY (1 << DQF_INFO_DIRTY_B)	/* Is info dirty? */

enum {
	DQST_LOOKUPS,
	DQST_DROPS,
	DQST_READS,
	DQST_WRITES,
	DQST_CACHE_HITS,
	DQST_ALLOC_DQUOTS,
	DQST_FREE_DQUOTS,
	DQST_SYNCS,
	_DQST_DQSTAT_LAST
};

struct quota_info {
	unsigned int flags;			/* Flags for diskquotas on this device */
	struct rw_semaphore dqio_sem;		/* Lock quota file while I/O in progress */
	struct inode *files[MAXQUOTAS];		/* inodes of quotafiles */
	struct mem_dqinfo info[MAXQUOTAS];	/* Information for each quota type */
	const struct quota_format_ops *ops[MAXQUOTAS];	/* Operations for each type */
};

#endif /* _QUOTA_ */
