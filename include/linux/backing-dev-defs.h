#ifndef __LINUX_BACKING_DEV_DEFS_H
#define __LINUX_BACKING_DEV_DEFS_H

#include <linux/list.h>
#include <linux/radix-tree.h>
#include <linux/spinlock.h>
#include <linux/percpu_counter.h>
#include <linux/flex_proportions.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

struct page;
struct device;
struct dentry;

/*
 * Bits in bdi_writeback.state
 */
enum wb_state {
	/*
	 * The two congested flags are modified asynchronously and must be
	 * atomic.  The other flags are protected either by wb->list_lock
	 * or ->work_lock and don't need to be atomic if placed on separate
	 * fields.  The extra atomic operations don't really matter here.
	 * Let's keep them together and use atomic bitops.
	 */
	WB_async_congested,	/* The async (write) queue is getting full */
	WB_sync_congested,	/* The sync queue is getting full */
	WB_registered,		/* bdi_register() was done */
	WB_writeback_running,	/* Writeback is in progress */
	WB_has_dirty_io,	/* Dirty inodes on ->b_{dirty|io|more_io} */
};

typedef int (congested_fn)(void *, int);

enum wb_stat_item {
	WB_RECLAIMABLE,
	WB_WRITEBACK,
	WB_DIRTIED,
	WB_WRITTEN,
	NR_WB_STAT_ITEMS
};

#define WB_STAT_BATCH (8*(1+ilog2(nr_cpu_ids)))

/*
 * IWBL_* flags which occupy the lower bits of inode_wb_link->data.  The
 * upper bits point to bdi_writeback, so the number of these flags
 * determines the minimum alignment of bdi_writeback.
 */
enum {
	IWBL_FLAGS_BITS,
	IWBL_FLAGS_MASK		= (1UL << IWBL_FLAGS_BITS) - 1,
};

/*
 * Align bdi_writeback so that inode_wb_link->data can carry IWBL_* flags
 * in the lower bits but don't let it fall below that of ullong.
 */
#define BDI_WRITEBACK_ALIGN	\
	((1UL << IWBL_FLAGS_BITS) > __alignof(unsigned long long) ?	\
	 (1UL << IWBL_FLAGS_BITS) : __alignof(unsigned long long))

struct bdi_writeback {
	struct backing_dev_info *bdi;	/* our parent bdi */

	unsigned long state;		/* Always use atomic bitops on this */
	unsigned long last_old_flush;	/* last old data flush */

	struct list_head b_dirty;	/* dirty inodes */
	struct list_head b_io;		/* parked for writeback */
	struct list_head b_more_io;	/* parked for more writeback */
	spinlock_t list_lock;		/* protects the b_* lists */

	struct percpu_counter stat[NR_WB_STAT_ITEMS];

	unsigned long bw_time_stamp;	/* last time write bw is updated */
	unsigned long dirtied_stamp;
	unsigned long written_stamp;	/* pages written at bw_time_stamp */
	unsigned long write_bandwidth;	/* the estimated write bandwidth */
	unsigned long avg_write_bandwidth; /* further smoothed write bw, > 0 */

	/*
	 * The base dirty throttle rate, re-calculated on every 200ms.
	 * All the bdi tasks' dirty rate will be curbed under it.
	 * @dirty_ratelimit tracks the estimated @balanced_dirty_ratelimit
	 * in small steps and is much more smooth/stable than the latter.
	 */
	unsigned long dirty_ratelimit;
	unsigned long balanced_dirty_ratelimit;

	struct fprop_local_percpu completions;
	int dirty_exceeded;

	spinlock_t work_lock;		/* protects work_list & dwork scheduling */
	struct list_head work_list;
	struct delayed_work dwork;	/* work item used for writeback */

#ifdef CONFIG_CGROUP_WRITEBACK
	struct cgroup_subsys_state *blkcg_css; /* the blkcg we belong to */
	struct list_head blkcg_node;	/* anchored at blkcg->wb_list */
	union {
		struct list_head shutdown_node;
		struct rcu_head rcu;
	};
#endif
} __aligned(BDI_WRITEBACK_ALIGN);

struct backing_dev_info {
	struct list_head bdi_list;
	unsigned long ra_pages;	/* max readahead in PAGE_CACHE_SIZE units */
	unsigned int capabilities; /* Device capabilities */
	congested_fn *congested_fn; /* Function pointer if device is md/dm */
	void *congested_data;	/* Pointer to aux data for congested func */

	char *name;

	unsigned int min_ratio;
	unsigned int max_ratio, max_prop_frac;

	/*
	 * Sum of avg_write_bw of wbs with dirty inodes.  > 0 if there are
	 * any dirty wbs, which is depended upon by bdi_has_dirty().
	 */
	atomic_long_t tot_write_bandwidth;

	struct bdi_writeback wb; /* the root writeback info for this bdi */
#ifdef CONFIG_CGROUP_WRITEBACK
	struct radix_tree_root cgwb_tree; /* radix tree of !root cgroup wbs */
#endif
	wait_queue_head_t wb_waitq;

	struct device *dev;

	struct timer_list laptop_mode_wb_timer;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debug_dir;
	struct dentry *debug_stats;
#endif
};

/*
 * Used to link a dirty inode on a wb (bdi_writeback).  Each inode embeds
 * one at ->i_wb_link which is used for the root wb.
 */
struct inode_wb_link {
#ifdef CONFIG_CGROUP_WRITEBACK
	/*
	 * Upper bits point to the associated bdi_writeback.  Lower carry
	 * IWBL_* flags.  Use iwbl_to_wb() to reach the bdi_writeback.
	 */
	unsigned long		data;
#endif
	unsigned long		dirtied_when;
	struct list_head	dirty_list;
};

/*
 * The following structure carries context used during page and inode
 * dirtying.  Should be initialized with init_dirty_{inode|page}_context().
 */
struct dirty_context {
	struct page		*page;
	struct inode		*inode;
	struct address_space	*mapping;
	struct bdi_writeback	*wb;
};

enum {
	BLK_RW_ASYNC	= 0,
	BLK_RW_SYNC	= 1,
};

void clear_wb_congested(struct bdi_writeback *wb, int sync);
void set_wb_congested(struct bdi_writeback *wb, int sync);

static inline void clear_bdi_congested(struct backing_dev_info *bdi, int sync)
{
	clear_wb_congested(&bdi->wb, sync);
}

static inline void set_bdi_congested(struct backing_dev_info *bdi, int sync)
{
	set_wb_congested(&bdi->wb, sync);
}

#endif	/* __LINUX_BACKING_DEV_DEFS_H */
