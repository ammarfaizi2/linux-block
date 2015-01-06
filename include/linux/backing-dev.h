/*
 * include/linux/backing-dev.h
 *
 * low-level device information and state which is propagated up through
 * to high-level code.
 */

#ifndef _LINUX_BACKING_DEV_H
#define _LINUX_BACKING_DEV_H

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/blk-cgroup.h>

#include <linux/backing-dev-defs.h>

int __must_check bdi_init(struct backing_dev_info *bdi);
void bdi_destroy(struct backing_dev_info *bdi);

__printf(3, 4)
int bdi_register(struct backing_dev_info *bdi, struct device *parent,
		const char *fmt, ...);
int bdi_register_dev(struct backing_dev_info *bdi, dev_t dev);
void bdi_unregister(struct backing_dev_info *bdi);
int __must_check bdi_setup_and_register(struct backing_dev_info *, char *, unsigned int);
void bdi_start_writeback(struct backing_dev_info *bdi, long nr_pages,
			enum wb_reason reason);
void bdi_start_background_writeback(struct backing_dev_info *bdi);
void wb_workfn(struct work_struct *work);
void wb_wakeup_delayed(struct bdi_writeback *wb);

extern spinlock_t bdi_lock;
extern struct list_head bdi_list;

extern struct workqueue_struct *bdi_wq;

static inline bool wb_has_dirty_io(struct bdi_writeback *wb)
{
	return test_bit(WB_has_dirty_io, &wb->state);
}

static inline bool bdi_has_dirty_io(struct backing_dev_info *bdi)
{
	/*
	 * @bdi->tot_write_bandwidth is guaranteed to be > 0 if there are
	 * any dirty wbs.  See wb_update_write_bandwidth().
	 */
	return atomic_long_read(&bdi->tot_write_bandwidth);
}

static inline void __add_wb_stat(struct bdi_writeback *wb,
				 enum wb_stat_item item, s64 amount)
{
	__percpu_counter_add(&wb->stat[item], amount, WB_STAT_BATCH);
}

static inline void __inc_wb_stat(struct bdi_writeback *wb,
				 enum wb_stat_item item)
{
	__add_wb_stat(wb, item, 1);
}

static inline void inc_wb_stat(struct bdi_writeback *wb, enum wb_stat_item item)
{
	unsigned long flags;

	local_irq_save(flags);
	__inc_wb_stat(wb, item);
	local_irq_restore(flags);
}

static inline void __dec_wb_stat(struct bdi_writeback *wb,
				 enum wb_stat_item item)
{
	__add_wb_stat(wb, item, -1);
}

static inline void dec_wb_stat(struct bdi_writeback *wb, enum wb_stat_item item)
{
	unsigned long flags;

	local_irq_save(flags);
	__dec_wb_stat(wb, item);
	local_irq_restore(flags);
}

static inline s64 wb_stat(struct bdi_writeback *wb, enum wb_stat_item item)
{
	return percpu_counter_read_positive(&wb->stat[item]);
}

static inline s64 __wb_stat_sum(struct bdi_writeback *wb,
				enum wb_stat_item item)
{
	return percpu_counter_sum_positive(&wb->stat[item]);
}

static inline s64 wb_stat_sum(struct bdi_writeback *wb, enum wb_stat_item item)
{
	s64 sum;
	unsigned long flags;

	local_irq_save(flags);
	sum = __wb_stat_sum(wb, item);
	local_irq_restore(flags);

	return sum;
}

extern void wb_writeout_inc(struct bdi_writeback *wb);

/*
 * maximal error of a stat counter.
 */
static inline unsigned long wb_stat_error(struct bdi_writeback *wb)
{
#ifdef CONFIG_SMP
	return nr_cpu_ids * WB_STAT_BATCH;
#else
	return 1;
#endif
}

int bdi_set_min_ratio(struct backing_dev_info *bdi, unsigned int min_ratio);
int bdi_set_max_ratio(struct backing_dev_info *bdi, unsigned int max_ratio);

/*
 * Flags in backing_dev_info::capability
 *
 * The first three flags control whether dirty pages will contribute to the
 * VM's accounting and whether writepages() should be called for dirty pages
 * (something that would not, for example, be appropriate for ramfs)
 *
 * WARNING: these flags are closely related and should not normally be
 * used separately.  The BDI_CAP_NO_ACCT_AND_WRITEBACK combines these
 * three flags into a single convenience macro.
 *
 * BDI_CAP_NO_ACCT_DIRTY:  Dirty pages shouldn't contribute to accounting
 * BDI_CAP_NO_WRITEBACK:   Don't write pages back
 * BDI_CAP_NO_ACCT_WB:     Don't automatically account writeback pages
 *
 * These flags let !MMU mmap() govern direct device mapping vs immediate
 * copying more easily for MAP_PRIVATE, especially for ROM filesystems.
 *
 * BDI_CAP_MAP_COPY:       Copy can be mapped (MAP_PRIVATE)
 * BDI_CAP_MAP_DIRECT:     Can be mapped directly (MAP_SHARED)
 * BDI_CAP_READ_MAP:       Can be mapped for reading
 * BDI_CAP_WRITE_MAP:      Can be mapped for writing
 * BDI_CAP_EXEC_MAP:       Can be mapped for execution
 *
 * BDI_CAP_SWAP_BACKED:    Count shmem/tmpfs objects as swap-backed.
 *
 * BDI_CAP_STRICTLIMIT:    Keep number of dirty pages below bdi threshold.
 *
 * BDI_CAP_CGROUP_WRITEBACK: Supports cgroup-aware writeback.
 */
#define BDI_CAP_NO_ACCT_DIRTY	0x00000001
#define BDI_CAP_NO_WRITEBACK	0x00000002
#define BDI_CAP_MAP_COPY	0x00000004
#define BDI_CAP_MAP_DIRECT	0x00000008
#define BDI_CAP_READ_MAP	0x00000010
#define BDI_CAP_WRITE_MAP	0x00000020
#define BDI_CAP_EXEC_MAP	0x00000040
#define BDI_CAP_NO_ACCT_WB	0x00000080
#define BDI_CAP_SWAP_BACKED	0x00000100
#define BDI_CAP_STABLE_WRITES	0x00000200
#define BDI_CAP_STRICTLIMIT	0x00000400
#define BDI_CAP_CGROUP_WRITEBACK 0x00000800

#define BDI_CAP_VMFLAGS \
	(BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP)

#define BDI_CAP_NO_ACCT_AND_WRITEBACK \
	(BDI_CAP_NO_WRITEBACK | BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_ACCT_WB)

#if defined(VM_MAYREAD) && \
	(BDI_CAP_READ_MAP != VM_MAYREAD || \
	 BDI_CAP_WRITE_MAP != VM_MAYWRITE || \
	 BDI_CAP_EXEC_MAP != VM_MAYEXEC)
#error please change backing_dev_info::capabilities flags
#endif

extern struct backing_dev_info default_backing_dev_info;
extern struct backing_dev_info noop_backing_dev_info;

int writeback_in_progress(struct backing_dev_info *bdi);

static inline int wb_congested(struct bdi_writeback *wb, int bdi_bits)
{
	struct backing_dev_info *bdi = wb->bdi;

	if (bdi->congested_fn)
		return bdi->congested_fn(bdi->congested_data, bdi_bits);
	return wb->state & bdi_bits;
}

long congestion_wait(int sync, long timeout);
long wait_iff_congested(struct zone *zone, int sync, long timeout);
int pdflush_proc_obsolete(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);

static inline bool bdi_cap_stable_pages_required(struct backing_dev_info *bdi)
{
	return bdi->capabilities & BDI_CAP_STABLE_WRITES;
}

static inline bool bdi_cap_writeback_dirty(struct backing_dev_info *bdi)
{
	return !(bdi->capabilities & BDI_CAP_NO_WRITEBACK);
}

static inline bool bdi_cap_account_dirty(struct backing_dev_info *bdi)
{
	return !(bdi->capabilities & BDI_CAP_NO_ACCT_DIRTY);
}

static inline bool bdi_cap_account_writeback(struct backing_dev_info *bdi)
{
	/* Paranoia: BDI_CAP_NO_WRITEBACK implies BDI_CAP_NO_ACCT_WB */
	return !(bdi->capabilities & (BDI_CAP_NO_ACCT_WB |
				      BDI_CAP_NO_WRITEBACK));
}

static inline bool bdi_cap_swap_backed(struct backing_dev_info *bdi)
{
	return bdi->capabilities & BDI_CAP_SWAP_BACKED;
}

static inline bool mapping_cap_writeback_dirty(struct address_space *mapping)
{
	return bdi_cap_writeback_dirty(mapping->backing_dev_info);
}

static inline bool mapping_cap_account_dirty(struct address_space *mapping)
{
	return bdi_cap_account_dirty(mapping->backing_dev_info);
}

static inline bool mapping_cap_swap_backed(struct address_space *mapping)
{
	return bdi_cap_swap_backed(mapping->backing_dev_info);
}

static inline int bdi_sched_wait(void *word)
{
	schedule();
	return 0;
}

static inline struct backing_dev_info *inode_to_bdi(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (sb_is_blkdev_sb(sb))
		return inode->i_mapping->backing_dev_info;

	return sb->s_bdi;
}

void init_dirty_page_context(struct dirty_context *dctx, struct page *page,
			     struct address_space *mapping);
void init_dirty_inode_context(struct dirty_context *dctx, struct inode *inode);

#ifdef CONFIG_CGROUP_WRITEBACK

void cgwb_blkcg_released(struct cgroup_subsys_state *blkcg_css);
int __cgwb_create(struct backing_dev_info *bdi,
		  struct cgroup_subsys_state *blkcg_css);
int mapping_congested(struct address_space *mapping, struct task_struct *task,
		      int bdi_bits);

/**
 * mapping_cgwb_enabled - test whether cgroup writeback is enabled on a mapping
 * @mapping: address_space of interest
 *
 * cgroup writeback requires support from both the bdi and filesystem.
 * Test whether @mapping has both.
 */
static inline bool mapping_cgwb_enabled(struct address_space *mapping)
{
	struct backing_dev_info *bdi = mapping->backing_dev_info;
	struct inode *inode = mapping->host;

	return bdi_cap_account_dirty(bdi) &&
		(bdi->capabilities & BDI_CAP_CGROUP_WRITEBACK) &&
		inode && (inode->i_sb->s_type->fs_flags & FS_CGROUP_WRITEBACK);
}

/**
 * cgwb_lookup - lookup cgwb for a given blkcg on a bdi
 * @bdi: target bdi
 * @blkcg_css: target blkcg
 *
 * Look up the cgwb (cgroup bdi_writeback) for @blkcg_css on @bdi.  The
 * returned cgwb is accessible as long as @bdi and @blkcg_css stay alive.
 *
 * Returns the pointer to the found cgwb on success, NULL on failure.
 */
static inline struct bdi_writeback *
cgwb_lookup(struct backing_dev_info *bdi, struct cgroup_subsys_state *blkcg_css)
{
	struct bdi_writeback *cgwb;

	if (blkcg_css == blkcg_root_css)
		return &bdi->wb;

	/*
	 * RCU locking protects the radix tree itself.  The looked up cgwb
	 * is protected by the caller ensuring that @bdi and the blkcg w/
	 * @blkcg_id are alive.
	 */
	rcu_read_lock();
	cgwb = radix_tree_lookup(&bdi->cgwb_tree, blkcg_css->id);
	rcu_read_unlock();
	return cgwb;
}

/**
 * cgwb_lookup_create - try to lookup cgwb and create one if not found
 * @bdi: target bdi
 * @blkcg_css: cgroup_subsys_state of the target blkcg
 *
 * Try to look up the cgwb (cgroup bdi_writeback) for the blkcg with
 * @blkcg_css on @bdi.  If it doesn't exist, try to create one.  This
 * function can be called under any context without locking as long as @bdi
 * and @blkcg_css are kept alive.  See cgwb_lookup() for details.
 *
 * Returns the pointer to the found cgwb on success, NULL if such cgwb
 * doesn't exist and creation failed due to memory pressure.
 */
static inline struct bdi_writeback *
cgwb_lookup_create(struct backing_dev_info *bdi,
		   struct cgroup_subsys_state *blkcg_css)
{
	struct bdi_writeback *wb;

	do {
		wb = cgwb_lookup(bdi, blkcg_css);
		if (wb)
			return wb;
	} while (!__cgwb_create(bdi, blkcg_css));

	return NULL;
}

/**
 * page_cgwb_dirty - lookup the dirty cgwb of a page
 * @page: target page
 *
 * Returns the dirty cgwb (cgroup bdi_writeback) of @page.  The returned
 * wb is accessible as long as @page is dirty.
 */
static inline struct bdi_writeback *page_cgwb_dirty(struct page *page)
{
	struct backing_dev_info *bdi = page->mapping->backing_dev_info;
	struct bdi_writeback *wb = cgwb_lookup(bdi, page_blkcg_dirty(page));

	if (WARN_ON_ONCE(!wb))
		return &bdi->wb;
	return wb;
}

/**
 * page_cgwb_wb - lookup the writeback cgwb of a page
 * @page: target page
 *
 * Returns the writeback cgwb (cgroup bdi_writeback) of @page.  The
 * returned wb is accessible as long as @page is under writeback.
 */
static inline struct bdi_writeback *page_cgwb_wb(struct page *page)
{
	struct backing_dev_info *bdi = page->mapping->backing_dev_info;
	struct bdi_writeback *wb = cgwb_lookup(bdi, page_blkcg_wb(page));

	if (WARN_ON_ONCE(!wb))
		return &bdi->wb;
	return wb;
}

struct wb_iter {
	int			start_blkcg_id;
	struct radix_tree_iter	tree_iter;
	void			**slot;
};

static inline struct bdi_writeback *__wb_iter_next(struct wb_iter *iter,
						   struct backing_dev_info *bdi)
{
	struct radix_tree_iter *titer = &iter->tree_iter;

	WARN_ON_ONCE(!rcu_read_lock_held());

	if (iter->start_blkcg_id >= 0) {
		iter->slot = radix_tree_iter_init(titer, iter->start_blkcg_id);
		iter->start_blkcg_id = -1;
	} else {
		iter->slot = radix_tree_next_slot(iter->slot, titer, 0);
	}

	if (!iter->slot)
		iter->slot = radix_tree_next_chunk(&bdi->cgwb_tree, titer, 0);
	if (iter->slot)
		return *iter->slot;
	return NULL;
}

static inline struct bdi_writeback *__wb_iter_init(struct wb_iter *iter,
						   struct backing_dev_info *bdi,
						   int start_blkcg_id)
{
	iter->start_blkcg_id = start_blkcg_id;

	if (start_blkcg_id)
		return __wb_iter_next(iter, bdi);
	else
		return &bdi->wb;
}

/**
 * bdi_for_each_wb - walk all wb's of a bdi in ascending blkcg ID order
 * @wb_cur: cursor struct bdi_writeback pointer
 * @bdi: bdi to walk wb's of
 * @iter: pointer to struct wb_iter to be used as iteration buffer
 * @start_blkcg_id: blkcg ID to start iteration from
 *
 * Iterate @wb_cur through the wb's (bdi_writeback's) of @bdi in ascending
 * blkcg ID order starting from @start_blkcg_id.  @iter is struct wb_iter
 * to be used as temp storage during iteration.  rcu_read_lock() must be
 * held throughout iteration.
 */
#define bdi_for_each_wb(wb_cur, bdi, iter, start_blkcg_id)		\
	for ((wb_cur) = __wb_iter_init(iter, bdi, start_blkcg_id);	\
	     (wb_cur); (wb_cur) = __wb_iter_next(iter, bdi))

#else	/* CONFIG_CGROUP_WRITEBACK */

static inline bool mapping_cgwb_enabled(struct address_space *mapping)
{
	return false;
}

static inline void cgwb_blkcg_released(struct cgroup_subsys_state *blkcg_css)
{
}

static inline int mapping_congested(struct address_space *mapping,
				    struct task_struct *task, int bdi_bits)
{
	return wb_congested(&mapping->backing_dev_info->wb, bdi_bits);
}

static inline struct bdi_writeback *
cgwb_lookup(struct backing_dev_info *bdi, struct cgroup_subsys_state *blkcg_css)
{
	return &bdi->wb;
}

static inline struct bdi_writeback *
cgwb_lookup_create(struct backing_dev_info *bdi,
		   struct cgroup_subsys_state *blkcg_css)
{
	return &bdi->wb;
}

static inline struct bdi_writeback *page_cgwb_dirty(struct page *page)
{
	return &page->mapping->backing_dev_info->wb;
}

static inline struct bdi_writeback *page_cgwb_wb(struct page *page)
{
	return &page->mapping->backing_dev_info->wb;
}

struct wb_iter {
	int		next_id;
};

#define bdi_for_each_wb(wb_cur, bdi, iter, start_blkcg_id)		\
	for ((iter)->next_id = (start_blkcg_id);			\
	     ({	(wb_cur) = !(iter)->next_id++ ? &(bdi)->wb : NULL;	\
	     }); )

#endif	/* CONFIG_CGROUP_WRITEBACK */

static inline int mapping_read_congested(struct address_space *mapping,
					 struct task_struct *task)
{
	return mapping_congested(mapping, task, 1 << WB_sync_congested);
}

static inline int mapping_write_congested(struct address_space *mapping,
					  struct task_struct *task)
{
	return mapping_congested(mapping, task, 1 << WB_async_congested);
}

static inline int mapping_rw_congested(struct address_space *mapping,
				       struct task_struct *task)
{
	return mapping_congested(mapping, task, (1 << WB_sync_congested) |
						(1 << WB_async_congested));
}

static inline int bdi_congested(struct backing_dev_info *bdi, int bdi_bits)
{
	return wb_congested(&bdi->wb, bdi_bits);
}

static inline int bdi_read_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, 1 << WB_sync_congested);
}

static inline int bdi_write_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, 1 << WB_async_congested);
}

static inline int bdi_rw_congested(struct backing_dev_info *bdi)
{
	return bdi_congested(bdi, (1 << WB_sync_congested) |
				  (1 << WB_async_congested));
}

#endif		/* _LINUX_BACKING_DEV_H */
