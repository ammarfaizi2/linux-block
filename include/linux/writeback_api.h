/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/writeback_api.h
 */
#ifndef WRITEBACK_API_H
#define WRITEBACK_API_H

#include <linux/writeback.h>

#include <linux/spinlock_api.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/flex_proportions.h>
#include <linux/backing-dev-defs.h>
#include <linux/blk_types.h>
#include <linux/blk-cgroup.h>

static inline int wbc_to_write_flags(struct writeback_control *wbc)
{
	int flags = 0;

	if (wbc->punt_to_cgroup)
		flags = REQ_CGROUP_PUNT;

	if (wbc->sync_mode == WB_SYNC_ALL)
		flags |= REQ_SYNC;
	else if (wbc->for_kupdate || wbc->for_background)
		flags |= REQ_BACKGROUND;

	return flags;
}

#ifdef CONFIG_CGROUP_WRITEBACK
#define wbc_blkcg_css(wbc) \
	((wbc)->wb ? (wbc)->wb->blkcg_css : blkcg_root_css)
#else
#define wbc_blkcg_css(wbc)		(blkcg_root_css)
#endif /* CONFIG_CGROUP_WRITEBACK */

/*
 * fs/fs-writeback.c
 */	
struct bdi_writeback;
void writeback_inodes_sb(struct super_block *, enum wb_reason reason);
void writeback_inodes_sb_nr(struct super_block *, unsigned long nr,
							enum wb_reason reason);
void try_to_writeback_inodes_sb(struct super_block *sb, enum wb_reason reason);
void sync_inodes_sb(struct super_block *);
void wakeup_flusher_threads(enum wb_reason reason);
void wakeup_flusher_threads_bdi(struct backing_dev_info *bdi,
				enum wb_reason reason);
void inode_wait_for_writeback(struct inode *inode);
void inode_io_list_del(struct inode *inode);

/* writeback.h requires fs.h; it, too, is not included from here. */
static inline void wait_on_inode(struct inode *inode)
{
	might_sleep();
	wait_on_bit(&inode->i_state, __I_NEW, TASK_UNINTERRUPTIBLE);
}

#ifdef CONFIG_CGROUP_WRITEBACK

#include <linux/cgroup.h>
#include <linux/bio.h>

void __inode_attach_wb(struct inode *inode, struct page *page);
void wbc_attach_and_unlock_inode(struct writeback_control *wbc,
				 struct inode *inode)
	__releases(&inode->i_lock);
void wbc_detach_inode(struct writeback_control *wbc);
void wbc_account_cgroup_owner(struct writeback_control *wbc, struct page *page,
			      size_t bytes);
int cgroup_writeback_by_id(u64 bdi_id, int memcg_id,
			   enum wb_reason reason, struct wb_completion *done);
void cgroup_writeback_umount(void);
bool cleanup_offline_cgwb(struct bdi_writeback *wb);

/**
 * inode_attach_wb - associate an inode with its wb
 * @inode: inode of interest
 * @page: page being dirtied (may be NULL)
 *
 * If @inode doesn't have its wb, associate it with the wb matching the
 * memcg of @page or, if @page is NULL, %current.  May be called w/ or w/o
 * @inode->i_lock.
 */
static inline void inode_attach_wb(struct inode *inode, struct page *page)
{
	if (!inode->i_wb)
		__inode_attach_wb(inode, page);
}

/**
 * inode_detach_wb - disassociate an inode from its wb
 * @inode: inode of interest
 *
 * @inode is being freed.  Detach from its wb.
 */
static inline void inode_detach_wb(struct inode *inode)
{
	if (inode->i_wb) {
		WARN_ON_ONCE(!(inode->i_state & I_CLEAR));
		wb_put(inode->i_wb);
		inode->i_wb = NULL;
	}
}

/**
 * wbc_attach_fdatawrite_inode - associate wbc and inode for fdatawrite
 * @wbc: writeback_control of interest
 * @inode: target inode
 *
 * This function is to be used by __filemap_fdatawrite_range(), which is an
 * alternative entry point into writeback code, and first ensures @inode is
 * associated with a bdi_writeback and attaches it to @wbc.
 */
static inline void wbc_attach_fdatawrite_inode(struct writeback_control *wbc,
					       struct inode *inode)
{
	spin_lock(&inode->i_lock);
	inode_attach_wb(inode, NULL);
	wbc_attach_and_unlock_inode(wbc, inode);
}

/**
 * wbc_init_bio - writeback specific initializtion of bio
 * @wbc: writeback_control for the writeback in progress
 * @bio: bio to be initialized
 *
 * @bio is a part of the writeback in progress controlled by @wbc.  Perform
 * writeback specific initialization.  This is used to apply the cgroup
 * writeback context.  Must be called after the bio has been associated with
 * a device.
 */
static inline void wbc_init_bio(struct writeback_control *wbc, struct bio *bio)
{
	/*
	 * pageout() path doesn't attach @wbc to the inode being written
	 * out.  This is intentional as we don't want the function to block
	 * behind a slow cgroup.  Ultimately, we want pageout() to kick off
	 * regular writeback instead of writing things out itself.
	 */
	if (wbc->wb)
		bio_associate_blkg_from_css(bio, wbc->wb->blkcg_css);
}

#else	/* CONFIG_CGROUP_WRITEBACK */

static inline void inode_attach_wb(struct inode *inode, struct page *page)
{
}

static inline void inode_detach_wb(struct inode *inode)
{
}

static inline void wbc_attach_and_unlock_inode(struct writeback_control *wbc,
					       struct inode *inode)
	__releases(&inode->i_lock)
{
	spin_unlock(&inode->i_lock);
}

static inline void wbc_attach_fdatawrite_inode(struct writeback_control *wbc,
					       struct inode *inode)
{
}

static inline void wbc_detach_inode(struct writeback_control *wbc)
{
}

static inline void wbc_init_bio(struct writeback_control *wbc, struct bio *bio)
{
}

static inline void wbc_account_cgroup_owner(struct writeback_control *wbc,
					    struct page *page, size_t bytes)
{
}

static inline void cgroup_writeback_umount(void)
{
}

#endif	/* CONFIG_CGROUP_WRITEBACK */

/*
 * mm/page-writeback.c
 */
void laptop_io_completion(struct backing_dev_info *info);
void laptop_sync_completion(void);
void laptop_mode_timer_fn(struct timer_list *t);
bool node_dirty_ok(struct pglist_data *pgdat);
int wb_domain_init(struct wb_domain *dom, gfp_t gfp);
#ifdef CONFIG_CGROUP_WRITEBACK
void wb_domain_exit(struct wb_domain *dom);
#endif

extern struct wb_domain global_wb_domain;

/* These are exported to sysctl. */
extern int dirty_background_ratio;
extern unsigned long dirty_background_bytes;
extern int vm_dirty_ratio;
extern unsigned long vm_dirty_bytes;
extern unsigned int dirty_writeback_interval;
extern unsigned int dirty_expire_interval;
extern unsigned int dirtytime_expire_interval;
extern int vm_highmem_is_dirtyable;
extern int laptop_mode;

int dirty_background_ratio_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
int dirty_background_bytes_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
int dirty_ratio_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
int dirty_bytes_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
int dirtytime_interval_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
int dirty_writeback_centisecs_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);

void global_dirty_limits(unsigned long *pbackground, unsigned long *pdirty);
unsigned long wb_calc_thresh(struct bdi_writeback *wb, unsigned long thresh);

void wb_update_bandwidth(struct bdi_writeback *wb);
void balance_dirty_pages_ratelimited(struct address_space *mapping);
bool wb_over_bg_thresh(struct bdi_writeback *wb);

typedef int (*writepage_t)(struct page *page, struct writeback_control *wbc,
				void *data);

int generic_writepages(struct address_space *mapping,
		       struct writeback_control *wbc);
void tag_pages_for_writeback(struct address_space *mapping,
			     pgoff_t start, pgoff_t end);
int write_cache_pages(struct address_space *mapping,
		      struct writeback_control *wbc, writepage_t writepage,
		      void *data);
int do_writepages(struct address_space *mapping, struct writeback_control *wbc);
void writeback_set_ratelimit(void);
void tag_pages_for_writeback(struct address_space *mapping,
			     pgoff_t start, pgoff_t end);

bool filemap_dirty_folio(struct address_space *mapping, struct folio *folio);
void folio_account_redirty(struct folio *folio);
static inline void account_page_redirty(struct page *page)
{
	folio_account_redirty(page_folio(page));
}
bool folio_redirty_for_writepage(struct writeback_control *, struct folio *);
bool redirty_page_for_writepage(struct writeback_control *, struct page *);

void sb_mark_inode_writeback(struct inode *inode);
void sb_clear_inode_writeback(struct inode *inode);

#endif		/* WRITEBACK_API_H */
