/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Internal definitions for network filesystem support
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/netfs.h>
#include <linux/fscache.h>
#include <trace/events/netfs.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "netfs: " fmt

/*
 * buffered_flush.c
 */
void netfs_check_dirty_list(char c, const struct list_head *list,
			    const struct netfs_dirty_region *star);
int netfs_flush_conflicting_writes(struct netfs_inode *ctx, struct file *file,
				   loff_t start, size_t len, struct folio *unlock_this);

/*
 * buffered_read.c
 */
void netfs_rreq_unlock_folios(struct netfs_io_request *rreq);
int netfs_prefetch_for_write(struct file *file, struct folio *folio, size_t len);

/*
 * buffered_write.c
 */
void netfs_discard_regions(struct netfs_inode *ctx,
			   struct list_head *discards,
			   enum netfs_region_trace why);
bool netfs_are_regions_mergeable(struct netfs_inode *ctx,
				 const struct netfs_dirty_region *a,
				 const struct netfs_dirty_region *b);
struct netfs_dirty_region *netfs_find_region(struct netfs_inode *ctx,
					     pgoff_t first, pgoff_t last);
void netfs_split_off_front(struct netfs_inode *ctx,
			   struct netfs_dirty_region *front,
			   struct netfs_dirty_region *back,
			   pgoff_t front_last,
			   enum netfs_dirty_trace why);
void netfs_rreq_do_write_to_cache(struct netfs_io_request *rreq);

/*
 * crypto.c
 */
int netfs_alloc_buffer(struct xarray *xa, pgoff_t index, unsigned int nr_pages);
bool netfs_encrypt(struct netfs_io_request *wreq);
void netfs_decrypt(struct netfs_io_request *rreq);

/*
 * direct_read.c
 */
int netfs_dio_copy_bounce_to_dest(struct netfs_io_request *rreq);

/*
 * direct_write.c
 */
ssize_t netfs_direct_write_iter(struct kiocb *iocb, struct iov_iter *from);

/*
 * io.c
 */
void netfs_rreq_completed(struct netfs_io_request *rreq, bool was_async);
ssize_t netfs_begin_read(struct netfs_io_request *rreq, bool sync);

/*
 * main.c
 */
extern unsigned int netfs_debug;
extern struct list_head netfs_io_requests;
extern struct list_head netfs_regions;
extern spinlock_t netfs_proc_lock;

#ifdef CONFIG_PROC_FS
static inline void netfs_proc_add_rreq(struct netfs_io_request *rreq)
{
	spin_lock(&netfs_proc_lock);
	list_add_tail_rcu(&rreq->proc_link, &netfs_io_requests);
	spin_unlock(&netfs_proc_lock);
}
static inline void netfs_proc_del_rreq(struct netfs_io_request *rreq)
{
	if (!list_empty(&rreq->proc_link)) {
		spin_lock(&netfs_proc_lock);
		list_del_rcu(&rreq->proc_link);
		spin_unlock(&netfs_proc_lock);
	}
}
#else
static inline void netfs_proc_add_rreq(struct netfs_io_request *rreq) {}
static inline void netfs_proc_del_rreq(struct netfs_io_request *rreq) {}
#endif

#ifdef CONFIG_PROC_FS
static inline void netfs_proc_add_region(struct netfs_dirty_region *region)
{
	spin_lock(&netfs_proc_lock);
	list_add_tail_rcu(&region->proc_link, &netfs_regions);
	spin_unlock(&netfs_proc_lock);
}
static inline void netfs_proc_del_region(struct netfs_dirty_region *region)
{
	spin_lock(&netfs_proc_lock);
	list_del_rcu(&region->proc_link);
	spin_unlock(&netfs_proc_lock);
}
#else
static inline void netfs_proc_add_region(struct netfs_dirty_region *region) {}
static inline void netfs_proc_del_region(struct netfs_dirty_region *region) {}
#endif

/*
 * misc.c
 */
extern atomic_long_t netfs_write_credit;

int netfs_xa_store_and_mark(struct xarray *xa, unsigned long index,
			    struct folio *folio, bool put_mark,
			    bool pagecache_mark, bool dirty_mark,
			    gfp_t gfp_mask);
int netfs_add_folios_to_buffer(struct xarray *buffer, pgoff_t index, pgoff_t to,
			       gfp_t gfp_mask);
int netfs_set_up_buffer(struct xarray *buffer,
			struct address_space *mapping,
			struct readahead_control *ractl,
			struct folio *keep,
			pgoff_t have_index, unsigned int have_folios);
void netfs_clear_buffer(struct xarray *buffer);
void netfs_deduct_write_credit(struct netfs_dirty_region *region, size_t credits);
void netfs_return_write_credit(struct netfs_dirty_region *region);
int netfs_wait_for_credit(struct writeback_control *wbc);

/*
 * objects.c
 */
extern atomic_t netfs_region_debug_ids;

struct netfs_io_request *netfs_alloc_request(struct address_space *mapping,
					     struct file *file,
					     loff_t start, size_t len,
					     enum netfs_io_origin origin);
void netfs_get_request(struct netfs_io_request *rreq, enum netfs_rreq_ref_trace what);
void netfs_clear_subrequests(struct netfs_io_request *rreq, bool was_async);
void netfs_put_request(struct netfs_io_request *rreq, bool was_async,
		       enum netfs_rreq_ref_trace what);
struct netfs_io_subrequest *netfs_alloc_subrequest(struct netfs_io_request *rreq);
struct netfs_dirty_region *netfs_alloc_dirty_region(gfp_t gfp);
struct netfs_dirty_region *netfs_get_dirty_region(struct netfs_inode *ctx,
						  struct netfs_dirty_region *region,
						  enum netfs_region_trace what);
void netfs_free_dirty_region(struct netfs_inode *ctx, struct netfs_dirty_region *region);
void netfs_put_dirty_region(struct netfs_inode *ctx,
			    struct netfs_dirty_region *region,
			    enum netfs_region_trace what);

static inline void netfs_see_request(struct netfs_io_request *rreq,
				     enum netfs_rreq_ref_trace what)
{
	trace_netfs_rreq_ref(rreq->debug_id, refcount_read(&rreq->ref), what);
}

/*
 * output.c
 */
int netfs_begin_write(struct netfs_io_request *wreq, bool may_wait);

/*
 * stats.c
 */
#ifdef CONFIG_NETFS_STATS
extern atomic_t netfs_n_rh_dio_read;
extern atomic_t netfs_n_rh_readahead;
extern atomic_t netfs_n_rh_readpage;
extern atomic_t netfs_n_rh_rreq;
extern atomic_t netfs_n_rh_sreq;
extern atomic_t netfs_n_rh_download;
extern atomic_t netfs_n_rh_download_done;
extern atomic_t netfs_n_rh_download_failed;
extern atomic_t netfs_n_rh_download_instead;
extern atomic_t netfs_n_rh_read;
extern atomic_t netfs_n_rh_read_done;
extern atomic_t netfs_n_rh_read_failed;
extern atomic_t netfs_n_rh_zero;
extern atomic_t netfs_n_rh_short_read;
extern atomic_t netfs_n_rh_write_begin;
extern atomic_t netfs_n_rh_write_zskip;
extern atomic_t netfs_n_wh_region;
extern atomic_t netfs_n_wh_upload;
extern atomic_t netfs_n_wh_upload_done;
extern atomic_t netfs_n_wh_upload_failed;
extern atomic_t netfs_n_wh_write;
extern atomic_t netfs_n_wh_write_done;
extern atomic_t netfs_n_wh_write_failed;


static inline void netfs_stat(atomic_t *stat)
{
	atomic_inc(stat);
}

static inline void netfs_stat_d(atomic_t *stat)
{
	atomic_dec(stat);
}

#else
#define netfs_stat(x) do {} while(0)
#define netfs_stat_d(x) do {} while(0)
#endif

/*
 * Miscellaneous functions.
 */
static inline bool netfs_is_cache_enabled(struct netfs_inode *ctx)
{
#if IS_ENABLED(CONFIG_FSCACHE)
	struct fscache_cookie *cookie = ctx->cache;

	return fscache_cookie_valid(cookie) && cookie->cache_priv &&
		fscache_cookie_enabled(cookie);
#else
	return false;
#endif
}

/*
 * Check to see if a buffer aligns with the crypto unit block size.  If it
 * doesn't the crypto layer is going to copy all the data - in which case
 * relying on the crypto op for a free copy is pointless.
 */
static inline bool netfs_is_crypto_aligned(struct netfs_io_request *rreq,
					   struct iov_iter *iter)
{
	struct netfs_inode *ctx = netfs_inode(rreq->inode);
	unsigned long align, mask = (1UL << ctx->min_bshift) - 1;

	if (!ctx->min_bshift)
		return true;
	align = iov_iter_alignment(iter);
	return (align & mask) == 0;
}

static inline struct netfs_dirty_region *netfs_prev_region(struct netfs_inode *ctx,
							   struct netfs_dirty_region *region)
{
	if (list_is_first(&region->dirty_link, &ctx->dirty_regions))
		return NULL;
	return list_prev_entry(region, dirty_link);
}

static inline struct netfs_dirty_region *netfs_next_region(struct netfs_inode *ctx,
							   struct netfs_dirty_region *region)
{
	if (list_is_last(&region->dirty_link, &ctx->dirty_regions))
		return NULL;
	return list_next_entry(region, dirty_link);
}

/*****************************************************************************/
/*
 * debug tracing
 */
#define dbgprintk(FMT, ...) \
	printk("[%-6.6s] "FMT"\n", current->comm, ##__VA_ARGS__)

#define kenter(FMT, ...) dbgprintk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) dbgprintk("<== %s()"FMT"", __func__, ##__VA_ARGS__)
#define kdebug(FMT, ...) dbgprintk(FMT, ##__VA_ARGS__)

#ifdef __KDEBUG
#define _enter(FMT, ...) kenter(FMT, ##__VA_ARGS__)
#define _leave(FMT, ...) kleave(FMT, ##__VA_ARGS__)
#define _debug(FMT, ...) kdebug(FMT, ##__VA_ARGS__)

#elif defined(CONFIG_NETFS_DEBUG)
#define _enter(FMT, ...)			\
do {						\
	if (netfs_debug)			\
		kenter(FMT, ##__VA_ARGS__);	\
} while (0)

#define _leave(FMT, ...)			\
do {						\
	if (netfs_debug)			\
		kleave(FMT, ##__VA_ARGS__);	\
} while (0)

#define _debug(FMT, ...)			\
do {						\
	if (netfs_debug)			\
		kdebug(FMT, ##__VA_ARGS__);	\
} while (0)

#else
#define _enter(FMT, ...) no_printk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define _leave(FMT, ...) no_printk("<== %s()"FMT"", __func__, ##__VA_ARGS__)
#define _debug(FMT, ...) no_printk(FMT, ##__VA_ARGS__)
#endif
