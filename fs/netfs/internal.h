/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Internal definitions for network filesystem support
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/netfs.h>
#include <linux/fscache.h>
#include <trace/events/netfs.h>
#include "xa_iterator.h"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "netfs: " fmt

/*
 * dio_helper.c
 */
ssize_t netfs_file_direct_write(struct netfs_dirty_region *region,
				struct kiocb *iocb, struct iov_iter *from);

/*
 * objects.c
 */
struct netfs_flush_group *netfs_get_flush_group(struct netfs_flush_group *group);
void netfs_put_flush_group(struct netfs_flush_group *group);
struct netfs_dirty_region *netfs_alloc_dirty_region(void);
struct netfs_dirty_region *netfs_get_dirty_region(struct netfs_i_context *ctx,
						  struct netfs_dirty_region *region,
						  enum netfs_region_trace what);
void netfs_free_dirty_region(struct netfs_i_context *ctx, struct netfs_dirty_region *region);
void netfs_put_dirty_region(struct netfs_i_context *ctx,
			    struct netfs_dirty_region *region,
			    enum netfs_region_trace what);
struct netfs_write_request *netfs_alloc_write_request(struct address_space *mapping,
						      bool is_dio);
void netfs_get_write_request(struct netfs_write_request *wreq,
			     enum netfs_wreq_trace what);
void netfs_free_write_request(struct work_struct *work);
void netfs_put_write_request(struct netfs_write_request *wreq,
			     bool was_async, enum netfs_wreq_trace what);

static inline void netfs_see_write_request(struct netfs_write_request *wreq,
					   enum netfs_wreq_trace what)
{
	trace_netfs_ref_wreq(wreq->debug_id, refcount_read(&wreq->usage), what);
}

/*
 * read_helper.c
 */
extern unsigned int netfs_debug;

int netfs_prefetch_for_write(struct file *file, struct page *page, loff_t pos, size_t len,
			     bool always_fill);

/*
 * write_helper.c
 */
void netfs_writeback_worker(struct work_struct *work);
void netfs_flush_region(struct netfs_i_context *ctx,
			struct netfs_dirty_region *region,
			enum netfs_dirty_trace why);

/*
 * stats.c
 */
#ifdef CONFIG_NETFS_STATS
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
extern atomic_t netfs_n_rh_write;
extern atomic_t netfs_n_rh_write_begin;
extern atomic_t netfs_n_rh_write_done;
extern atomic_t netfs_n_rh_write_failed;
extern atomic_t netfs_n_rh_write_zskip;
extern atomic_t netfs_n_wh_region;
extern atomic_t netfs_n_wh_flush_group;
extern atomic_t netfs_n_wh_upload;
extern atomic_t netfs_n_wh_upload_done;
extern atomic_t netfs_n_wh_upload_failed;
extern atomic_t netfs_n_wh_wreq;
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

static inline bool netfs_is_cache_enabled(struct inode *inode)
{
	struct fscache_cookie *cookie = netfs_i_cookie(inode);

	return fscache_cookie_enabled(cookie) && cookie->cache_priv;
}

#else
#define netfs_stat(x) do {} while(0)
#define netfs_stat_d(x) do {} while(0)
#endif

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
