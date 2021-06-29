/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Network filesystem support services.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * See:
 *
 *	Documentation/filesystems/netfs_library.rst
 *
 * for a description of the network filesystem interface declared here.
 */

#ifndef _LINUX_NETFS_H
#define _LINUX_NETFS_H

#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/uio.h>

struct scatterlist;
enum netfs_sreq_ref_trace;

/*
 * Overload PG_private_2 to give us PG_fscache - this is used to indicate that
 * a page is currently backed by a local disk cache
 */
#define folio_test_fscache(folio)	folio_test_private_2(folio)
#define PageFsCache(page)		PagePrivate2((page))
#define SetPageFsCache(page)		SetPagePrivate2((page))
#define ClearPageFsCache(page)		ClearPagePrivate2((page))
#define TestSetPageFsCache(page)	TestSetPagePrivate2((page))
#define TestClearPageFsCache(page)	TestClearPagePrivate2((page))

/**
 * folio_start_fscache - Start an fscache write on a folio.
 * @folio: The folio.
 *
 * Call this function before writing a folio to a local cache.  Starting a
 * second write before the first one finishes is not allowed.
 */
static inline void folio_start_fscache(struct folio *folio)
{
	VM_BUG_ON_FOLIO(folio_test_private_2(folio), folio);
	folio_get(folio);
	folio_set_private_2(folio);
}

/**
 * folio_end_fscache - End an fscache write on a folio.
 * @folio: The folio.
 *
 * Call this function after the folio has been written to the local cache.
 * This will wake any sleepers waiting on this folio.
 */
static inline void folio_end_fscache(struct folio *folio)
{
	folio_end_private_2(folio);
}

/**
 * folio_wait_fscache - Wait for an fscache write on this folio to end.
 * @folio: The folio.
 *
 * If this folio is currently being written to a local cache, wait for
 * the write to finish.  Another write may start after this one finishes,
 * unless the caller holds the folio lock.
 */
static inline void folio_wait_fscache(struct folio *folio)
{
	folio_wait_private_2(folio);
}

/**
 * folio_wait_fscache_killable - Wait for an fscache write on this folio to end.
 * @folio: The folio.
 *
 * If this folio is currently being written to a local cache, wait
 * for the write to finish or for a fatal signal to be received.
 * Another write may start after this one finishes, unless the caller
 * holds the folio lock.
 *
 * Return:
 * - 0 if successful.
 * - -EINTR if a fatal signal was encountered.
 */
static inline int folio_wait_fscache_killable(struct folio *folio)
{
	return folio_wait_private_2_killable(folio);
}

static inline void set_page_fscache(struct page *page)
{
	folio_start_fscache(page_folio(page));
}

static inline void end_page_fscache(struct page *page)
{
	folio_end_private_2(page_folio(page));
}

static inline void wait_on_page_fscache(struct page *page)
{
	folio_wait_private_2(page_folio(page));
}

static inline int wait_on_page_fscache_killable(struct page *page)
{
	return folio_wait_private_2_killable(page_folio(page));
}

/* Marks used on xarray-based buffers */
#define NETFS_BUF_PUT_MARK	XA_MARK_0	/* - Page needs putting  */
#define NETFS_BUF_PAGECACHE_MARK XA_MARK_1	/* - Page needs wb/dirty flag wrangling */
#define NETFS_BUF_DIRTY_MARK	XA_MARK_2	/* - Page was dirty */

enum netfs_io_source {
	NETFS_FILL_WITH_ZEROES,
	NETFS_DOWNLOAD_FROM_SERVER,
	NETFS_READ_FROM_CACHE,
	NETFS_INVALID_READ,
	NETFS_UPLOAD_TO_SERVER,
	NETFS_WRITE_TO_CACHE,
	NETFS_INVALID_WRITE,
} __mode(byte);

typedef void (*netfs_io_terminated_t)(void *priv, ssize_t transferred_or_error,
				      bool was_async);

/*
 * Per-inode context.  This wraps the VFS inode.
 */
struct netfs_inode {
	struct inode		inode;		/* The VFS inode */
	const struct netfs_request_ops *ops;
	struct mutex		wb_mutex;	/* Mutex controlling writeback setup */
	struct list_head	writebacks;	/* List of writebacks in progress */
	struct list_head	dirty_regions;	/* List of dirty regions in the pagecache */
	spinlock_t		dirty_lock;	/* Lock for dirty_regions & writebacks */
#if IS_ENABLED(CONFIG_FSCACHE)
	struct fscache_cookie	*cache;
#endif
	loff_t			remote_i_size;	/* Size of the remote file */
	loff_t			zero_point;	/* Size after which we assume there's no data
						 * on the server */
	unsigned long		flags;
#define NETFS_ICTX_ENCRYPTED	0		/* The file contents are encrypted */
#define NETFS_ICTX_DO_RMW	1		/* Set if RMW required (no write streaming) */
	unsigned char		min_bshift;	/* log2 min block size for bounding box or 0 */
	unsigned char		obj_bshift;	/* log2 storage object shift (ceph/pnfs) or 0 */
	unsigned char		crypto_bshift;	/* log2 of crypto block size */
	unsigned char		cache_order;	/* Log2 of cache's required page alignment */
};

/*
 * Resources required to do operations on a cache.
 */
struct netfs_cache_resources {
	const struct netfs_cache_ops	*ops;
	void				*cache_priv;
	void				*cache_priv2;
	unsigned int			debug_id;	/* Cookie debug ID */
	unsigned int			inval_counter;	/* object->inval_counter at begin_op */
};

/*
 * Descriptor for a single component subrequest.  Each operation represents an
 * individual read/write from/to a server, a cache, a journal, etc..
 *
 * The buffer iterator is persistent for the life of the subrequest struct and
 * the pages it points to can be relied on to exist for the duration.
 */
struct netfs_io_subrequest {
	struct work_struct	work;
	struct netfs_io_request *rreq;		/* Supervising I/O request */
	struct list_head	rreq_link;	/* Link in rreq->subrequests */
	struct iov_iter		iter;		/* Iterator for this subrequest */
	loff_t			start;		/* Where to start the I/O */
	size_t			len;		/* Size of the I/O */
	size_t			transferred;	/* Amount of data transferred */
	refcount_t		ref;
	short			error;		/* 0 or error that occurred */
	unsigned short		debug_index;	/* Index in list (for debugging output) */
	unsigned int		max_nr_segs;	/* 0 or max number of segments in an iterator */
	enum netfs_io_source	source;		/* Where to read from/write to */
	unsigned long		flags;
#define NETFS_SREQ_COPY_TO_CACHE	0	/* Set if should copy the data to the cache */
#define NETFS_SREQ_CLEAR_TAIL		1	/* Set if the rest of the read should be cleared */
#define NETFS_SREQ_SHORT_IO		2	/* Set if the I/O was short */
#define NETFS_SREQ_SEEK_DATA_READ	3	/* Set if ->read() should SEEK_DATA first */
#define NETFS_SREQ_NO_PROGRESS		4	/* Set if we didn't manage to read any data */
#define NETFS_SREQ_ONDEMAND		5	/* Set if it's from on-demand read mode */
};

enum netfs_io_origin {
	NETFS_READAHEAD,		/* This read was triggered by readahead */
	NETFS_READPAGE,			/* This read is a synchronous read */
	NETFS_READ_FOR_WRITE,		/* This read is to prepare a write */
	NETFS_WRITEBACK,		/* This write was triggered by writepages */
	NETFS_DIO_READ,			/* This read is a direct I/O read */
	NETFS_DIO_WRITE,		/* This read is a direct I/O write */
	nr__netfs_io_origin
} __mode(byte);

enum netfs_buffering {
	NETFS_INVALID,			/* Buffering unset */
	NETFS_DIRECT,			/* Do I/O to/from ->direct_iter */
	NETFS_DIRECT_BV,		/* Do I/O to/from ->direct_iter/bv[] */
	NETFS_BUFFER,			/* Do I/O to/from ->buffer */
	NETFS_BOUNCE,			/* Do I/O to/from ->bounce */
	NETFS_ENC_DIRECT_TO_BOUNCE,	/* Encrypt from ->direct_iter to ->bounce */
	NETFS_ENC_BUFFER_TO_BOUNCE,	/* Encrypt from ->buffer to ->bounce */
	NETFS_COPY_ENC_BOUNCE,		/* Copy ->direct to ->bounce, then encrypt in place */
	NETFS_BUFFER_DEC,		/* Decrypt ->buffer in place */
	NETFS_BOUNCE_DEC_TO_BUFFER,	/* Decrypt from ->bounce to ->buffer */
	NETFS_BOUNCE_DEC_TO_DIRECT,	/* Decrypt from ->bounce to ->direct_iter */
	NETFS_BOUNCE_DEC_TO_DIRECT_BV,	/* Decrypt from ->bounce to ->direct_iter/bv[] */
	NETFS_BOUNCE_DEC_COPY,		/* Decrypt ->bounce in place, then copy to ->direct */
	NETFS_BOUNCE_DEC_COPY_BV,	/* Decrypt ->bounce in place, then copy to ->direct_bv */
} __mode(byte);

/*
 * Descriptor for an I/O helper request.  This is used to make multiple I/O
 * operations to a variety of data stores and then stitch the result together.
 */
struct netfs_io_request {
	union {
		struct work_struct work;
		struct rcu_head rcu;
	};
	struct inode		*inode;		/* The file being accessed */
	struct address_space	*mapping;	/* The mapping being accessed */
	struct kiocb		*iocb;		/* AIO completion vector */
	struct netfs_cache_resources cache_resources;
	struct list_head	wb_link;	/* Link in ictx->writebacks */
	struct list_head	proc_link;	/* Link in netfs_iorequests */
	struct list_head	regions;	/* List of regions to be uploaded */
	struct list_head	subrequests;	/* Contributory I/O operations */
	struct xarray		buffer;		/* Buffer to hold raw data */
	struct xarray		bounce;		/* Bounce buffer (eg. for crypto/compression) */
	struct bio_vec		*direct_bv;	/* DIO buffer list (when handling iovec-iter) */
	struct iov_iter		direct_iter;	/* Iterator for direct I/O */
	void			*netfs_priv;	/* Private data for the netfs */
	unsigned int		direct_bv_count; /* Number of elements in bv[] */
	unsigned int		debug_id;
	unsigned int		rsize;		/* Maximum read size (0 for none) */
	unsigned int		wsize;		/* Maximum write size (0 for none) */
	unsigned int		alignment;	/* Preferred alignment (1 for none) */
	unsigned int		subreq_counter;	/* Next subreq->debug_index */
	atomic_t		nr_outstanding;	/* Number of ops in progress */
	size_t			submitted;	/* Amount submitted for I/O so far */
	size_t			len;		/* Length of the request */
	size_t			transferred;	/* Amount to be indicated as transferred */
	short			error;		/* 0 or error that occurred */
	enum netfs_io_origin	origin;		/* Origin of the request */
	enum netfs_buffering	buffering;	/* Method of buffering */
	loff_t			i_size;		/* Size of the file */
	loff_t			start;		/* Start position */
	pgoff_t			first;		/* First page included */
	pgoff_t			last;		/* Last page included */
	pgoff_t			no_unlock_folio; /* Don't unlock this folio after read */
	refcount_t		ref;
	unsigned long		flags;
#define NETFS_RREQ_INCOMPLETE_IO	0	/* Some ioreqs terminated short or with error */
#define NETFS_RREQ_COPY_TO_CACHE	1	/* Need to write to the cache */
#define NETFS_RREQ_NO_UNLOCK_FOLIO	2	/* Don't unlock no_unlock_folio on completion */
#define NETFS_RREQ_DONT_UNLOCK_FOLIOS	3	/* Don't unlock the folios on completion */
#define NETFS_RREQ_FAILED		4	/* The request failed */
#define NETFS_RREQ_IN_PROGRESS		5	/* Unlocked when the request completes */
#define NETFS_RREQ_NONBLOCK		6	/* Don't block if possible (O_NONBLOCK) */
#define NETFS_RREQ_BLOCKED		7	/* We blocked */
#define NETFS_RREQ_WRITE_TO_CACHE	8	/* Need to write to the cache */
#define NETFS_RREQ_UPLOAD_TO_SERVER	9	/* Need to write to the server */
#define NETFS_RREQ_CONTENT_ENCRYPTION	10	/* Content encryption is in use */
#define NETFS_RREQ_SETTING_UP		11	/* Setting up the writeback */
	const struct netfs_request_ops *netfs_ops;
	void (*cleanup)(struct netfs_io_request *req);
};

enum netfs_region_type {
	NETFS_MODIFIED_REGION,
	NETFS_COPY_TO_CACHE,
} __mode(byte);

/*
 * Descriptor for a dirty region that has a common set of parameters and can
 * feasibly be written back in one go.  These are held in an ordered list.
 *
 * Regions are not allowed to overlap, though they may be merged.
 */
struct netfs_dirty_region {
	struct list_head	dirty_link;	/* Link in netfs_inode::dirty_regions */
	struct list_head	proc_link;	/* Link in /proc/fs/netfs/regions */
	void			*netfs_priv;	/* Private data for the netfs */
	size_t			credit;		/* Amount of credit used */
	pgoff_t			first;		/* First page index in region */
	pgoff_t			last;		/* Last page index in region */
	unsigned long long	from;		/* File position of start of modified part */
	unsigned long long	to;		/* File position of end of modified part */
	unsigned int		debug_id;
	enum netfs_region_type	type;
	refcount_t		ref;
};

/*
 * Operations the network filesystem can/must provide to the helpers.
 */
struct netfs_request_ops {
	unsigned int	io_request_size;	/* Alloc size for netfs_io_request struct */
	unsigned int	io_subrequest_size;	/* Alloc size for netfs_io_subrequest struct */
	int (*init_request)(struct netfs_io_request *rreq, struct file *file);
	void (*free_request)(struct netfs_io_request *rreq);
	int (*begin_cache_operation)(struct netfs_io_request *rreq);

	/* Read request handling */
	void (*expand_readahead)(struct netfs_io_request *rreq);
	bool (*clamp_length)(struct netfs_io_subrequest *subreq);
	void (*issue_read)(struct netfs_io_subrequest *subreq);
	bool (*is_still_valid)(struct netfs_io_request *rreq);
	int (*check_write_begin)(struct file *file, loff_t pos, unsigned len,
				 struct folio *folio, void **_fsdata);
	void (*done)(struct netfs_io_request *rreq);

	/* Modification handling */
	void (*update_i_size)(struct inode *inode, loff_t i_size);
	int (*validate_for_write)(struct inode *inode, struct file *file);

	/* Write request handling */
	void (*create_write_requests)(struct netfs_io_request *wreq);
	void (*invalidate_cache)(struct netfs_io_request *wreq);

	/* Content encryption */
	int (*encrypt_block)(struct netfs_io_request *wreq, loff_t pos, size_t len,
			     struct scatterlist *source_sg, unsigned int n_source,
			     struct scatterlist *dest_sg, unsigned int n_dest);
	int (*decrypt_block)(struct netfs_io_request *rreq, loff_t pos, size_t len,
			     struct scatterlist *source_sg, unsigned int n_source,
			     struct scatterlist *dest_sg, unsigned int n_dest);

	/* Dirty region handling */
	void (*init_dirty_region)(struct netfs_dirty_region *region, struct file *file);
	void (*split_dirty_region)(struct netfs_dirty_region *front,
				   struct netfs_dirty_region *back);
	void (*free_dirty_region)(struct netfs_dirty_region *region);
	bool (*are_regions_mergeable)(struct netfs_inode *ctx,
				      const struct netfs_dirty_region *front,
				      const struct netfs_dirty_region *back);
	bool (*is_write_compatible)(struct netfs_inode *ctx,
				    struct file *file,
				    const struct netfs_dirty_region *front);
};

/*
 * How to handle reading from a hole.
 */
enum netfs_read_from_hole {
	NETFS_READ_HOLE_IGNORE,
	NETFS_READ_HOLE_CLEAR,
	NETFS_READ_HOLE_FAIL,
};

/*
 * Table of operations for access to a cache.  This is obtained by
 * rreq->ops->begin_cache_operation().
 */
struct netfs_cache_ops {
	/* End an operation */
	void (*end_operation)(struct netfs_cache_resources *cres);

	/* Read data from the cache */
	int (*read)(struct netfs_cache_resources *cres,
		    loff_t start_pos,
		    struct iov_iter *iter,
		    enum netfs_read_from_hole read_hole,
		    netfs_io_terminated_t term_func,
		    void *term_func_priv);

	/* Write data to the cache */
	int (*write)(struct netfs_cache_resources *cres,
		     loff_t start_pos,
		     struct iov_iter *iter,
		     netfs_io_terminated_t term_func,
		     void *term_func_priv);

	/* Expand readahead request */
	void (*expand_readahead)(struct netfs_cache_resources *cres,
				 loff_t *_start, size_t *_len, loff_t i_size);

	/* Prepare a read operation, shortening it to a cached/uncached
	 * boundary as appropriate.
	 */
	enum netfs_io_source (*prepare_read)(struct netfs_io_subrequest *subreq,
					     loff_t i_size);

	/* Prepare a write operation, working out what part of the write we can
	 * actually do.
	 */
	int (*prepare_write)(struct netfs_cache_resources *cres,
			     loff_t *_start, size_t *_len, loff_t i_size,
			     bool no_space_allocated_yet);

	/* Query the occupancy of the cache in a region, returning where the
	 * next chunk of data starts and how long it is.
	 */
	int (*query_occupancy)(struct netfs_cache_resources *cres,
			       loff_t start, size_t len, size_t granularity,
			       loff_t *_data_start, size_t *_data_len);
};

struct readahead_control;
extern void netfs_readahead(struct readahead_control *);
int netfs_read_folio(struct file *, struct folio *);
extern int netfs_write_begin(struct netfs_inode *,
			     struct file *, struct address_space *,
			     loff_t, unsigned int, struct folio **,
			     void **);
extern ssize_t netfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from);
extern vm_fault_t netfs_page_mkwrite(struct vm_fault *vmf);
extern int netfs_writepages(struct address_space *mapping, struct writeback_control *wbc);
extern void netfs_invalidate_folio(struct folio *folio, size_t offset, size_t length);
extern bool netfs_release_folio(struct folio *folio, gfp_t gfp);

extern void netfs_subreq_terminated(struct netfs_io_subrequest *, ssize_t, bool);
extern void netfs_get_subrequest(struct netfs_io_subrequest *subreq,
				 enum netfs_sreq_ref_trace what);
extern void netfs_put_subrequest(struct netfs_io_subrequest *subreq,
				 bool was_async, enum netfs_sreq_ref_trace what);
extern void netfs_stats_show(struct seq_file *);
extern ssize_t netfs_direct_read_iter(struct kiocb *, struct iov_iter *);
extern struct netfs_io_subrequest *netfs_create_write_request(
	struct netfs_io_request *wreq, enum netfs_io_source dest,
	loff_t start, size_t len, work_func_t worker);
extern void netfs_write_subrequest_terminated(void *_op, ssize_t transferred_or_error,
					      bool was_async);
extern void netfs_queue_write_request(struct netfs_io_subrequest *subreq);

/**
 * netfs_inode - Get the netfs inode context from the inode
 * @inode: The inode to query
 *
 * Get the netfs lib inode context from the network filesystem's inode.  The
 * context struct is expected to directly follow on from the VFS inode struct.
 */
static inline struct netfs_inode *netfs_inode(struct inode *inode)
{
	return container_of(inode, struct netfs_inode, inode);
}

/**
 * netfs_inode_init - Initialise a netfslib inode context
 * @ctx: The netfs inode to initialise
 * @ops: The netfs's operations list
 *
 * Initialise the netfs library context struct.  This is expected to follow on
 * directly from the VFS inode struct.
 */
static inline void netfs_inode_init(struct netfs_inode *ctx,
				    const struct netfs_request_ops *ops)
{
	ctx->ops = ops;
	ctx->remote_i_size = i_size_read(&ctx->inode);
	ctx->zero_point = ctx->remote_i_size;
	INIT_LIST_HEAD(&ctx->writebacks);
	INIT_LIST_HEAD(&ctx->dirty_regions);
	spin_lock_init(&ctx->dirty_lock);
	mutex_init(&ctx->wb_mutex);
#if IS_ENABLED(CONFIG_FSCACHE)
	ctx->cache = NULL;
#endif
}

/**
 * netfs_resize_file - Note that a file got resized
 * @ctx: The netfs inode being resized
 * @new_i_size: The new file size
 *
 * Inform the netfs lib that a file got resized so that it can adjust its state.
 */
static inline void netfs_resize_file(struct netfs_inode *ctx, loff_t new_i_size)
{
	ctx->remote_i_size = new_i_size;
	if (new_i_size < ctx->zero_point)
		ctx->zero_point = new_i_size;
}

/**
 * netfs_i_cookie - Get the cache cookie from the inode
 * @ctx: The netfs inode to query
 *
 * Get the caching cookie (if enabled) from the network filesystem's inode.
 */
static inline struct fscache_cookie *netfs_i_cookie(struct netfs_inode *ctx)
{
#if IS_ENABLED(CONFIG_FSCACHE)
	return ctx->cache;
#else
	return NULL;
#endif
}

#endif /* _LINUX_NETFS_H */
