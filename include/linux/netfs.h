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

enum netfs_wreq_trace;

/*
 * Overload PG_private_2 to give us PG_fscache - this is used to indicate that
 * a page is currently backed by a local disk cache
 */
#define PageFsCache(page)		PagePrivate2((page))
#define SetPageFsCache(page)		SetPagePrivate2((page))
#define ClearPageFsCache(page)		ClearPagePrivate2((page))
#define TestSetPageFsCache(page)	TestSetPagePrivate2((page))
#define TestClearPageFsCache(page)	TestClearPagePrivate2((page))

/**
 * set_page_fscache - Set PG_fscache on a page and take a ref
 * @page: The page.
 *
 * Set the PG_fscache (PG_private_2) flag on a page and take the reference
 * needed for the VM to handle its lifetime correctly.  This sets the flag and
 * takes the reference unconditionally, so care must be taken not to set the
 * flag again if it's already set.
 */
static inline void set_page_fscache(struct page *page)
{
	set_page_private_2(page);
}

/**
 * end_page_fscache - Clear PG_fscache and release any waiters
 * @page: The page
 *
 * Clear the PG_fscache (PG_private_2) bit on a page and wake up any sleepers
 * waiting for this.  The page ref held for PG_private_2 being set is released.
 *
 * This is, for example, used when a netfs page is being written to a local
 * disk cache, thereby allowing writes to the cache for the same page to be
 * serialised.
 */
static inline void end_page_fscache(struct page *page)
{
	end_page_private_2(page);
}

/**
 * wait_on_page_fscache - Wait for PG_fscache to be cleared on a page
 * @page: The page to wait on
 *
 * Wait for PG_fscache (aka PG_private_2) to be cleared on a page.
 */
static inline void wait_on_page_fscache(struct page *page)
{
	wait_on_page_private_2(page);
}

/**
 * wait_on_page_fscache_killable - Wait for PG_fscache to be cleared on a page
 * @page: The page to wait on
 *
 * Wait for PG_fscache (aka PG_private_2) to be cleared on a page or until a
 * fatal signal is received by the calling task.
 *
 * Return:
 * - 0 if successful.
 * - -EINTR if a fatal signal was encountered.
 */
static inline int wait_on_page_fscache_killable(struct page *page)
{
	return wait_on_page_private_2_killable(page);
}

enum netfs_read_source {
	NETFS_FILL_WITH_ZEROES,
	NETFS_DOWNLOAD_FROM_SERVER,
	NETFS_READ_FROM_CACHE,
	NETFS_INVALID_READ,
} __mode(byte);

typedef void (*netfs_io_terminated_t)(void *priv, ssize_t transferred_or_error,
				      bool was_async);

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
 * Descriptor for a single component subrequest.
 */
struct netfs_read_subrequest {
	struct netfs_read_request *rreq;	/* Supervising read request */
	struct list_head	rreq_link;	/* Link in rreq->subrequests */
	struct iov_iter		iter;		/* Iterator for this subrequest */
	loff_t			start;		/* Where to start the I/O */
	size_t			len;		/* Size of the I/O */
	size_t			transferred;	/* Amount of data transferred */
	refcount_t		usage;
	short			error;		/* 0 or error that occurred */
	unsigned short		debug_index;	/* Index in list (for debugging output) */
	enum netfs_read_source	source;		/* Where to read from */
	unsigned long		flags;
#define NETFS_SREQ_WRITE_TO_CACHE	0	/* Set if should write to cache */
#define NETFS_SREQ_CLEAR_TAIL		1	/* Set if the rest of the read should be cleared */
#define NETFS_SREQ_SHORT_READ		2	/* Set if there was a short read from the cache */
#define NETFS_SREQ_SEEK_DATA_READ	3	/* Set if ->read() should SEEK_DATA first */
#define NETFS_SREQ_NO_PROGRESS		4	/* Set if we didn't manage to read any data */
};

/*
 * Descriptor for a read helper request.  This is used to make multiple I/O
 * requests on a variety of sources and then stitch the result together.
 */
struct netfs_read_request {
	struct work_struct	work;
	struct inode		*inode;		/* The file being accessed */
	struct address_space	*mapping;	/* The mapping being accessed */
	struct netfs_cache_resources cache_resources;
	struct list_head	subrequests;	/* Requests to fetch I/O from disk or net */
	struct xarray		buffer;		/* Decryption/decompression buffer */
	void			*netfs_priv;	/* Private data for the netfs */
	unsigned int		debug_id;
	atomic_t		nr_rd_ops;	/* Number of read ops in progress */
	atomic_t		nr_wr_ops;	/* Number of write ops in progress */
	size_t			submitted;	/* Amount submitted for I/O so far */
	size_t			len;		/* Length of the request */
	short			error;		/* 0 or error that occurred */
	loff_t			i_size;		/* Size of the file */
	loff_t			start;		/* Start position */
	pgoff_t			no_unlock_page;	/* Don't unlock this page after read */
	refcount_t		usage;
	unsigned long		flags;
#define NETFS_RREQ_INCOMPLETE_IO	0	/* Some ioreqs terminated short or with error */
#define NETFS_RREQ_WRITE_TO_CACHE	1	/* Need to write to the cache */
#define NETFS_RREQ_NO_UNLOCK_PAGE	2	/* Don't unlock no_unlock_page on completion */
#define NETFS_RREQ_DONT_UNLOCK_PAGES	3	/* Don't unlock the pages on completion */
#define NETFS_RREQ_FAILED		4	/* The request failed */
#define NETFS_RREQ_IN_PROGRESS		5	/* Unlocked when the request completes */
	const struct netfs_request_ops *netfs_ops;
};

/*
 * Per-inode description.  This must be directly after the inode struct.
 */
struct netfs_i_context {
	const struct netfs_request_ops *ops;
	struct list_head	pending_writes;	/* List of writes waiting to be begin */
	struct list_head	active_writes;	/* List of writes being applied */
	struct list_head	dirty_regions;	/* List of dirty regions in the pagecache */
	struct list_head	flush_groups;	/* Writeable region ordering queue */
	struct list_head	flush_queue;	/* Regions that need to be flushed */
#ifdef CONFIG_FSCACHE
	struct fscache_cookie	*cache;
#endif
	unsigned long		flags;
#define NETFS_ICTX_NEW_CONTENT	0		/* Set if file has new content (create/trunc-0) */
	spinlock_t		lock;
	unsigned int		rsize;		/* Maximum read size */
	unsigned int		wsize;		/* Maximum write size */
	unsigned int		bsize;		/* Min block size for bounding box */
	unsigned int		inval_counter;	/* Number of invalidations made */
	unsigned char		n_wstreams;	/* Number of write streams to allocate */
};

/*
 * Descriptor for a set of writes that will need to be flushed together.
 */
struct netfs_flush_group {
	struct list_head	group_link;	/* Link in i_context->flush_groups */
	struct list_head	region_list;	/* List of regions in this group */
	void			*netfs_priv;
	refcount_t		ref;
	bool			flush;
};

struct netfs_range {
	unsigned long long	start;		/* Start of region */
	unsigned long long	end;		/* End of region */
};

/* State of a netfs_dirty_region */
enum netfs_region_state {
	NETFS_REGION_IS_PENDING,	/* Proposed write is waiting on an active write */
	NETFS_REGION_IS_RESERVED,	/* Writable region is reserved, waiting on flushes */
	NETFS_REGION_IS_ACTIVE,		/* Write is actively modifying the pagecache */
	NETFS_REGION_IS_DIRTY,		/* Region is dirty */
	NETFS_REGION_IS_FLUSHING,	/* Region is being flushed */
	NETFS_REGION_IS_COMPLETE,	/* Region has been completed (stored/invalidated) */
} __attribute__((mode(byte)));

enum netfs_region_type {
	NETFS_REGION_ORDINARY,		/* Ordinary write */
	NETFS_REGION_DIO,		/* Direct I/O write */
	NETFS_REGION_DSYNC,		/* O_DSYNC/RWF_DSYNC write */
} __attribute__((mode(byte)));

/*
 * Descriptor for a dirty region that has a common set of parameters and can
 * feasibly be written back in one go.  These are held in an ordered list.
 *
 * Regions are not allowed to overlap, though they may be merged.
 */
struct netfs_dirty_region {
	struct netfs_flush_group *group;
	struct list_head	active_link;	/* Link in i_context->pending/active_writes */
	struct list_head	dirty_link;	/* Link in i_context->dirty_regions */
	struct list_head	flush_link;	/* Link in group->region_list or
						 * i_context->flush_queue */
	spinlock_t		lock;
	void			*netfs_priv;	/* Private data for the netfs */
	struct netfs_range	bounds;		/* Bounding box including all affected pages */
	struct netfs_range	reserved;	/* The region reserved against other writes */
	struct netfs_range	dirty;		/* The region that has been modified */
	loff_t			i_size;		/* Size of the file */
	enum netfs_region_type	type;
	enum netfs_region_state	state;
	unsigned long		flags;
#define NETFS_REGION_SYNC	0		/* Set if metadata sync required (RWF_SYNC) */
#define NETFS_REGION_FLUSH_Q	1		/* Set if region is on flush queue */
#define NETFS_REGION_SUPERSEDED	2		/* Set if region is being superseded */
	unsigned int		debug_id;
	refcount_t		ref;
};

enum netfs_write_dest {
	NETFS_UPLOAD_TO_SERVER,
	NETFS_WRITE_TO_CACHE,
	NETFS_INVALID_WRITE,
} __mode(byte);

/*
 * Descriptor for a write subrequest.  Each subrequest represents an individual
 * write to a server or a cache.
 */
struct netfs_write_subrequest {
	struct netfs_write_request *wreq;	/* Supervising write request */
	struct list_head	stream_link;	/* Link in stream->subrequests */
	loff_t			start;		/* Where to start the I/O */
	size_t			len;		/* Size of the I/O */
	size_t			transferred;	/* Amount of data transferred */
	refcount_t		usage;
	short			error;		/* 0 or error that occurred */
	unsigned short		debug_index;	/* Index in list (for debugging output) */
	unsigned char		stream_index;	/* Which stream we're part of */
	enum netfs_write_dest	dest;		/* Where to write to */
};

/*
 * Descriptor for a write stream.  Each stream represents a sequence of writes
 * to a destination, where a stream covers the entirety of the write request.
 * All of a stream goes to the same destination - and that destination might be
 * a server, a cache, a journal.
 *
 * Each stream may be split up into separate subrequests according to different
 * rules.
 */
struct netfs_write_stream {
	struct work_struct	work;
	struct list_head	subrequests;	/* The subrequests comprising this stream */
	enum netfs_write_dest	dest;		/* Where to write to */
	unsigned char		index;		/* Index in wreq->streams[] */
	short			error;		/* 0 or error that occurred */
};

/*
 * Descriptor for a write request.  This is used to manage the preparation and
 * storage of a sequence of dirty data - its compression/encryption and its
 * writing to one or more servers and the cache.
 *
 * The prepared data is buffered here, and then the streams are used to
 * distribute the buffer to various destinations (servers, caches, etc.).
 */
struct netfs_write_request {
	struct work_struct	work;
	struct inode		*inode;		/* The file being accessed */
	struct address_space	*mapping;	/* The mapping being accessed */
	struct netfs_dirty_region *region;	/* The region we're writing back */
	struct netfs_cache_resources cache_resources;
	struct xarray		buffer;		/* Buffer for encrypted/compressed data */
	struct iov_iter		source;		/* The iterator to be used */
	struct list_head	write_link;	/* Link in i_context->write_requests */
	void			*netfs_priv;	/* Private data for the netfs */
	unsigned int		debug_id;
	unsigned char		max_streams;	/* Number of streams allocated */
	unsigned char		n_streams;	/* Number of streams in use */
	short			error;		/* 0 or error that occurred */
	loff_t			i_size;		/* Size of the file */
	loff_t			start;		/* Start position */
	size_t			len;		/* Length of the request */
	pgoff_t			first;		/* First page included */
	pgoff_t			last;		/* Last page included */
	atomic_t		outstanding;	/* Number of outstanding writes */
	refcount_t		usage;
	unsigned long		flags;
#define NETFS_WREQ_WRITE_TO_CACHE	0	/* Need to write to the cache */
	const struct netfs_request_ops *netfs_ops;
	struct netfs_write_stream streams[];	/* Individual write streams */
};

enum netfs_write_compatibility {
	NETFS_WRITES_COMPATIBLE,	/* Dirty regions can be directly merged */
	NETFS_WRITES_SUPERSEDE,		/* Second write can supersede the first without first
					 * having to be flushed (eg. authentication, DSYNC) */
	NETFS_WRITES_INCOMPATIBLE,	/* Second write must wait for first (eg. DIO, ceph snap) */
};

/*
 * Operations the network filesystem can/must provide to the helpers.
 */
struct netfs_request_ops {
	/* Read request handling */
	void (*init_rreq)(struct netfs_read_request *rreq, struct file *file);
	int (*begin_cache_operation)(struct netfs_read_request *rreq);
	void (*expand_readahead)(struct netfs_read_request *rreq);
	bool (*clamp_length)(struct netfs_read_subrequest *subreq);
	void (*issue_op)(struct netfs_read_subrequest *subreq);
	bool (*is_still_valid)(struct netfs_read_request *rreq);
	int (*check_write_begin)(struct file *file, loff_t pos, unsigned len,
				 struct page *page, void **_fsdata);
	void (*done)(struct netfs_read_request *rreq);
	void (*cleanup)(struct address_space *mapping, void *netfs_priv);

	/* Dirty region handling */
	void (*init_dirty_region)(struct netfs_dirty_region *region, struct file *file);
	void (*split_dirty_region)(struct netfs_dirty_region *region);
	void (*free_dirty_region)(struct netfs_dirty_region *region);
	enum netfs_write_compatibility (*is_write_compatible)(
		struct netfs_i_context *ctx,
		struct netfs_dirty_region *old_region,
		struct netfs_dirty_region *candidate);
	bool (*check_compatible_write)(struct netfs_dirty_region *region, struct file *file);
	void (*update_i_size)(struct file *file, loff_t i_size);

	/* Write request handling */
	void (*init_wreq)(struct netfs_write_request *wreq);
	void (*add_write_streams)(struct netfs_write_request *wreq);
	void (*invalidate_cache)(struct netfs_write_request *wreq);
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
		    bool seek_data,
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
	enum netfs_read_source (*prepare_read)(struct netfs_read_subrequest *subreq,
					       loff_t i_size);

	/* Prepare a write operation, working out what part of the write we can
	 * actually do.
	 */
	int (*prepare_write)(struct netfs_cache_resources *cres,
			     loff_t *_start, size_t *_len, loff_t i_size);
};

struct readahead_control;
extern void netfs_readahead(struct readahead_control *);
extern int netfs_readpage(struct file *, struct page *);
extern int netfs_write_begin(struct file *, struct address_space *,
			     loff_t, unsigned int, unsigned int, struct page **,
			     void **);
extern ssize_t netfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from);
extern int netfs_writepages(struct address_space *mapping, struct writeback_control *wbc);
extern void netfs_invalidatepage(struct page *page, unsigned int offset, unsigned int length);
extern int netfs_releasepage(struct page *page, gfp_t gfp_flags);

extern void netfs_subreq_terminated(struct netfs_read_subrequest *, ssize_t, bool);
extern void netfs_stats_show(struct seq_file *);
extern struct netfs_flush_group *netfs_new_flush_group(struct inode *, void *);
extern void netfs_set_up_write_stream(struct netfs_write_request *wreq,
				      enum netfs_write_dest dest, work_func_t worker);
extern void netfs_put_write_request(struct netfs_write_request *wreq,
				    bool was_async, enum netfs_wreq_trace what);
extern void netfs_write_stream_completed(void *_stream, ssize_t transferred_or_error,
					 bool was_async);

/**
 * netfs_i_context - Get the netfs inode context from the inode
 * @inode: The inode to query
 *
 * This function gets the netfs lib inode context from the network filesystem's
 * inode.  It expects it to follow on directly from the VFS inode struct.
 */
static inline struct netfs_i_context *netfs_i_context(struct inode *inode)
{
	return (struct netfs_i_context *)(inode + 1);
}

static inline void netfs_i_context_init(struct inode *inode,
					const struct netfs_request_ops *ops)
{
	struct netfs_i_context *ctx = netfs_i_context(inode);

	ctx->ops = ops;
	ctx->bsize = PAGE_SIZE;
	INIT_LIST_HEAD(&ctx->pending_writes);
	INIT_LIST_HEAD(&ctx->active_writes);
	INIT_LIST_HEAD(&ctx->dirty_regions);
	INIT_LIST_HEAD(&ctx->flush_groups);
	INIT_LIST_HEAD(&ctx->flush_queue);
	spin_lock_init(&ctx->lock);
}

/**
 * netfs_i_cookie - Get the cache cookie from the inode
 * @inode: The inode to query
 *
 * Get the caching cookie (if enabled) from the network filesystem's inode.
 */
static inline struct fscache_cookie *netfs_i_cookie(struct inode *inode)
{
#ifdef CONFIG_FSCACHE
	struct netfs_i_context *ctx = netfs_i_context(inode);
	return ctx->cache;
#else
	return NULL;
#endif
}

static inline
struct netfs_write_request *netfs_stream_to_wreq(struct netfs_write_stream *stream)
{
	return container_of(stream, struct netfs_write_request, streams[stream->index]);
}

#endif /* _LINUX_NETFS_H */
