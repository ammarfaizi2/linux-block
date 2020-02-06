/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General filesystem caching interface
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/netfs-api.txt
 *
 * for a description of the network filesystem interface declared here.
 */

#ifndef _LINUX_FSCACHE_H
#define _LINUX_FSCACHE_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/list_bl.h>

#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
#define fscache_available() (1)
#define fscache_cookie_valid(cookie) (cookie)
#else
#define fscache_available() (0)
#define fscache_cookie_valid(cookie) (0)
#endif


/*
 * overload PG_private_2 to give us PG_fscache - this is used to indicate that
 * a page is currently being written to the cache, possibly by direct I/O.
 */
#define PageFsCache(page)		PagePrivate2((page))
#define SetPageFsCache(page)		SetPagePrivate2((page))
#define ClearPageFsCache(page)		ClearPagePrivate2((page))
#define TestSetPageFsCache(page)	TestSetPagePrivate2((page))
#define TestClearPageFsCache(page)	TestClearPagePrivate2((page))

/* pattern used to fill dead space in an index entry */
#define FSCACHE_INDEX_DEADFILL_PATTERN 0x79

struct iov_iter;
struct fscache_cache_tag;
struct fscache_cookie;
struct fscache_netfs;
struct fscache_io_request_ops;

enum fscache_cookie_type {
	FSCACHE_COOKIE_TYPE_INDEX,
	FSCACHE_COOKIE_TYPE_DATAFILE,
};

#define FSCACHE_ADV_SINGLE_CHUNK	0x01 /* The object is a single chunk of data */
#define FSCACHE_ADV_WRITE_CACHE		0x00 /* Do cache if written to locally */
#define FSCACHE_ADV_WRITE_NOCACHE	0x02 /* Don't cache if written to locally */

/*
 * fscache cached network filesystem type
 * - name, version and ops must be filled in before registration
 * - all other fields will be set during registration
 */
struct fscache_netfs {
	uint32_t			version;	/* indexing version */
	const char			*name;		/* filesystem name */
	struct fscache_cookie		*primary_index;
};

/*
 * Data object state.
 */
enum fscache_cookie_stage {
	FSCACHE_COOKIE_STAGE_QUIESCENT,		/* The cookie is uncached */
	FSCACHE_COOKIE_STAGE_INITIALISING,	/* The in-memory structs are being inited */
	FSCACHE_COOKIE_STAGE_LOOKING_UP,	/* The cache object is being looked up */
	FSCACHE_COOKIE_STAGE_NO_DATA_YET,	/* The cache has no data, read to network */
	FSCACHE_COOKIE_STAGE_ACTIVE,		/* The cache is active, readable and writable */
	FSCACHE_COOKIE_STAGE_INVALIDATING,	/* The cache is being invalidated */
	FSCACHE_COOKIE_STAGE_DEAD,		/* The cache object is dead */
} __attribute__((mode(byte)));

/*
 * data file or index object cookie
 * - a file will only appear in one cache
 * - a request to cache a file may or may not be honoured, subject to
 *   constraints such as disk space
 * - indices are created on disk just-in-time
 */
struct fscache_cookie {
	atomic_t			usage;		/* number of users of this cookie */
	atomic_t			n_children;	/* number of children of this cookie */
	atomic_t			n_active;	/* number of active users of cookie */
	atomic_t			n_ops;		/* Number of active ops on this cookie */
	unsigned int			debug_id;
	spinlock_t			lock;
	struct hlist_head		backing_objects; /* object(s) backing this file/index */
	struct fscache_cookie		*parent;	/* parent of this entry */
	struct fscache_cache_tag	*preferred_cache; /* The preferred cache or NULL */
	struct hlist_bl_node		hash_link;	/* Link in hash table */
	struct list_head		proc_link;	/* Link in proc list */
	char				type_name[8];	/* Cookie type name */
	loff_t				object_size;	/* Size of the netfs object */

	unsigned long			flags;
#define FSCACHE_COOKIE_INVALIDATING	4	/* T if cookie is being invalidated */
#define FSCACHE_COOKIE_ACQUIRED		5	/* T if cookie is in use */
#define FSCACHE_COOKIE_RELINQUISHED	6	/* T if cookie has been relinquished */

	enum fscache_cookie_stage	stage;
	enum fscache_cookie_type	type:8;
	u8				advice;		/* FSCACHE_ADV_* */
	u8				key_len;	/* Length of index key */
	u8				aux_len;	/* Length of auxiliary data */
	u32				key_hash;	/* Hash of parent, type, key, len */
	union {
		void			*key;		/* Index key */
		u8			inline_key[16];	/* - If the key is short enough */
	};
	union {
		void			*aux;		/* Auxiliary data */
		u8			inline_aux[8];	/* - If the aux data is short enough */
	};
};

/*
 * The extent of the allocation granule in the cache, modulated for the
 * available data on doing a read, the page size and non-contiguities.
 *
 * This also includes the block size to which I/O requests must be aligned.
 */
struct fscache_extent {
	pgoff_t		start;		/* First page in the extent */
	pgoff_t		block_end;	/* End of first block */
	pgoff_t		limit;		/* Limit of extent (or ULONG_MAX) */
	unsigned int	dio_block_size;	/* Block size required for direct I/O */
};

/*
 * Descriptor for an fscache I/O request.
 */
struct fscache_io_request {
	const struct fscache_io_request_ops *ops;
	struct fscache_cookie	*cookie;
	struct fscache_object	*object;
	loff_t			pos;		/* Where to start the I/O */
	loff_t			len;		/* Size of the I/O */
	loff_t			transferred;	/* Amount of data transferred */
	short			error;		/* 0 or error that occurred */
	unsigned long		flags;
#define FSCACHE_IO_DATA_FROM_SERVER	0	/* Set if data was read from server */
#define FSCACHE_IO_DATA_FROM_CACHE	1	/* Set if data was read from the cache */
	void (*io_done)(struct fscache_io_request *);
};

struct fscache_io_request_ops {
	bool (*is_still_valid)(struct fscache_io_request *);
	void (*issue_op)(struct fscache_io_request *);
	void (*done)(struct fscache_io_request *);
	void (*get)(struct fscache_io_request *);
	void (*put)(struct fscache_io_request *);
};

/*
 * slow-path functions for when there is actually caching available, and the
 * netfs does actually have a valid token
 * - these are not to be called directly
 * - these are undefined symbols when FS-Cache is not configured and the
 *   optimiser takes care of not using them
 */
extern int __fscache_register_netfs(struct fscache_netfs *);
extern void __fscache_unregister_netfs(struct fscache_netfs *);
extern struct fscache_cache_tag *__fscache_lookup_cache_tag(const char *);
extern void __fscache_release_cache_tag(struct fscache_cache_tag *);

extern struct fscache_cookie *__fscache_acquire_cookie(
	struct fscache_cookie *,
	enum fscache_cookie_type,
	const char *,
	u8,
	struct fscache_cache_tag *,
	const void *, size_t,
	const void *, size_t,
	loff_t);
extern void __fscache_use_cookie(struct fscache_cookie *, bool);
extern void __fscache_unuse_cookie(struct fscache_cookie *, const void *, const loff_t *);
extern void __fscache_relinquish_cookie(struct fscache_cookie *, bool);
extern void __fscache_update_cookie(struct fscache_cookie *, const void *, const loff_t *);
extern void __fscache_invalidate(struct fscache_cookie *);
extern unsigned int __fscache_shape_extent(struct fscache_cookie *,
					   struct fscache_extent *,
					   loff_t, bool);
extern void __fscache_init_io_request(struct fscache_io_request *,
				      struct fscache_cookie *);
extern void __fscache_free_io_request(struct fscache_io_request *);
extern int __fscache_read(struct fscache_io_request *, struct iov_iter *);
extern int __fscache_write(struct fscache_io_request *, struct iov_iter *);

/**
 * fscache_register_netfs - Register a filesystem as desiring caching services
 * @netfs: The description of the filesystem
 *
 * Register a filesystem as desiring caching services if they're available.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
int fscache_register_netfs(struct fscache_netfs *netfs)
{
	if (fscache_available())
		return __fscache_register_netfs(netfs);
	else
		return 0;
}

/**
 * fscache_unregister_netfs - Indicate that a filesystem no longer desires
 * caching services
 * @netfs: The description of the filesystem
 *
 * Indicate that a filesystem no longer desires caching services for the
 * moment.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
void fscache_unregister_netfs(struct fscache_netfs *netfs)
{
	if (fscache_available())
		__fscache_unregister_netfs(netfs);
}

/**
 * fscache_lookup_cache_tag - Look up a cache tag
 * @name: The name of the tag to search for
 *
 * Acquire a specific cache referral tag that can be used to select a specific
 * cache in which to cache an index.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
struct fscache_cache_tag *fscache_lookup_cache_tag(const char *name)
{
	if (fscache_available())
		return __fscache_lookup_cache_tag(name);
	else
		return NULL;
}

/**
 * fscache_release_cache_tag - Release a cache tag
 * @tag: The tag to release
 *
 * Release a reference to a cache referral tag previously looked up.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
void fscache_release_cache_tag(struct fscache_cache_tag *tag)
{
	if (fscache_available())
		__fscache_release_cache_tag(tag);
}

/**
 * fscache_acquire_cookie - Acquire a cookie to represent a cache object
 * @parent: The cookie that's to be the parent of this one
 * @type: Type of the cookie
 * @type_name: Name of cookie type (max 7 chars)
 * @advice: Advice flags (FSCACHE_COOKIE_ADV_*)
 * @preferred_cache: The cache to use (or NULL)
 * @index_key: The index key for this cookie
 * @index_key_len: Size of the index key
 * @aux_data: The auxiliary data for the cookie (may be NULL)
 * @aux_data_len: Size of the auxiliary data buffer
 * @netfs_data: An arbitrary piece of data to be kept in the cookie to
 * represent the cache object to the netfs
 * @object_size: The initial size of object
 *
 * This function is used to inform FS-Cache about part of an index hierarchy
 * that can be used to locate files.  This is done by requesting a cookie for
 * each index in the path to the file.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
struct fscache_cookie *fscache_acquire_cookie(
	struct fscache_cookie *parent,
	enum fscache_cookie_type type,
	const char *type_name,
	u8 advice,
	struct fscache_cache_tag *preferred_cache,
	const void *index_key,
	size_t index_key_len,
	const void *aux_data,
	size_t aux_data_len,
	loff_t object_size)
{
	if (fscache_cookie_valid(parent))
		return __fscache_acquire_cookie(parent, type, type_name, advice,
						preferred_cache,
						index_key, index_key_len,
						aux_data, aux_data_len,
						object_size);
	else
		return NULL;
}

/**
 * fscache_use_cookie - Request usage of cookie attached to an object
 * @object: Object description
 * @will_modify: If cache is expected to be modified locally
 *
 * Request usage of the cookie attached to an object.  The caller should tell
 * the cache if the object's contents are about to be modified locally and then
 * the cache can apply the policy that has been set to handle this case.
 */
static inline void fscache_use_cookie(struct fscache_cookie *cookie,
				      bool will_modify)
{
	if (fscache_cookie_valid(cookie) &&
	    cookie->type != FSCACHE_COOKIE_TYPE_INDEX)
		__fscache_use_cookie(cookie, will_modify);
}

/**
 * fscache_unuse_cookie - Cease usage of cookie attached to an object
 * @object: Object description
 * @aux_data: Updated auxiliary data (or NULL)
 * @object_size: Revised size of the object (or NULL)
 *
 * Cease usage of the cookie attached to an object.  When the users count
 * reaches zero then the cookie relinquishment will be permitted to proceed.
 */
static inline void fscache_unuse_cookie(struct fscache_cookie *cookie,
					const void *aux_data,
					const loff_t *object_size)
{
	if (fscache_cookie_valid(cookie) &&
	    cookie->type != FSCACHE_COOKIE_TYPE_INDEX)
		__fscache_unuse_cookie(cookie, aux_data, object_size);
}

/**
 * fscache_relinquish_cookie - Return the cookie to the cache, maybe discarding
 * it
 * @cookie: The cookie being returned
 * @retire: True if the cache object the cookie represents is to be discarded
 *
 * This function returns a cookie to the cache, forcibly discarding the
 * associated cache object if retire is set to true.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
void fscache_relinquish_cookie(struct fscache_cookie *cookie, bool retire)
{
	if (fscache_cookie_valid(cookie))
		__fscache_relinquish_cookie(cookie, retire);
}

/**
 * fscache_update_cookie - Request that a cache object be updated
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @object_size: The current size of the object (may be NULL)
 *
 * Request an update of the index data for the cache object associated with the
 * cookie.  The auxiliary data on the cookie will be updated first if @aux_data
 * is set and the object size will be updated and the object possibly trimmed
 * if @object_size is set.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
void fscache_update_cookie(struct fscache_cookie *cookie, const void *aux_data,
			   const loff_t *object_size)
{
	if (fscache_cookie_valid(cookie))
		__fscache_update_cookie(cookie, aux_data, object_size);
}

/**
 * fscache_pin_cookie - Pin a data-storage cache object in its cache
 * @cookie: The cookie representing the cache object
 *
 * Permit data-storage cache objects to be pinned in the cache.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
int fscache_pin_cookie(struct fscache_cookie *cookie)
{
	return -ENOBUFS;
}

/**
 * fscache_pin_cookie - Unpin a data-storage cache object in its cache
 * @cookie: The cookie representing the cache object
 *
 * Permit data-storage cache objects to be unpinned from the cache.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
void fscache_unpin_cookie(struct fscache_cookie *cookie)
{
}

/**
 * fscache_invalidate - Notify cache that an object needs invalidation
 * @cookie: The cookie representing the cache object
 *
 * Notify the cache that an object is needs to be invalidated and that it
 * should abort any retrievals or stores it is doing on the cache.  The object
 * is then marked non-caching until such time as the invalidation is complete.
 *
 * This can be called with spinlocks held.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
void fscache_invalidate(struct fscache_cookie *cookie)
{
	if (fscache_cookie_valid(cookie))
		__fscache_invalidate(cookie);
}

/**
 * fscache_init_io_request - Initialise an I/O request
 * @req: The I/O request to initialise
 * @cookie: The I/O cookie to access
 * @ops: The operations table to set
 */
static inline void fscache_init_io_request(struct fscache_io_request *req,
					   struct fscache_cookie *cookie,
					   const struct fscache_io_request_ops *ops)
{
	req->ops = ops;
	if (fscache_cookie_valid(cookie))
		__fscache_init_io_request(req, cookie);
}

/**
 * fscache_free_io_request - Clean up an I/O request
 * @req: The I/O request to clean
 */
static inline
void fscache_free_io_request(struct fscache_io_request *req)
{
	if (req->cookie)
		__fscache_free_io_request(req);
}

#define FSCACHE_READ_FROM_CACHE	0x01
#define FSCACHE_WRITE_TO_CACHE	0x02
#define FSCACHE_FILL_WITH_ZERO	0x04

/**
 * fscache_shape_extent - Shape an extent to fit cache granulation
 * @cookie: The cache cookie to access
 * @extent: The extent proposed by the VM/filesystem and the reply.
 * @i_size: The size to consider the file to be.
 * @for_write: If the determination is for a write.
 *
 * Determine the size and position of the extent that will cover the first page
 * in the cache such that either that extent will entirely be read from the
 * server or entirely read from the cache.  The provided extent may be
 * adjusted, by a combination of extending the front of the extent forward
 * and/or extending or shrinking the end of the extent.  In any case, the
 * starting page of the proposed extent will be contained in the revised
 * extent.
 *
 * The function returns FSCACHE_READ_FROM_CACHE to indicate that the data is
 * resident in the cache and can be read from there, FSCACHE_WRITE_TO_CACHE to
 * indicate that the data isn't present, but the netfs should write it,
 * FSCACHE_FILL_WITH_ZERO to indicate that the data should be all zeros on the
 * server and can just be fabricated locally in or 0 to indicate that there's
 * no cache or an error occurred and the netfs should just read from the
 * server.
 */
static inline
unsigned int fscache_shape_extent(struct fscache_cookie *cookie,
				  struct fscache_extent *extent,
				  loff_t i_size, bool for_write)
{
	if (fscache_cookie_valid(cookie))
		return __fscache_shape_extent(cookie, extent, i_size,
					      for_write);
	return 0;
}

/**
 * fscache_read - Read data from the cache.
 * @req: The I/O request descriptor
 * @iter: The buffer to read into
 *
 * The cache will attempt to read from the object referred to by the cookie,
 * using the size and position described in the request.  The data will be
 * transferred to the buffer described by the iterator specified in the request.
 *
 * If this fails or can't be done, an error will be set in the request
 * descriptor and the netfs must reissue the read to the server.
 *
 * Note that the length and position of the request should be aligned to the DIO
 * block size returned by fscache_shape_extent().
 *
 * If req->done is set, the request will be submitted as asynchronous I/O and
 * -EIOCBQUEUED may be returned to indicate that the operation is in progress.
 * The done function will be called when the operation is concluded either way.
 *
 * If req->done is not set, the request will be submitted as synchronous I/O and
 * will be completed before the function returns.
 */
static inline
int fscache_read(struct fscache_io_request *req, struct iov_iter *iter)
{
	if (fscache_cookie_valid(req->cookie))
		return __fscache_read(req, iter);
	req->error = -ENODATA;
	if (req->io_done)
		req->io_done(req);
	return -ENODATA;
}


/**
 * fscache_write - Write data to the cache.
 * @req: The I/O request description
 * @iter: The data to write
 *
 * The cache will attempt to write to the object referred to by the cookie,
 * using the size and position described in the request.  The data will be
 * transferred from the iterator specified in the request.
 *
 * If this fails or can't be done, an error will be set in the request
 * descriptor.
 *
 * Note that the length and position of the request should be aligned to the DIO
 * block size returned by fscache_shape_extent().
 *
 * If req->io_done is set, the request will be submitted as asynchronous I/O and
 * -EIOCBQUEUED may be returned to indicate that the operation is in progress.
 * The done function will be called when the operation is concluded either way.
 *
 * If req->io_done is not set, the request will be submitted as synchronous I/O and
 * will be completed before the function returns.
 */
static inline
int fscache_write(struct fscache_io_request *req, struct iov_iter *iter)
{
	if (fscache_cookie_valid(req->cookie))
		return __fscache_write(req, iter);
	req->error = -ENOBUFS;
	if (req->io_done)
		req->io_done(req);
	return -ENOBUFS;
}

#endif /* _LINUX_FSCACHE_H */
