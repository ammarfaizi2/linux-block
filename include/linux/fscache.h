/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General filesystem caching interface
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/netfs-api.rst
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
#include <linux/writeback.h>
#include <linux/netfs.h>

#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
#define __fscache_available (1)
#define fscache_available() (1)
#define fscache_cookie_valid(cookie) (cookie)
#define fscache_object_valid(object) (object)
#define fscache_cookie_enabled(cookie) (cookie && !test_bit(FSCACHE_COOKIE_DISABLED, &cookie->flags))
#else
#define __fscache_available (0)
#define fscache_available() (0)
#define fscache_cookie_valid(cookie) (0)
#define fscache_object_valid(object) (NULL)
#define fscache_cookie_enabled(cookie) (0)
#endif


/* pattern used to fill dead space in an index entry */
#define FSCACHE_INDEX_DEADFILL_PATTERN 0x79

struct fscache_cache_tag;
struct fscache_cookie;
struct fscache_netfs;

enum fscache_cookie_type {
	FSCACHE_COOKIE_TYPE_INDEX,
	FSCACHE_COOKIE_TYPE_DATAFILE,
};

#define FSCACHE_ADV_SINGLE_CHUNK	0x01 /* The object is a single chunk of data */
#define FSCACHE_ADV_WRITE_CACHE		0x00 /* Do cache if written to locally */
#define FSCACHE_ADV_WRITE_NOCACHE	0x02 /* Don't cache if written to locally */

enum fscache_want_stage {
	FSCACHE_WANT_PARAMS,
	FSCACHE_WANT_WRITE,
	FSCACHE_WANT_READ,
};

#define FSCACHE_INVAL_LIGHT		0x01 /* Don't re-invalidate if temp object */
#define FSCACHE_INVAL_DIO_WRITE		0x02 /* Invalidate due to DIO write */

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
	FSCACHE_COOKIE_STAGE_INDEX,		/* The cookie is an index cookie */
	FSCACHE_COOKIE_STAGE_QUIESCENT,		/* The cookie is uncached */
	FSCACHE_COOKIE_STAGE_INITIALISING,	/* The in-memory structs are being inited */
	FSCACHE_COOKIE_STAGE_LOOKING_UP,	/* The cache object is being looked up */
	FSCACHE_COOKIE_STAGE_NO_DATA_YET,	/* The cache has no data, read to network */
	FSCACHE_COOKIE_STAGE_ACTIVE,		/* The cache is active, readable and writable */
	FSCACHE_COOKIE_STAGE_INVALIDATING,	/* The cache is being invalidated */
	FSCACHE_COOKIE_STAGE_FAILED,		/* The cache failed, withdraw to clear */
	FSCACHE_COOKIE_STAGE_WITHDRAWING,	/* The cache is being withdrawn */
	FSCACHE_COOKIE_STAGE_RELINQUISHING,	/* The cookie is being relinquished */
	FSCACHE_COOKIE_STAGE_DROPPED,		/* The cookie has been dropped */
} __attribute__((mode(byte)));

/*
 * data file or index object cookie
 * - a file will only appear in one cache
 * - a request to cache a file may or may not be honoured, subject to
 *   constraints such as disk space
 * - indices are created on disk just-in-time
 */
struct fscache_cookie {
	refcount_t			ref;		/* number of users of this cookie */
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
	loff_t				zero_point;	/* Size after which no data on server */

	unsigned long			flags;
#define FSCACHE_COOKIE_RELINQUISHED	6		/* T if cookie has been relinquished */
#define FSCACHE_COOKIE_DISABLED		7		/* T if cookie has been disabled */

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
extern void __fscache_invalidate(struct fscache_cookie *, const void *, loff_t, unsigned int);
extern int __fscache_begin_read_operation(struct netfs_read_request *, struct fscache_cookie *);
extern void fscache_put_super(struct super_block *,
			      struct fscache_cookie *(*get_cookie)(struct inode *));

/**
 * fscache_register_netfs - Register a filesystem as desiring caching services
 * @netfs: The description of the filesystem
 *
 * Register a filesystem as desiring caching services if they're available.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
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
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
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
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
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
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
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
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
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
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
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
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_update_cookie(struct fscache_cookie *cookie, const void *aux_data,
			   const loff_t *object_size)
{
	if (fscache_cookie_enabled(cookie))
		__fscache_update_cookie(cookie, aux_data, object_size);
}

/**
 * fscache_pin_cookie - Pin a data-storage cache object in its cache
 * @cookie: The cookie representing the cache object
 *
 * Permit data-storage cache objects to be pinned in the cache.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
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
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_unpin_cookie(struct fscache_cookie *cookie)
{
}

/**
 * fscache_invalidate - Notify cache that an object needs invalidation
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @size: The revised size of the object.
 * @flags: Invalidation flags (FSCACHE_INVAL_*)
 *
 * Notify the cache that an object is needs to be invalidated and that it
 * should abort any retrievals or stores it is doing on the cache.  The object
 * is then marked non-caching until such time as the invalidation is complete.
 *
 * FSCACHE_INVAL_LIGHT indicates that if the object has been invalidated and
 * replaced by a temporary object, the temporary object need not be replaced
 * again.  This is primarily intended for use with FSCACHE_ADV_SINGLE_CHUNK.
 *
 * FSCACHE_INVAL_DIO_WRITE indicates that this is due to a direct I/O write and
 * may cause caching to be suspended on this cookie.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_invalidate(struct fscache_cookie *cookie,
			const void *aux_data, loff_t size, unsigned int flags)
{
	if (fscache_cookie_enabled(cookie))
		__fscache_invalidate(cookie, aux_data, size, flags);
}

/**
 * fscache_begin_read_operation - Begin a read operation for the netfs lib
 * @rreq: The read request being undertaken
 * @cookie: The cookie representing the cache object
 *
 * Begin a read operation on behalf of the netfs helper library.  @rreq
 * indicates the read request to which the operation state should be attached;
 * @cookie indicates the cache object that will be accessed.
 *
 * This is intended to be called from the ->begin_cache_operation() netfs lib
 * operation as implemented by the network filesystem.
 *
 * Returns:
 * * 0		- Success
 * * -ENOBUFS	- No caching available
 * * Other error code from the cache, such as -ENOMEM.
 */
static inline
int fscache_begin_read_operation(struct netfs_read_request *rreq,
				 struct fscache_cookie *cookie)
{
	if (fscache_cookie_enabled(cookie))
		return __fscache_begin_read_operation(rreq, cookie);
	return -ENOBUFS;
}

/**
 * fscache_operation_valid - Return true if operations resources are usable
 * @cres: The resources to check.
 *
 * Returns a pointer to the operations table if usable or NULL if not.
 */
static inline
const struct netfs_cache_ops *fscache_operation_valid(const struct netfs_cache_resources *cres)
{
#if __fscache_available
	return fscache_object_valid(cres->cache_priv) ? cres->ops : NULL;
#else
	return NULL;
#endif
}

/**
 * fscache_wait_for_operation - Wait for an object become accessible
 * @cookie: The cookie representing the cache object
 * @want_stage: The minimum stage the object must be at
 *
 * See if the target cache object is at the specified minimum stage of
 * accessibility yet, and if not, wait for it.
 */
static inline
void fscache_wait_for_operation(struct netfs_cache_resources *cres,
				enum fscache_want_stage want_stage)
{
	const struct netfs_cache_ops *ops = fscache_operation_valid(cres);
	if (ops)
		ops->wait_for_operation(cres, want_stage);
}

/**
 * fscache_end_operation - End an fscache I/O operation.
 * @cres: The resources to dispose of.
 */
static inline
void fscache_end_operation(struct netfs_cache_resources *cres)
{
	const struct netfs_cache_ops *ops = fscache_operation_valid(cres);
	if (ops)
		ops->end_operation(cres);
}

/**
 * fscache_read - Start a read from the cache.
 * @cres: The cache resources to use
 * @start_pos: The beginning file offset in the cache file
 * @iter: The buffer to fill - and also the length
 * @seek_data: True to seek for the data
 * @term_func: The function to call upon completion
 * @term_func_priv: The private data for @term_func
 *
 * Start a read from the cache.  @cres indicates the cache object to read from
 * and must be obtained by a call to fscache_begin_operation() beforehand.
 *
 * The data is read into the iterator, @iter, and that also indicates the size
 * of the operation.  @start_pos is the start position in the file, though if
 * @seek_data is set, the cache will use SEEK_DATA to find the next piece of
 * data, writing zeros for the hole into the iterator.
 *
 * Upon termination of the operation, @term_func will be called and supplied
 * with @term_func_priv plus the amount of data written, if successful, or the
 * error code otherwise.
 */
static inline
int fscache_read(struct netfs_cache_resources *cres,
		 loff_t start_pos,
		 struct iov_iter *iter,
		 bool seek_data,
		 netfs_io_terminated_t term_func,
		 void *term_func_priv)
{
	const struct netfs_cache_ops *ops = fscache_operation_valid(cres);
	return ops->read(cres, start_pos, iter, seek_data,
			 term_func, term_func_priv);
}

/**
 * fscache_write - Start a write to the cache.
 * @cres: The cache resources to use
 * @start_pos: The beginning file offset in the cache file
 * @iter: The data to write - and also the length
 * @term_func: The function to call upon completion
 * @term_func_priv: The private data for @term_func
 *
 * Start a write to the cache.  @cres indicates the cache object to write to and
 * must be obtained by a call to fscache_begin_operation() beforehand.
 *
 * The data to be written is obtained from the iterator, @iter, and that also
 * indicates the size of the operation.  @start_pos is the start position in
 * the file.
 *
 * Upon termination of the operation, @term_func will be called and supplied
 * with @term_func_priv plus the amount of data written, if successful, or the
 * error code otherwise.
 */
static inline
int fscache_write(struct netfs_cache_resources *cres,
		  loff_t start_pos,
		  struct iov_iter *iter,
		  netfs_io_terminated_t term_func,
		  void *term_func_priv)
{
	const struct netfs_cache_ops *ops = fscache_operation_valid(cres);
	return ops->write(cres, start_pos, iter, term_func, term_func_priv);
}

#if __fscache_available
extern int fscache_set_page_dirty(struct page *page, struct fscache_cookie *cookie);
#else
#define fscache_set_page_dirty(PAGE, COOKIE) (__set_page_dirty_nobuffers((PAGE)))
#endif

/**
 * fscache_unpin_writeback - Unpin writeback resources
 * @wbc: The writeback control
 * @cookie: The cookie referring to the cache object
 *
 * Unpin the writeback resources pinned by fscache_set_page_dirty().  This is
 * intended to be called by the netfs's ->write_inode() method.
 */
static inline void fscache_unpin_writeback(struct writeback_control *wbc,
					   struct fscache_cookie *cookie)
{
	if (wbc->unpinned_fscache_wb)
		fscache_unuse_cookie(cookie, NULL, NULL);
}

#endif /* _LINUX_FSCACHE_H */
