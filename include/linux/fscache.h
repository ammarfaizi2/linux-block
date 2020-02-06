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
#include <linux/netfs.h>

#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
#define fscache_available() (1)
#define fscache_cookie_valid(cookie) (cookie)
#else
#define fscache_available() (0)
#define fscache_cookie_valid(cookie) (0)
#endif


/* pattern used to fill dead space in an index entry */
#define FSCACHE_INDEX_DEADFILL_PATTERN 0x79

struct fscache_cache_tag;
struct fscache_cookie;
struct fscache_netfs;
struct netfs_read_request;

enum fscache_cookie_type {
	FSCACHE_COOKIE_TYPE_INDEX,
	FSCACHE_COOKIE_TYPE_DATAFILE,
};

#define FSCACHE_ADV_SINGLE_CHUNK	0x01 /* The object is a single chunk of data */

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
 * data file or index object cookie
 * - a file will only appear in one cache
 * - a request to cache a file may or may not be honoured, subject to
 *   constraints such as disk space
 * - indices are created on disk just-in-time
 */
struct fscache_cookie {
	atomic_t			usage;		/* number of users of this cookie */
	atomic_t			n_children;	/* number of children of this cookie */
	atomic_t			n_active;	/* number of active users of netfs ptrs */
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
#define FSCACHE_COOKIE_LOOKING_UP	0	/* T if non-index cookie being looked up still */
#define FSCACHE_COOKIE_NO_DATA_YET	1	/* T if new object with no cached data yet */
#define FSCACHE_COOKIE_UNAVAILABLE	2	/* T if cookie is unavailable (error, etc) */
#define FSCACHE_COOKIE_INVALIDATING	3	/* T if cookie is being invalidated */
#define FSCACHE_COOKIE_RELINQUISHED	4	/* T if cookie has been relinquished */
#define FSCACHE_COOKIE_ENABLED		5	/* T if cookie is enabled */
#define FSCACHE_COOKIE_ENABLEMENT_LOCK	6	/* T if cookie is being en/disabled */
#define FSCACHE_COOKIE_AUX_UPDATED	8	/* T if the auxiliary data was updated */
#define FSCACHE_COOKIE_ACQUIRED		9	/* T if cookie is in use */
#define FSCACHE_COOKIE_RELINQUISHING	10	/* T if cookie is being relinquished */

	enum fscache_cookie_type	type:8;
	u8				advice;		/* FSCACHE_COOKIE_ADV_* */
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

static inline bool fscache_cookie_enabled(struct fscache_cookie *cookie)
{
	return test_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
}

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
	loff_t, bool);
extern void __fscache_relinquish_cookie(struct fscache_cookie *, const void *, bool);
extern int __fscache_check_consistency(struct fscache_cookie *, const void *);
extern void __fscache_update_cookie(struct fscache_cookie *, const void *);
extern int __fscache_attr_changed(struct fscache_cookie *);
extern void __fscache_invalidate(struct fscache_cookie *);
extern void __fscache_wait_on_invalidate(struct fscache_cookie *);
extern int __fscache_begin_read_operation(struct netfs_read_request *, struct fscache_cookie *);
extern void __fscache_disable_cookie(struct fscache_cookie *, const void *, bool);
extern void __fscache_enable_cookie(struct fscache_cookie *, const void *, loff_t,
				    bool (*)(void *), void *);

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
 * @enable: Whether or not to enable a data cookie immediately
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
	loff_t object_size,
	bool enable)
{
	if (fscache_cookie_valid(parent) && fscache_cookie_enabled(parent))
		return __fscache_acquire_cookie(parent, type, type_name, advice,
						preferred_cache,
						index_key, index_key_len,
						aux_data, aux_data_len,
						object_size, enable);
	else
		return NULL;
}

/**
 * fscache_relinquish_cookie - Return the cookie to the cache, maybe discarding
 * it
 * @cookie: The cookie being returned
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @retire: True if the cache object the cookie represents is to be discarded
 *
 * This function returns a cookie to the cache, forcibly discarding the
 * associated cache object if retire is set to true.  The opportunity is
 * provided to update the auxiliary data in the cache before the object is
 * disconnected.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_relinquish_cookie(struct fscache_cookie *cookie,
			       const void *aux_data,
			       bool retire)
{
	if (fscache_cookie_valid(cookie))
		__fscache_relinquish_cookie(cookie, aux_data, retire);
}

/**
 * fscache_check_consistency - Request validation of a cache's auxiliary data
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 *
 * Request an consistency check from fscache, which passes the request to the
 * backing cache.  The auxiliary data on the cookie will be updated first if
 * @aux_data is set.
 *
 * Returns 0 if consistent and -ESTALE if inconsistent.  May also
 * return -ENOMEM and -ERESTARTSYS.
 */
static inline
int fscache_check_consistency(struct fscache_cookie *cookie,
			      const void *aux_data)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		return __fscache_check_consistency(cookie, aux_data);
	else
		return 0;
}

/**
 * fscache_update_cookie - Request that a cache object be updated
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 *
 * Request an update of the index data for the cache object associated with the
 * cookie.  The auxiliary data on the cookie will be updated first if @aux_data
 * is set.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_update_cookie(struct fscache_cookie *cookie, const void *aux_data)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		__fscache_update_cookie(cookie, aux_data);
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
 * fscache_attr_changed - Notify cache that an object's attributes changed
 * @cookie: The cookie representing the cache object
 *
 * Send a notification to the cache indicating that an object's attributes have
 * changed.  This includes the data size.  These attributes will be obtained
 * through the get_attr() cookie definition op.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
int fscache_attr_changed(struct fscache_cookie *cookie)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		return __fscache_attr_changed(cookie);
	else
		return -ENOBUFS;
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
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_invalidate(struct fscache_cookie *cookie)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		__fscache_invalidate(cookie);
}

/**
 * fscache_wait_on_invalidate - Wait for invalidation to complete
 * @cookie: The cookie representing the cache object
 *
 * Wait for the invalidation of an object to complete.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_wait_on_invalidate(struct fscache_cookie *cookie)
{
	if (fscache_cookie_valid(cookie))
		__fscache_wait_on_invalidate(cookie);
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
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		return __fscache_begin_read_operation(rreq, cookie);
	return -ENOBUFS;
}

/**
 * fscache_disable_cookie - Disable a cookie
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @invalidate: Invalidate the backing object
 *
 * Disable a cookie from accepting further alloc, read, write, invalidate,
 * update or acquire operations.  Outstanding operations can still be waited
 * upon and pages can still be uncached and the cookie relinquished.
 *
 * This will not return until all outstanding operations have completed.
 *
 * If @invalidate is set, then the backing object will be invalidated and
 * detached, otherwise it will just be detached.
 *
 * If @aux_data is set, then auxiliary data will be updated from that.
 */
static inline
void fscache_disable_cookie(struct fscache_cookie *cookie,
			    const void *aux_data,
			    bool invalidate)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		__fscache_disable_cookie(cookie, aux_data, invalidate);
}

/**
 * fscache_enable_cookie - Reenable a cookie
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @object_size: Current size of object
 * @can_enable: A function to permit enablement once lock is held
 * @data: Data for can_enable()
 *
 * Reenable a previously disabled cookie, allowing it to accept further alloc,
 * read, write, invalidate, update or acquire operations.  An attempt will be
 * made to immediately reattach the cookie to a backing object.  If @aux_data
 * is set, the auxiliary data attached to the cookie will be updated.
 *
 * The can_enable() function is called (if not NULL) once the enablement lock
 * is held to rule on whether enablement is still permitted to go ahead.
 */
static inline
void fscache_enable_cookie(struct fscache_cookie *cookie,
			   const void *aux_data,
			   loff_t object_size,
			   bool (*can_enable)(void *data),
			   void *data)
{
	if (fscache_cookie_valid(cookie) && !fscache_cookie_enabled(cookie))
		__fscache_enable_cookie(cookie, aux_data, object_size,
					can_enable, data);
}

#endif /* _LINUX_FSCACHE_H */
