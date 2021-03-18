/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General filesystem caching backing cache interface
 *
 * Copyright (C) 2004-2007, 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/backend-api.rst
 *
 * for a description of the cache backend interface declared here.
 */

#ifndef _LINUX_FSCACHE_CACHE_H
#define _LINUX_FSCACHE_CACHE_H

#include <linux/fscache.h>

struct fscache_cache;
struct fscache_cache_ops;
enum fscache_cache_trace;
enum fscache_cookie_trace;
enum fscache_access_trace;

enum fscache_cache_state {
	FSCACHE_CACHE_IS_NOT_PRESENT,	/* No cache is present for this name */
	FSCACHE_CACHE_IS_PREPARING,	/* A cache is preparing to come live */
	FSCACHE_CACHE_IS_LIVE,		/* Attached cache is live and can be used */
	FSCACHE_CACHE_GOT_IOERROR,	/* Attached cache stopped on I/O error */
	FSCACHE_CACHE_IS_WITHDRAWN,	/* Attached cache is being withdrawn */
#define NR__FSCACHE_CACHE_STATE (FSCACHE_CACHE_IS_WITHDRAWN + 1)
};

/*
 * Cache cookie.
 */
struct fscache_cache {
	const struct fscache_cache_ops *ops;
	struct list_head	cache_link;	/* Link in cache list */
	struct list_head	volumes;	/* List of volumes in this cache */
	void			*cache_priv;	/* Private cache data (or NULL) */
	refcount_t		ref;
	atomic_t		n_volumes;	/* Number of active volumes; */
	atomic_t		n_accesses;	/* Number of in-progress accesses on the cache */
	atomic_t		object_count;	/* no. of live objects in this cache */
	unsigned int		debug_id;
	enum fscache_cache_state state;
	char			name[];
};

/*
 * cache operations
 */
struct fscache_cache_ops {
	/* name of cache provider */
	const char *name;

	/* Acquire a volume */
	void (*acquire_volume)(struct fscache_volume *volume);

	/* Relinquish a volume when the volume cookie is relinquished */
	void (*relinquish_volume)(struct fscache_volume *volume);

	/* Destroy stuff attached to a volume cookie */
	void (*put_volume)(struct fscache_volume *volume);

	/* Look up a cookie in the cache */
	bool (*lookup_cookie)(struct fscache_cookie *cookie);

	/* The netfs relinquished a cookie */
	void (*relinquish_cookie)(struct fscache_cookie *cookie);

	/* Change the size of a data object */
	void (*resize_cookie)(struct netfs_cache_resources *cres, loff_t new_size);

	/* Invalidate an object */
	bool (*invalidate_cookie)(struct fscache_cookie *cookie,
				  unsigned int flags);

	/* Begin an operation for the netfs lib */
	int (*begin_operation)(struct netfs_cache_resources *cres);

	/* Prepare to write to a live cache object */
	int (*prepare_to_write)(struct fscache_cookie *cookie);
};

static inline enum fscache_cache_state fscache_cache_state(const struct fscache_cache *cache)
{
	return smp_load_acquire(&cache->state);
}

static inline bool fscache_cache_is_live(const struct fscache_cache *cache)
{
	return fscache_cache_state(cache) == FSCACHE_CACHE_IS_LIVE;
}

static inline void fscache_set_cache_state(struct fscache_cache *cache,
					   enum fscache_cache_state new_state)
{
	smp_store_release(&cache->state, new_state);

}

static inline bool fscache_set_cache_state_maybe(struct fscache_cache *cache,
						 enum fscache_cache_state old_state,
						 enum fscache_cache_state new_state)
{
	return try_cmpxchg_release(&cache->state, &old_state, new_state);
}

/*
 * out-of-line cache backend functions
 */
extern struct rw_semaphore fscache_addremove_sem;
extern struct fscache_cache *fscache_acquire_cache(const char *name);
extern int fscache_add_cache(struct fscache_cache *cache,
			     const struct fscache_cache_ops *ops,
			     void *cache_priv);
extern void fscache_put_cache(struct fscache_cache *cache,
			      enum fscache_cache_trace where);
extern void fscache_withdraw_cache(struct fscache_cache *cache);

extern void fscache_io_error(struct fscache_cache *cache);

extern void fscache_end_volume_access(struct fscache_volume *volume,
				      enum fscache_access_trace why);

extern struct fscache_cookie *fscache_get_cookie(struct fscache_cookie *cookie,
						 enum fscache_cookie_trace where);
extern void fscache_put_cookie(struct fscache_cookie *cookie,
			       enum fscache_cookie_trace where);
extern void fscache_drop_cookie(struct fscache_cookie *cookie,
				enum fscache_cookie_trace where);
extern void fscache_end_cookie_access(struct fscache_cookie *cookie,
				      enum fscache_access_trace why);
extern void fscache_set_cookie_stage(struct fscache_cookie *cookie,
				     enum fscache_cookie_stage stage);

/*
 * Find the key on a cookie.
 */
static inline void *fscache_get_key(struct fscache_cookie *cookie)
{
	if (cookie->key_len <= sizeof(cookie->inline_key))
		return cookie->inline_key;
	else
		return cookie->key;
}

extern void __fscache_wait_for_operation(struct netfs_cache_resources *, enum fscache_want_stage);

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

static inline struct fscache_cookie *fscache_cres_cookie(struct netfs_cache_resources *cres)
{
	return cres->cache_priv;
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

#ifdef CONFIG_FSCACHE_STATS
extern atomic_t fscache_n_read;
extern atomic_t fscache_n_write;
#define fscache_count_read() atomic_inc(&fscache_n_read)
#define fscache_count_write() atomic_inc(&fscache_n_write)
#else
#define fscache_count_read() do {} while(0)
#define fscache_count_write() do {} while(0)
#endif

#endif /* _LINUX_FSCACHE_CACHE_H */
