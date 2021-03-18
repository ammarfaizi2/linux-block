// SPDX-License-Identifier: GPL-2.0-or-later
/* FS-Cache cache handling
 *
 * Copyright (C) 2007, 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/export.h>
#include <linux/slab.h>
#include "internal.h"

static LIST_HEAD(fscache_caches);
DECLARE_RWSEM(fscache_addremove_sem);
EXPORT_SYMBOL(fscache_addremove_sem);

static atomic_t fscache_cache_debug_id;

/*
 * Allocate a cache cookie.
 */
static struct fscache_cache *fscache_alloc_cache(const char *name)
{
	struct fscache_cache *cache;

	cache = kzalloc(sizeof(*cache) + strlen(name) + 1, GFP_KERNEL);
	if (cache) {
		refcount_set(&cache->ref, 1);
		strcpy(cache->name, name);
		INIT_LIST_HEAD(&cache->cache_link);
		INIT_LIST_HEAD(&cache->volumes);
		cache->debug_id = atomic_inc_return(&fscache_cache_debug_id);
	}
	return cache;
}

static bool fscache_get_cache_maybe(struct fscache_cache *cache,
				    enum fscache_cache_trace where)
{
	bool success;
	int ref;

	success = __refcount_inc_not_zero(&cache->ref, &ref);
	if (success)
		trace_fscache_cache(cache->debug_id, ref + 1, where);
	return success;
}

/*
 * Look up a cache cookie.
 */
struct fscache_cache *fscache_acquire_cache(const char *name)
{
	struct fscache_cache *candidate, *cache;

	/* firstly check for the existence of the cache under read lock */
	down_read(&fscache_addremove_sem);

	list_for_each_entry(cache, &fscache_caches, cache_link) {
		if (strcmp(cache->name, name) == 0 &&
		    fscache_get_cache_maybe(cache, fscache_cache_get_acquire)) {
			up_read(&fscache_addremove_sem);
			return cache;
		}
	}

	up_read(&fscache_addremove_sem);

	/* the cache does not exist - create a candidate */
	candidate = fscache_alloc_cache(name);
	if (!candidate)
		return ERR_PTR(-ENOMEM);

	/* write lock, search again and add if still not present */
	down_write(&fscache_addremove_sem);

	list_for_each_entry(cache, &fscache_caches, cache_link) {
		if (strcmp(cache->name, name) == 0 &&
		    fscache_get_cache_maybe(cache, fscache_cache_get_acquire)) {
			up_write(&fscache_addremove_sem);
			kfree(candidate);
			return cache;
		}
	}

	list_add_tail(&candidate->cache_link, &fscache_caches);
	trace_fscache_cache(candidate->debug_id,
			    refcount_read(&candidate->ref),
			    fscache_cache_new_acquire);
	up_write(&fscache_addremove_sem);
	return candidate;
}
EXPORT_SYMBOL(fscache_acquire_cache);

void fscache_put_cache(struct fscache_cache *cache,
		       enum fscache_cache_trace where)
{
	unsigned int debug_id = cache->debug_id;
	bool zero;
	int ref;

	if (IS_ERR_OR_NULL(cache))
		return;

	zero = __refcount_dec_and_test(&cache->ref, &ref);
	trace_fscache_cache(debug_id, ref - 1, where);

	if (zero) {
		down_write(&fscache_addremove_sem);
		list_del_init(&cache->cache_link);
		up_write(&fscache_addremove_sem);
		kfree(cache);
	}
}
EXPORT_SYMBOL(fscache_put_cache);

/**
 * fscache_add_cache - Declare a cache as being open for business
 * @cache: The record describing the cache
 * @ops: Table of cache operations to use
 * @cache_priv: Private data for the cache record
 *
 * Add a cache to the system, making it available for netfs's to use.
 *
 * See Documentation/filesystems/caching/backend-api.rst for a complete
 * description.
 */
int fscache_add_cache(struct fscache_cache *cache,
		      const struct fscache_cache_ops *ops,
		      void *cache_priv)
{
	_enter("{%s,%s}", ops->name, cache->name);

	BUG_ON(fscache_cache_state(cache) != FSCACHE_CACHE_IS_PREPARING);

	down_write(&fscache_addremove_sem);

	cache->ops = ops;
	cache->cache_priv = cache_priv;
	fscache_set_cache_state(cache, FSCACHE_CACHE_IS_LIVE);

	up_write(&fscache_addremove_sem);
	pr_notice("Cache \"%s\" added (type %s)\n", cache->name, ops->name);
	_leave(" = 0 [%s]", cache->name);
	return 0;
}
EXPORT_SYMBOL(fscache_add_cache);

/*
 * Get an increment on a cache's access counter if the cache is live to prevent
 * it from going away whilst we're accessing it.
 */
bool fscache_begin_cache_access(struct fscache_cache *cache, enum fscache_access_trace why)
{
	int n_accesses;

	if (!fscache_cache_is_live(cache))
		return false;

	n_accesses = atomic_inc_return(&cache->n_accesses);
	smp_mb__after_atomic(); /* Reread live flag after n_accesses */
	trace_fscache_access_cache(cache->debug_id, refcount_read(&cache->ref),
				   n_accesses, why);
	if (!fscache_cache_is_live(cache)) {
		fscache_end_cache_access(cache, fscache_access_unlive);
		return false;
	}
	return true;
}

/*
 * Drop an increment on a cache's access counter.
 */
void fscache_end_cache_access(struct fscache_cache *cache, enum fscache_access_trace why)
{
	int n_accesses;

	smp_mb__before_atomic();
	n_accesses = atomic_dec_return(&cache->n_accesses);
	trace_fscache_access_cache(cache->debug_id, refcount_read(&cache->ref),
				   n_accesses, why);
	if (n_accesses == 0)
		wake_up_var(&cache->n_accesses);
}

/**
 * fscache_io_error - Note a cache I/O error
 * @cache: The record describing the cache
 *
 * Note that an I/O error occurred in a cache and that it should no longer be
 * used for anything.  This also reports the error into the kernel log.
 *
 * See Documentation/filesystems/caching/backend-api.rst for a complete
 * description.
 */
void fscache_io_error(struct fscache_cache *cache)
{
	if (fscache_set_cache_state_maybe(cache,
					  FSCACHE_CACHE_IS_LIVE,
					  FSCACHE_CACHE_GOT_IOERROR))
		pr_err("Cache '%s' stopped due to I/O error\n",
		       cache->name);
}
EXPORT_SYMBOL(fscache_io_error);

/**
 * fscache_withdraw_cache - Withdraw a cache from the active service
 * @cache: The cache cookie
 *
 * Begin the process of withdrawing a cache from service.
 */
void fscache_withdraw_cache(struct fscache_cache *cache)
{
	pr_notice("Withdrawing cache \"%s\" (%u objs)\n",
		  cache->name, atomic_read(&cache->object_count));

	fscache_set_cache_state(cache, FSCACHE_CACHE_IS_WITHDRAWN);
}
EXPORT_SYMBOL(fscache_withdraw_cache);

#ifdef CONFIG_PROC_FS
static const char fscache_cache_states[NR__FSCACHE_CACHE_STATE] = "-PLEW";

/*
 * Generate a list of caches in /proc/fs/fscache/caches
 */
static int fscache_caches_seq_show(struct seq_file *m, void *v)
{
	struct fscache_cache *cache;

	if (v == &fscache_caches) {
		seq_puts(m,
			 "CACHE    REF   VOLS  OBJS  ACCES S NAME\n"
			 "======== ===== ===== ===== ===== = ===============\n"
			 );
		return 0;
	}

	cache = list_entry(v, struct fscache_cache, cache_link);
	seq_printf(m,
		   "%08x %5d %5d %5d %5d %c %s\n",
		   cache->debug_id,
		   refcount_read(&cache->ref),
		   atomic_read(&cache->n_volumes),
		   atomic_read(&cache->object_count),
		   atomic_read(&cache->n_accesses),
		   fscache_cache_states[cache->state],
		   cache->name);
	return 0;
}

static void *fscache_caches_seq_start(struct seq_file *m, loff_t *_pos)
	__acquires(fscache_addremove_sem)
{
	down_read(&fscache_addremove_sem);
	return seq_list_start_head(&fscache_caches, *_pos);
}

static void *fscache_caches_seq_next(struct seq_file *m, void *v, loff_t *_pos)
{
	return seq_list_next(v, &fscache_caches, _pos);
}

static void fscache_caches_seq_stop(struct seq_file *m, void *v)
	__releases(fscache_addremove_sem)
{
	up_read(&fscache_addremove_sem);
}

const struct seq_operations fscache_caches_seq_ops = {
	.start  = fscache_caches_seq_start,
	.next   = fscache_caches_seq_next,
	.stop   = fscache_caches_seq_stop,
	.show   = fscache_caches_seq_show,
};
#endif /* CONFIG_PROC_FS */
