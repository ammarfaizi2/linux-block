// SPDX-License-Identifier: GPL-2.0-or-later
/* Volume-level cache cookie handling.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL COOKIE
#include <linux/export.h>
#include <linux/slab.h>
#include "internal.h"

#define fscache_volume_hash_shift 10
static struct hlist_bl_head fscache_volume_hash[1 << fscache_volume_hash_shift];
static atomic_t fscache_volume_debug_id;
static LIST_HEAD(fscache_volumes);

struct fscache_volume *fscache_get_volume(struct fscache_volume *volume,
					  enum fscache_volume_trace where)
{
	int ref;

	__refcount_inc(&volume->ref, &ref);
	trace_fscache_volume(volume->debug_id, ref + 1, where);
	return volume;
}

static void fscache_see_volume(struct fscache_volume *volume,
			       enum fscache_volume_trace where)
{
	int ref = refcount_read(&volume->ref);

	trace_fscache_volume(volume->debug_id, ref, where);
}

/*
 * Pin the cache behind a volume so that we can access it.
 */
bool fscache_begin_volume_access(struct fscache_volume *volume,
				 enum fscache_access_trace why)
{
	int n_accesses;

	if (!fscache_cache_is_live(volume->cache))
		return false;
	n_accesses = atomic_inc_return(&volume->n_accesses);
	smp_mb__after_atomic();
	trace_fscache_access_volume(volume->debug_id, refcount_read(&volume->ref),
				    n_accesses, why);
	if (!fscache_cache_is_live(volume->cache)) {
		fscache_end_volume_access(volume, fscache_access_unlive);
		return false;
	}
	return true;
}

/*
 * Mark the end of an access on a volume.
 */
void fscache_end_volume_access(struct fscache_volume *volume,
			       enum fscache_access_trace why)
{
	int n_accesses;

	smp_mb__before_atomic();
	n_accesses = atomic_dec_return(&volume->n_accesses);
	trace_fscache_access_volume(volume->debug_id, refcount_read(&volume->ref),
				    n_accesses, why);
	if (n_accesses == 0)
		wake_up_var(&volume->n_accesses);
}
EXPORT_SYMBOL(fscache_end_volume_access);

/*
 * Remove a volume cookie from the hash table.
 */
static void fscache_unhash_volume(struct fscache_volume *volume)
{
	struct hlist_bl_head *h;
	unsigned int bucket;

	bucket = volume->key_hash & (ARRAY_SIZE(fscache_volume_hash) - 1);
	h = &fscache_volume_hash[bucket];

	hlist_bl_lock(h);
	hlist_bl_del(&volume->hash_link);
	hlist_bl_unlock(h);
}

/*
 * Drop a cache's volume attachments.
 */
static void fscache_do_relinquish_volume(struct fscache_volume *volume)
{
	if (fscache_begin_volume_access(volume, fscache_access_relinquish_volume)) {
		if (volume->cache->ops->relinquish_volume)
			volume->cache->ops->relinquish_volume(volume);
		fscache_end_volume_access(volume, fscache_access_relinquish_volume_end);
	}
}

/*
 * Drop a reference to a volume cookie.
 */
void fscache_put_volume(struct fscache_volume *volume,
			enum fscache_volume_trace where)
{
	if (volume) {
		unsigned int debug_id = volume->debug_id;
		bool zero;
		int ref;

		zero = __refcount_dec_and_test(&volume->ref, &ref);
		trace_fscache_volume(debug_id, ref - 1, where);
		if (zero) {
			struct fscache_cache *cache = volume->cache;

			fscache_do_relinquish_volume(volume);

			down_write(&fscache_addremove_sem);
			list_del_init(&volume->proc_link);
			list_del_init(&volume->cache_link);
			atomic_dec(&volume->cache->n_volumes);
			up_write(&fscache_addremove_sem);

			if (!hlist_bl_unhashed(&volume->hash_link))
				fscache_unhash_volume(volume);

			smp_mb__before_atomic();
			set_bit(FSCACHE_VOLUME_DROPPED, &volume->flags);
			wake_up_bit(&volume->flags, FSCACHE_VOLUME_DROPPED);

			kfree(volume->key);
			kfree(volume);
			fscache_stat_d(&fscache_n_volumes);
			fscache_put_cache(cache, fscache_cache_put_volume);
		}
	}
}

static bool fscache_is_volume_dropped(struct fscache_volume *volume)
{
	return test_bit(FSCACHE_VOLUME_DROPPED, &volume->flags);
}

static void fscache_wait_on_volume_collision(struct fscache_volume *candidate,
					     struct fscache_volume *wait_for)
{
	wait_var_event_timeout(&wait_for->flags, fscache_is_volume_dropped(wait_for),
			       20 * HZ);
	if (!fscache_is_volume_dropped(wait_for)) {
		pr_notice("Potential volume collision new=%08x old=%08x",
			  candidate->debug_id, wait_for->debug_id);
		fscache_stat(&fscache_n_volumes_collision);
		wait_var_event(&wait_for->flags, fscache_is_volume_dropped(wait_for));
	}
}

static long fscache_compare_volume(const struct fscache_volume *a,
				   const struct fscache_volume *b)
{
	size_t klen;

	if (a->key_hash != b->key_hash)
		return (long)a->key_hash - (long)b->key_hash;
	if (a->cache != b->cache)
		return (long)a->cache    - (long)b->cache;
	if (a->key[0] != b->key[0])
		return (long)a->key[0]   - (long)b->key[0];

	klen = round_up(a->key[0] + 1, sizeof(long));
	return memcmp(a->key, b->key, klen);
}

/*
 * Attempt to insert the new volume into the hash.  If there's a collision, we
 * wait for the old volume to complete if it's being relinquished and an error
 * otherwise.
 */
static struct fscache_volume *fscache_hash_volume(struct fscache_volume *candidate)
{
	struct fscache_volume *cursor, *wait_for = NULL;
	struct hlist_bl_head *h;
	struct hlist_bl_node *p;
	unsigned int bucket;

	bucket = candidate->key_hash & (ARRAY_SIZE(fscache_volume_hash) - 1);
	h = &fscache_volume_hash[bucket];

	hlist_bl_lock(h);
	hlist_bl_for_each_entry(cursor, p, h, hash_link) {
		if (fscache_compare_volume(candidate, cursor) == 0) {
			if (!test_bit(FSCACHE_VOLUME_RELINQUISHED, &cursor->flags))
				goto collision;
			wait_for = fscache_get_volume(cursor,
						      fscache_volume_get_hash_collision);
			break;
		}
	}

	hlist_bl_add_head(&candidate->hash_link, h);
	hlist_bl_unlock(h);

	if (wait_for) {
		fscache_wait_on_volume_collision(candidate, wait_for);
		fscache_put_volume(wait_for, fscache_volume_put_hash_wait);
	}
	return candidate;

collision:
	fscache_see_volume(cursor, fscache_volume_collision);
	pr_err("Cache volume already in use\n");
	hlist_bl_unlock(h);
	return NULL;
}

/*
 * Allocate and initialise a volume representation cookie.
 */
static struct fscache_volume *fscache_alloc_volume(const char *volume_key,
						   const char *cache_name,
						   u64 coherency_data)
{
	struct fscache_volume *volume;
	struct fscache_cache *cache;
	unsigned long hash;
	size_t klen, hlen;
	char *key;
	int i;

	if (!cache_name)
		cache_name = "default";

	cache = fscache_acquire_cache(cache_name);
	if (!cache)
		return NULL;

	volume = kzalloc(sizeof(*volume), GFP_KERNEL);
	if (!volume)
		goto err_cache;

	volume->cache = cache;
	volume->coherency = coherency_data;
	INIT_LIST_HEAD(&volume->proc_link);
	INIT_LIST_HEAD(&volume->cache_link);
	refcount_set(&volume->ref, 1);
	spin_lock_init(&volume->lock);

	/* Stick the length on the front of the key and pad it out to a whole
	 * number of words to make hashing easier.
	 */
	klen = strlen(volume_key);
	hlen = round_up(1 + klen + 1, sizeof(long));
	key = kzalloc(hlen, GFP_KERNEL);
	if (!key)
		goto err_vol;
	key[0] = klen;
	memcpy(key + 1, volume_key, klen);

	hash = (unsigned long)cache;
	for (i = 0; i < hlen / 4; i++) {
		hash *= 0x9201;
		hash += key[i];
	}
	volume->key_hash = hash;
	volume->key = key;

	volume->debug_id = atomic_inc_return(&fscache_volume_debug_id);
	down_write(&fscache_addremove_sem);
	atomic_inc(&cache->n_volumes);
	list_add_tail(&volume->proc_link, &fscache_volumes);
	fscache_see_volume(volume, fscache_volume_new_acquire);
	fscache_stat(&fscache_n_volumes);
	up_write(&fscache_addremove_sem);
	_leave(" = v=%x", volume->debug_id);
	return volume;

err_vol:
	kfree(volume);
err_cache:
	fscache_put_cache(cache, fscache_cache_put_alloc_volume);
	fscache_stat(&fscache_n_volumes_nomem);
	return NULL;
}

/*
 * Acquire a volume representation cookie and link it to a (proposed) cache.
 */
struct fscache_volume *__fscache_acquire_volume(const char *volume_key,
						const char *cache_name,
						u64 coherency_data)
{
	const struct fscache_cache_ops *ops;
	struct fscache_volume *volume;

	volume = fscache_alloc_volume(volume_key, cache_name, coherency_data);
	if (!volume)
		return NULL;

	if (!fscache_hash_volume(volume)) {
		fscache_put_volume(volume, fscache_volume_put_hash_collision);
		return NULL;
	}

	down_write(&fscache_addremove_sem);
	list_add(&volume->cache_link, &volume->cache->volumes);
	up_write(&fscache_addremove_sem);

	if (fscache_begin_cache_access(volume->cache,
				       fscache_access_acquire_volume)) {
		ops = volume->cache->ops;
		if (ops->acquire_volume)
			ops->acquire_volume(volume);
		fscache_end_cache_access(volume->cache,
					 fscache_access_acquire_volume_end);
	}
	return volume;
}
EXPORT_SYMBOL(__fscache_acquire_volume);

/*
 * Relinquish a volume representation cookie.
 */
void __fscache_relinquish_volume(struct fscache_volume *volume,
				 u64 coherency_data,
				 bool invalidate)
{
	const struct fscache_cache_ops *ops;

	set_bit(FSCACHE_VOLUME_RELINQUISHED, &volume->flags);
	if (invalidate)
		set_bit(FSCACHE_VOLUME_INVALIDATE, &volume->flags);

	if (fscache_begin_volume_access(volume, fscache_access_relinquish_volume)) {
		ops = volume->cache->ops;
		if (ops->relinquish_volume)
			ops->relinquish_volume(volume);
		fscache_end_volume_access(volume, fscache_access_relinquish_volume_end);
	}

	fscache_put_volume(volume, fscache_volume_put_relinquish);
}
EXPORT_SYMBOL(__fscache_relinquish_volume);

#ifdef CONFIG_PROC_FS
/*
 * Generate a list of volumes in /proc/fs/fscache/volumes
 */
static int fscache_volumes_seq_show(struct seq_file *m, void *v)
{
	struct fscache_volume *volume;

	if (v == &fscache_volumes) {
		seq_puts(m,
			 "VOLUME   REF   nCOOK ACC FL CACHE           KEY\n"
			 "======== ===== ===== === == =============== ================\n");
		return 0;
	}

	volume = list_entry(v, struct fscache_volume, proc_link);
	seq_printf(m,
		   "%08x %5d %5d %3d %02lx %-15.15s %s\n",
		   volume->debug_id,
		   refcount_read(&volume->ref),
		   atomic_read(&volume->n_cookies),
		   atomic_read(&volume->n_accesses),
		   volume->flags,
		   volume->cache->name,
		   volume->key + 1);
	return 0;
}

static void *fscache_volumes_seq_start(struct seq_file *m, loff_t *_pos)
	__acquires(fscache_volumes_lock)
{
	down_read(&fscache_addremove_sem);
	return seq_list_start_head(&fscache_volumes, *_pos);
}

static void *fscache_volumes_seq_next(struct seq_file *m, void *v, loff_t *_pos)
{
	return seq_list_next(v, &fscache_volumes, _pos);
}

static void fscache_volumes_seq_stop(struct seq_file *m, void *v)
	__releases(rcu)
{
	up_read(&fscache_addremove_sem);
}

const struct seq_operations fscache_volumes_seq_ops = {
	.start  = fscache_volumes_seq_start,
	.next   = fscache_volumes_seq_next,
	.stop   = fscache_volumes_seq_stop,
	.show   = fscache_volumes_seq_show,
};
#endif /* CONFIG_PROC_FS */
