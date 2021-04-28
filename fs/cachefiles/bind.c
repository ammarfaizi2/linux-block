// SPDX-License-Identifier: GPL-2.0-or-later
/* Bind and unbind a cache from the filesystem backing it
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/ctype.h>
#include <linux/xattr.h>
#include <trace/events/fscache.h>
#include "internal.h"

DECLARE_WAIT_QUEUE_HEAD(cachefiles_clearance_wq);

static int cachefiles_daemon_add_cache(struct cachefiles_cache *caches);

/*
 * bind a directory as a cache
 */
int cachefiles_daemon_bind(struct cachefiles_cache *cache, char *args)
{
	_enter("{%u,%u,%u,%u,%u,%u},%s",
	       cache->frun_percent,
	       cache->fcull_percent,
	       cache->fstop_percent,
	       cache->brun_percent,
	       cache->bcull_percent,
	       cache->bstop_percent,
	       args);

	/* start by checking things over */
	ASSERT(cache->fstop_percent < cache->fcull_percent &&
	       cache->fcull_percent < cache->frun_percent &&
	       cache->frun_percent  < 100);

	ASSERT(cache->bstop_percent < cache->bcull_percent &&
	       cache->bcull_percent < cache->brun_percent &&
	       cache->brun_percent  < 100);

	if (*args) {
		pr_err("'bind' command doesn't take an argument\n");
		return -EINVAL;
	}

	if (!cache->rootdirname) {
		pr_err("No cache directory specified\n");
		return -EINVAL;
	}

	/* don't permit already bound caches to be re-bound */
	if (test_bit(CACHEFILES_READY, &cache->flags)) {
		pr_err("Cache already bound\n");
		return -EBUSY;
	}

	return cachefiles_daemon_add_cache(cache);
}

/*
 * add a cache
 */
static int cachefiles_daemon_add_cache(struct cachefiles_cache *cache)
{
	struct fscache_cache *fscache;
	struct kstatfs stats;
	struct dentry *root;
	const struct cred *saved_cred;
	int ret;

	_enter("");

	fscache = fscache_acquire_cache(cache->tag);
	if (IS_ERR(fscache))
		return PTR_ERR(fscache);

	if (!fscache_set_cache_state_maybe(fscache,
					   FSCACHE_CACHE_IS_NOT_PRESENT,
					   FSCACHE_CACHE_IS_PREPARING)) {
		pr_warn("Cache tag in use\n");
		ret = -EBUSY;
		goto error_preparing;
	}

	/* we want to work under the module's security ID */
	ret = cachefiles_get_security_ID(cache);
	if (ret < 0)
		goto error_getsec;

	cachefiles_begin_secure(cache, &saved_cred);

	/* look up the directory at the root of the cache */
	ret = kern_path(cache->rootdirname, LOOKUP_DIRECTORY, &cache->root_path);
	if (ret < 0)
		goto error_open_root;

	ret = -EINVAL;
	if (mnt_user_ns(cache->root_path.mnt) != &init_user_ns) {
		pr_warn("File cache on idmapped mounts not supported");
		goto error_unsupported;
	}

	/* check parameters */
	root = cache->root_path.dentry;
	ret = -EOPNOTSUPP;
	if (d_is_negative(root) ||
	    !d_backing_inode(root)->i_op->lookup ||
	    !d_backing_inode(root)->i_op->mkdir ||
	    !(d_backing_inode(root)->i_opflags & IOP_XATTR) ||
	    !root->d_sb->s_op->statfs ||
	    !root->d_sb->s_op->sync_fs)
		goto error_unsupported;

	ret = -EROFS;
	if (sb_rdonly(root->d_sb))
		goto error_unsupported;

	/* determine the security of the on-disk cache as this governs
	 * security ID of files we create */
	ret = cachefiles_determine_cache_security(cache, root, &saved_cred);
	if (ret < 0)
		goto error_unsupported;

	/* get the cache size and blocksize */
	ret = vfs_statfs(&cache->root_path, &stats);
	if (ret < 0)
		goto error_unsupported;

	ret = -ERANGE;
	if (stats.f_bsize <= 0)
		goto error_unsupported;

	ret = -EOPNOTSUPP;
	if (stats.f_bsize > PAGE_SIZE)
		goto error_unsupported;

	cache->bsize = stats.f_bsize;
	cache->bshift = 0;
	if (stats.f_bsize < PAGE_SIZE)
		cache->bshift = PAGE_SHIFT - ilog2(stats.f_bsize);

	_debug("blksize %u (shift %u)",
	       cache->bsize, cache->bshift);

	_debug("size %llu, avail %llu",
	       (unsigned long long) stats.f_blocks,
	       (unsigned long long) stats.f_bavail);

	/* set up caching limits */
	do_div(stats.f_files, 100);
	cache->fstop = stats.f_files * cache->fstop_percent;
	cache->fcull = stats.f_files * cache->fcull_percent;
	cache->frun  = stats.f_files * cache->frun_percent;

	_debug("limits {%llu,%llu,%llu} files",
	       (unsigned long long) cache->frun,
	       (unsigned long long) cache->fcull,
	       (unsigned long long) cache->fstop);

	stats.f_blocks >>= cache->bshift;
	do_div(stats.f_blocks, 100);
	cache->bstop = stats.f_blocks * cache->bstop_percent;
	cache->bcull = stats.f_blocks * cache->bcull_percent;
	cache->brun  = stats.f_blocks * cache->brun_percent;

	_debug("limits {%llu,%llu,%llu} blocks",
	       (unsigned long long) cache->brun,
	       (unsigned long long) cache->bcull,
	       (unsigned long long) cache->bstop);

	ret = cachefiles_get_directory(cache, "cache", &cache->cache_path);
	if (ret < 0)
		goto error_unsupported;

	ret = cachefiles_get_directory(cache, "graveyard", &cache->graveyard_path);
	if (ret < 0)
		goto error_unsupported;

	cache->cache = fscache;
	ret = fscache_add_cache(fscache, &cachefiles_cache_ops, cache);
	if (ret < 0)
		goto error_add_cache;

	/* done */
	set_bit(CACHEFILES_READY, &cache->flags);

	pr_info("File cache on %s registered\n", fscache->name);

	/* check how much space the cache has */
	cachefiles_has_space(cache, 0, 0);
	cachefiles_end_secure(cache, saved_cred);
	_leave(" = 0 [%px]", cache->cache);
	return 0;

error_add_cache:
	path_put(&cache->graveyard_path);
	memset(&cache->graveyard_path, 0, sizeof(cache->graveyard_path));
error_unsupported:
	path_put(&cache->cache_path);
	path_put(&cache->root_path);
	memset(&cache->cache_path, 0, sizeof(cache->cache_path));
	memset(&cache->root_path, 0, sizeof(cache->root_path));
error_open_root:
	cachefiles_end_secure(cache, saved_cred);
error_getsec:
	fscache_set_cache_state(fscache, FSCACHE_CACHE_IS_NOT_PRESENT);
error_preparing:
	fscache_put_cache(fscache, fscache_cache_put_cache);
	cache->cache = NULL;
	pr_err("Failed to register: %d\n", ret);
	return ret;
}

/*
 * Withdraw an object.
 */
static void cachefiles_withdraw_object(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache = object->cache;
	struct fscache_cookie *cookie = object->cookie;
	const struct cred *saved_cred;
	bool invalidate;
	int n_accesses;

	_enter("o=%x", object->debug_id);

	/* Wait for the object to become inactive.  A wakeup will be generated
	 * when someone transitions n_accesses to 0.
	 */
	n_accesses = atomic_dec_return(&object->cookie->n_accesses);
	trace_fscache_access(cookie->debug_id, refcount_read(&cookie->ref),
			     n_accesses, fscache_access_cache_unpin);
	wait_var_event(&object->cookie->n_accesses,
		       atomic_read(&object->cookie->n_accesses) == 0);

	/* If the netfs hadn't finished using the object, we don't know what
	 * state the coherency is in and we should just invalidate the object;
	 * otherwise we note whether it got retired.
	 */
	switch (cookie->stage) {
	case FSCACHE_COOKIE_STAGE_DROPPED:
		goto out;
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
		invalidate = test_bit(FSCACHE_COOKIE_RETIRED, &cookie->flags);
		break;
	default:
		invalidate = true;
		break;
	}

	cachefiles_begin_secure(cache, &saved_cred);
	cachefiles_clean_up_object(object, cache, invalidate);
	cachefiles_end_secure(cache, saved_cred);

	if (cookie->stage == FSCACHE_COOKIE_STAGE_RELINQUISHING) {
		fscache_drop_cookie(cookie, fscache_cookie_put_withdrawn);
	} else {
		cookie->cache_priv = NULL;
		clear_bit(FSCACHE_COOKIE_OBJ_NEEDS_UPDATE, &cookie->flags);
		clear_bit(FSCACHE_COOKIE_LOCAL_WRITE, &cookie->flags);
		set_bit(FSCACHE_COOKIE_NO_DATA_TO_READ, &cookie->flags);
		fscache_set_cookie_stage(cookie, FSCACHE_COOKIE_STAGE_QUIESCENT);
	}

out:
	cachefiles_put_object(object, cachefiles_obj_put_detach);
}

/*
 * Work item to withdraw cache objects.
 */
void cachefiles_withdrawal_work(struct work_struct *work)
{
	struct cachefiles_object *object =
		container_of(work, struct cachefiles_object, work);

	cachefiles_withdraw_object(object);
}

/*
 * Mark all the objects as being out of service and move them all to the
 * withdrawal queue.
 */
static void cachefiles_withdraw_objects(struct cachefiles_cache *cache)
{
	struct cachefiles_object *object;
	unsigned int count = 0;

	_enter("");

	spin_lock(&cache->object_list_lock);

	while (!list_empty(&cache->object_list)) {
		object = list_first_entry(&cache->object_list,
					  struct cachefiles_object, cache_link);
		clear_bit(FSCACHE_COOKIE_IS_CACHING, &object->flags);
		list_move(&object->cache_link, &cache->withdrawal_list);
		queue_work(system_unbound_wq, &object->work);
		count++;
		if ((count & 63) == 0) {
			spin_unlock(&cache->object_list_lock);
			cond_resched();
			spin_lock(&cache->object_list_lock);
		}
	}

	spin_unlock(&cache->object_list_lock);
	_leave(" [%u objs]", count);
}

/*
 * Withdraw volumes.
 */
static void cachefiles_withdraw_volumes(struct cachefiles_cache *cache)
{
	struct fscache_volume *volume;

	_enter("");

	down_read(&fscache_addremove_sem);

	list_for_each_entry(volume, &cache->cache->volumes, cache_link) {
		if (volume->cache_priv) {
			_debug("withdraw V=%x", volume->debug_id);
			atomic_dec(&volume->n_accesses); /* Allow wakeups on dec-to-0 */
			wait_var_event(&volume->n_accesses,
				       atomic_read(&volume->n_accesses) == 0);
			dput(volume->cache_priv);
			volume->cache_priv = NULL;
		}
	}

	up_read(&fscache_addremove_sem);

	_leave("");
}

/*
 * Withdraw cache objects.
 */
static void cachefiles_withdraw_cache(struct cachefiles_cache *cache)
{
	struct fscache_cache *fscache = cache->cache;

	pr_info("File cache on %s unregistering\n", fscache->name);

	fscache_withdraw_cache(fscache);

	/* we now have to destroy all the active objects pertaining to this
	 * cache - which we do by passing them off to thread pool to be
	 * disposed of */
	cachefiles_withdraw_objects(cache);
	cachefiles_withdraw_volumes(cache);

	/* make sure all outstanding data is written to disk */
	cachefiles_sync_cache(cache);

	/* wait for all extant objects to finish their outstanding operations
	 * and go away */
	_debug("wait for finish %u", atomic_read(&fscache->object_count));
	wait_event(cachefiles_clearance_wq,
		   atomic_read(&fscache->object_count) == 0);
	_debug("cleared");

	_debug("wait for clearance");
	wait_event(cachefiles_clearance_wq, list_empty(&cache->object_list));

	cache->cache = NULL;
	fscache->ops = NULL;
	fscache->cache_priv = NULL;
	fscache_set_cache_state(fscache, FSCACHE_CACHE_IS_NOT_PRESENT);
	fscache_put_cache(fscache, fscache_cache_put_withdraw);
}

/*
 * unbind a cache on fd release
 */
void cachefiles_daemon_unbind(struct cachefiles_cache *cache)
{
	_enter("%px", cache->cache);

	if (test_bit(CACHEFILES_READY, &cache->flags))
		cachefiles_withdraw_cache(cache);

	path_put(&cache->graveyard_path);
	path_put(&cache->cache_path);
	path_put(&cache->root_path);

	kfree(cache->rootdirname);
	kfree(cache->secctx);
	kfree(cache->tag);

	_leave("");
}
