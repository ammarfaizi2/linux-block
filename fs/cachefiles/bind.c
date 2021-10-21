// SPDX-License-Identifier: GPL-2.0-or-later
/* Bind and unbind a cache from the filesystem backing it
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
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
	struct fscache_cache *cache_cookie;
	struct path path;
	struct kstatfs stats;
	struct dentry *graveyard, *cachedir, *root;
	const struct cred *saved_cred;
	int ret;

	_enter("");

	cache_cookie = fscache_acquire_cache(cache->tag);
	if (IS_ERR(cache_cookie))
		return PTR_ERR(cache_cookie);

	if (!fscache_set_cache_state_maybe(cache_cookie,
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
	ret = kern_path(cache->rootdirname, LOOKUP_DIRECTORY, &path);
	if (ret < 0)
		goto error_open_root;

	cache->mnt = path.mnt;
	root = path.dentry;

	ret = -EINVAL;
	if (mnt_user_ns(path.mnt) != &init_user_ns) {
		pr_warn("File cache on idmapped mounts not supported");
		goto error_unsupported;
	}

	/* check parameters */
	ret = -EOPNOTSUPP;
	if (d_is_negative(root) ||
	    !d_backing_inode(root)->i_op->lookup ||
	    !d_backing_inode(root)->i_op->mkdir ||
	    !(d_backing_inode(root)->i_opflags & IOP_XATTR) ||
	    !root->d_sb->s_op->statfs ||
	    !root->d_sb->s_op->sync_fs ||
	    root->d_sb->s_blocksize > PAGE_SIZE)
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
	ret = vfs_statfs(&path, &stats);
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

	/* get the cache directory and check its type */
	cachedir = cachefiles_get_directory(cache, root, "cache");
	if (IS_ERR(cachedir)) {
		ret = PTR_ERR(cachedir);
		goto error_unsupported;
	}

	cache->store = cachedir;

	/* get the graveyard directory */
	graveyard = cachefiles_get_directory(cache, root, "graveyard");
	if (IS_ERR(graveyard)) {
		ret = PTR_ERR(graveyard);
		goto error_unsupported;
	}

	cache->graveyard = graveyard;
	cache->cache = cache_cookie;

	ret = fscache_add_cache(cache_cookie, &cachefiles_cache_ops, cache);
	if (ret < 0)
		goto error_add_cache;

	/* done */
	set_bit(CACHEFILES_READY, &cache->flags);
	dput(root);

	pr_info("File cache on %s registered\n", cache_cookie->name);

	/* check how much space the cache has */
	cachefiles_has_space(cache, 0, 0, cachefiles_has_space_check);
	cachefiles_end_secure(cache, saved_cred);
	_leave(" = 0 [%px]", cache->cache);
	return 0;

error_add_cache:
	dput(cache->graveyard);
	cache->graveyard = NULL;
error_unsupported:
	dput(cache->store);
	cache->store = NULL;
	mntput(cache->mnt);
	cache->mnt = NULL;
	dput(root);
error_open_root:
	cachefiles_end_secure(cache, saved_cred);
error_getsec:
	fscache_set_cache_state(cache_cookie, FSCACHE_CACHE_IS_NOT_PRESENT);
error_preparing:
	fscache_put_cache(cache_cookie, fscache_cache_put_cache);
	cache->cache = NULL;
	pr_err("Failed to register: %d\n", ret);
	return ret;
}

/*
 * Mark all the objects as being out of service and queue them all for cleanup.
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
		cachefiles_see_object(object, cachefiles_obj_see_withdrawal);
		list_del_init(&object->cache_link);
		fscache_withdraw_cookie(object->cookie);
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
	_enter("");

	for (;;) {
		struct cachefiles_volume *volume = NULL;

		spin_lock(&cache->object_list_lock);
		if (!list_empty(&cache->volumes)) {
			volume = list_first_entry(&cache->volumes,
						  struct cachefiles_volume, cache_link);
			list_del_init(&volume->cache_link);
		}
		spin_unlock(&cache->object_list_lock);
		if (!volume)
			break;

		cachefiles_withdraw_volume(volume);
	}

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

	/* wait for all extant objects to finish their outstanding operations
	 * and go away */
	_debug("wait for finish %u", atomic_read(&fscache->object_count));
	wait_event(cachefiles_clearance_wq,
		   atomic_read(&fscache->object_count) == 0);
	_debug("cleared");

	cachefiles_withdraw_volumes(cache);

	/* make sure all outstanding data is written to disk */
	cachefiles_sync_cache(cache);

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

	dput(cache->graveyard);
	dput(cache->store);
	mntput(cache->mnt);

	kfree(cache->rootdirname);
	kfree(cache->secctx);
	kfree(cache->tag);

	_leave("");
}
