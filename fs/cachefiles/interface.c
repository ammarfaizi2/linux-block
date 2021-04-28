// SPDX-License-Identifier: GPL-2.0-or-later
/* FS-Cache interface to CacheFiles
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/file.h>
#include <linux/falloc.h>
#include <trace/events/fscache.h>
#include "internal.h"

static atomic_t cachefiles_object_debug_id;

static int cachefiles_attr_changed(struct cachefiles_object *object);

/*
 * Allocate an object record for a cookie lookup and prepare the lookup data.
 * Eats the caller's ref on parent.
 */
static
struct cachefiles_object *cachefiles_alloc_object(struct fscache_cookie *cookie)
{
	struct fscache_cache *fscache = cookie->volume->cache;
	struct cachefiles_object *object;
	struct cachefiles_cache *cache = fscache->cache_priv;
	int n_accesses;

	_enter("{%s},%x,", fscache->name, cookie->debug_id);

	object = kmem_cache_zalloc(cachefiles_object_jar, cachefiles_gfp);
	if (!object)
		return NULL;

	rwlock_init(&object->content_map_lock);
	object->stage = CACHEFILES_OBJECT_STAGE_LOOKING_UP;
	atomic_set(&object->usage, 1);

	spin_lock_init(&object->lock);
	INIT_LIST_HEAD(&object->cache_link);
	INIT_WORK(&object->work, cachefiles_withdrawal_work);
	object->cache = cache;
	object->debug_id = atomic_inc_return(&cachefiles_object_debug_id);
	object->cookie = fscache_get_cookie(cookie, fscache_cookie_get_attach_object);

	atomic_inc(&fscache->object_count);
	trace_cachefiles_ref(object->debug_id, cookie->debug_id, 1,
			     cachefiles_obj_new);

	/* Get a ref on the cookie and keep its n_accesses counter raised by 1
	 * to prevent wakeups from transitioning it to 0 until we're
	 * withdrawing caching services from it.
	 */
	n_accesses = atomic_inc_return(&cookie->n_accesses);
	trace_fscache_access(cookie->debug_id, refcount_read(&cookie->ref),
			     n_accesses, fscache_access_cache_pin);
	return object;
}

/*
 * Prepare data for use in lookup.  This involves cooking the binary key into
 * something that can be used as a filename.
 */
static char *cachefiles_prepare_lookup_data(struct cachefiles_object *object)
{
	struct fscache_cookie *cookie = object->cookie;
	unsigned keylen;
	void *buffer, *p;
	char *key;

	/* get hold of the raw key
	 * - stick the length on the front and leave space on the back for the
	 *   encoder
	 */
	buffer = kmalloc((2 + 512) + 3, cachefiles_gfp);
	if (!buffer)
		goto nomem;

	keylen = cookie->key_len;
	p = fscache_get_key(cookie);
	memcpy(buffer + 2, p, keylen);

	*(uint16_t *)buffer = keylen;
	((char *)buffer)[keylen + 2] = 0;
	((char *)buffer)[keylen + 3] = 0;
	((char *)buffer)[keylen + 4] = 0;

	/* turn the raw key into something that we can work with as a filename */
	key = cachefiles_cook_key(buffer, keylen + 2, &object->key_hash);
	kfree(buffer);
	if (!key)
		goto nomem;

	_leave(" = %s", key);
	return key;

nomem:
	return NULL;
}

/*
 * Attempt to look up the nominated node in this cache
 */
static bool cachefiles_lookup_cookie(struct fscache_cookie *cookie)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache = cookie->volume->cache->cache_priv;
	const struct cred *saved_cred;
	char *lookup_key;
	bool success, bound = false;

	object = cachefiles_alloc_object(cookie);
	if (!object)
		goto fail;

	_enter("{OBJ%x}", object->debug_id);

	lookup_key = cachefiles_prepare_lookup_data(object);
	if (!lookup_key)
		goto fail_obj;

	/* look up the key, creating any missing bits */
	cachefiles_begin_secure(cache, &saved_cred);
	success = cachefiles_walk_to_object(object, lookup_key);
	cachefiles_end_secure(cache, saved_cred);
	kfree(lookup_key);

	if (!success)
		goto fail_obj;

	spin_lock(&cookie->lock);
	if (cookie->stage == FSCACHE_COOKIE_STAGE_LOOKING_UP) {
		cachefiles_see_object(object, cachefiles_obj_see_lookup_cookie);
		cookie->cache_priv = object;
		bound = true;
	}
	spin_unlock(&cookie->lock);

	if (!bound)
		goto fail_clean;

	spin_lock(&cache->object_list_lock);
	list_add(&object->cache_link, &cache->object_list);
	spin_unlock(&cache->object_list_lock);
	cachefiles_attr_changed(object);
	_leave(" = t");
	return true;

fail_clean:
	cachefiles_see_object(object, cachefiles_obj_see_lookup_scrapped);
	kdebug("scrapped c=%08x", cookie->debug_id);
	cachefiles_clean_up_object(object, cache, false);
fail_obj:
	cachefiles_put_object(object, cachefiles_obj_put_alloc_fail);
fail:
	return false;
}

/*
 * Note that an object has been seen.
 */
void cachefiles_see_object(struct cachefiles_object *object,
			   enum cachefiles_obj_ref_trace why)
{
	trace_cachefiles_ref(object->debug_id, object->cookie->debug_id,
			     atomic_read(&object->usage), why);
}

/*
 * increment the usage count on an inode object (may fail if unmounting)
 */
struct cachefiles_object *cachefiles_grab_object(struct cachefiles_object *object,
						 enum cachefiles_obj_ref_trace why)
{
	int u;

	u = atomic_inc_return(&object->usage);
	trace_cachefiles_ref(object->debug_id, object->cookie->debug_id, u, why);
	return object;
}

/*
 * Shorten the backing object to discard any dirty data and free up
 * any unused granules.
 */
static bool cachefiles_shorten_object(struct cachefiles_object *object, loff_t new_size)
{
	struct cachefiles_cache *cache = object->cache;
	struct inode *inode = d_inode(object->dentry);
	struct path path;
	loff_t i_size, dio_size;
	int ret;

	dio_size = round_up(new_size, CACHEFILES_DIO_BLOCK_SIZE);
	i_size = i_size_read(inode);

	path.mnt = cache->cache_path.mnt;
	path.dentry = object->dentry;

	trace_cachefiles_trunc(object, inode, i_size, dio_size, cachefiles_trunc_shrink);
	ret = vfs_truncate(&path, dio_size);
	if (ret < 0) {
		cachefiles_io_error_obj(object, "Trunc-to-size failed %d", ret);
		cachefiles_remove_object_xattr(cache, object->dentry);
		return false;
	}

	if (new_size < dio_size) {
		trace_cachefiles_trunc(object, inode, dio_size, new_size,
				       cachefiles_trunc_clear);
		ret = vfs_fallocate(object->backing_file, FALLOC_FL_ZERO_RANGE,
				    new_size, dio_size);
		if (ret < 0) {
			cachefiles_io_error_obj(object, "Trunc-to-dio-size failed %d", ret);
			cachefiles_remove_object_xattr(cache, object->dentry);
			return false;
		}
	}

	return true;
}

/*
 * Resize the backing object.
 */
static void cachefiles_resize_cookie(struct netfs_cache_resources *cres,
				     loff_t new_size)
{
	struct fscache_cookie *cookie = fscache_cres_cookie(cres);
	struct cachefiles_object *object = cookie->cache_priv;
	struct cachefiles_cache *cache = object->cache;
	const struct cred *saved_cred;
	loff_t old_size = cookie->object_size;

	_enter("%llu->%llu", old_size, new_size);

	if (new_size < old_size) {
		cachefiles_begin_secure(cache, &saved_cred);
		cachefiles_shorten_content_map(object, new_size);
		cachefiles_shorten_object(object, new_size);
		cachefiles_end_secure(cache, saved_cred);
		cookie->object_size = new_size;
		return;
	}

	/* The file is being expanded.  We don't need to do anything
	 * particularly.  cookie->initial_size doesn't change and so the point
	 * at which we have to download before doesn't change.
	 */
	cookie->object_size = new_size;
}

/*
 * Commit changes to the object as we drop it.
 */
static bool cachefiles_commit_object(struct cachefiles_object *object,
				     struct cachefiles_cache *cache)
{
	bool update = false;

	if (object->content_map_changed)
		cachefiles_save_content_map(object);
	if (test_and_clear_bit(FSCACHE_OBJECT_LOCAL_WRITE, &object->flags))
		update = true;
	if (test_and_clear_bit(FSCACHE_COOKIE_OBJ_NEEDS_UPDATE, &object->cookie->flags))
		update = true;
	if (update)
		cachefiles_set_object_xattr(object);

	if (test_bit(CACHEFILES_OBJECT_USING_TMPFILE, &object->flags))
		return cachefiles_commit_tmpfile(cache, object);
	return true;
}

/*
 * Finalise and object and close the VFS structs that we have.
 */
void cachefiles_clean_up_object(struct cachefiles_object *object,
				struct cachefiles_cache *cache,
				bool invalidate)
{
	if (invalidate) {
		_debug("- inval object OBJ%x", object->debug_id);
		cachefiles_delete_object(cache, object);
	} else {
		cachefiles_commit_object(object, cache);
	}

	/* close the filesystem stuff attached to the object */
	if (object->backing_file)
		fput(object->backing_file);
	object->backing_file = NULL;

	dput(object->old);
	object->old = NULL;

	cachefiles_unmark_inode_in_use(object);
	dput(object->dentry);
	object->dentry = NULL;
}

/*
 * discard the resources pinned by an object and effect retirement if
 * requested
 */
static void cachefiles_relinquish_cookie(struct fscache_cookie *cookie)
{
	struct cachefiles_object *object = cookie->cache_priv;
	struct cachefiles_cache *cache = cookie->volume->cache->cache_priv;
	const struct cred *saved_cred;
	bool invalidate = test_bit(FSCACHE_COOKIE_RETIRED, &cookie->flags);
	int n_accesses;

	clear_bit(FSCACHE_COOKIE_IS_CACHING, &cookie->flags);
	smp_store_release(&cookie->cache_priv, NULL);

	if (object) {
		/* There should be one count on n_accesses for the cache
		 * binding and one for the relinquishment op, but the former
		 * doesn't necessarily hold true if the cache is being
		 * withdrawn and there may be ops in progress, so if we're
		 * unsure, punt to the withdrawal list (we can't dec n_accesses
		 * here).
		 */
		spin_lock(&cache->object_list_lock);
		n_accesses = atomic_read(&cookie->n_accesses);
		if (n_accesses != 2 ||
		    !fscache_cache_is_live(cookie->volume->cache)) {
			trace_fscache_access(
				cookie->debug_id, refcount_read(&cookie->ref),
				n_accesses, fscache_access_relinquish_defer);
			kdebug("punt c=%x", cookie->debug_id);
			list_move(&object->cache_link, &cache->withdrawal_list);
			spin_unlock(&cache->object_list_lock);
			return;
		}

		list_del(&object->cache_link);
		spin_unlock(&cache->object_list_lock);

		/* We need to tidy the object up if we did in fact manage to
		 * open it.  It's possible for us to get here before the object
		 * is fully initialised if the parent goes away or the object
		 * gets retired before we set it up.
		 */
		if (object->dentry) {
			cachefiles_begin_secure(cache, &saved_cred);
			cachefiles_clean_up_object(object, cache, invalidate);
			cachefiles_end_secure(cache, saved_cred);
		}

		cachefiles_put_object(object, cachefiles_obj_put_detach);
	}

	fscache_drop_cookie(cookie, fscache_cookie_put_relinquish_cache);
	_leave("");
}

/*
 * dispose of a reference to an object
 */
void cachefiles_put_object(struct cachefiles_object *object,
			   enum cachefiles_obj_ref_trace why)
{
	unsigned int object_debug_id = object->debug_id;
	unsigned int cookie_debug_id = object->cookie->debug_id;
	struct fscache_cache *cache;
	int u;

	u = atomic_dec_return(&object->usage);
	trace_cachefiles_ref(object_debug_id, cookie_debug_id, u, why);
	if (u == 0) {
		_debug("- kill object OBJ%x", object_debug_id);

		ASSERTCMP(object->old, ==, NULL);
		ASSERTCMP(object->dentry, ==, NULL);

		kfree(object->content_map);

		cache = object->cache->cache;
		fscache_put_cookie(object->cookie, fscache_cookie_put_object);
		object->cookie = NULL;
		kmem_cache_free(cachefiles_object_jar, object);
		if (atomic_dec_and_test(&cache->object_count))
			wake_up_all(&cachefiles_clearance_wq);
	}

	_leave("");
}

/*
 * sync a cache
 */
void cachefiles_sync_cache(struct cachefiles_cache *cache)
{
	const struct cred *saved_cred;
	int ret;

	_enter("%s", cache->cache->name);

	/* make sure all pages pinned by operations on behalf of the netfs are
	 * written to disc */
	cachefiles_begin_secure(cache, &saved_cred);
	down_read(&cache->cache_path.mnt->mnt_sb->s_umount);
	ret = sync_filesystem(cache->cache_path.mnt->mnt_sb);
	up_read(&cache->cache_path.mnt->mnt_sb->s_umount);
	cachefiles_end_secure(cache, saved_cred);

	if (ret == -EIO)
		cachefiles_io_error(
			cache,
			"Attempt to sync backing fs superblock returned error %d",
			ret);
}

/*
 * notification the attributes on an object have changed
 * - called with reads/writes excluded by FS-Cache
 */
static int cachefiles_attr_changed(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache = object->cache;
	const struct cred *saved_cred;
	struct iattr newattrs;
	uint64_t ni_size;
	loff_t oi_size;
	int ret;

	ni_size = object->cookie->object_size;
	ni_size = round_up(ni_size, CACHEFILES_DIO_BLOCK_SIZE);

	_enter("{OBJ%x},[%llu]",
	       object->debug_id, (unsigned long long) ni_size);

	if (ni_size == object->i_size)
		return 0;

	if (!object->dentry)
		return -ENOBUFS;

	ASSERT(d_is_reg(object->dentry));

	oi_size = i_size_read(d_backing_inode(object->dentry));
	if (oi_size == ni_size)
		return 0;

	cachefiles_begin_secure(cache, &saved_cred);
	inode_lock(d_inode(object->dentry));

	/* if there's an extension to a partial page at the end of the backing
	 * file, we need to discard the partial page so that we pick up new
	 * data after it */
	if (oi_size & ~PAGE_MASK && ni_size > oi_size) {
		_debug("discard tail %llx", oi_size);
		newattrs.ia_valid = ATTR_SIZE;
		newattrs.ia_size = oi_size & PAGE_MASK;
		ret = notify_change(&init_user_ns, object->dentry, &newattrs, NULL);
		if (ret < 0)
			goto truncate_failed;
	}

	newattrs.ia_valid = ATTR_SIZE;
	newattrs.ia_size = ni_size;
	ret = notify_change(&init_user_ns, object->dentry, &newattrs, NULL);

truncate_failed:
	inode_unlock(d_inode(object->dentry));
	cachefiles_end_secure(cache, saved_cred);

	if (ret == -EIO) {
		cachefiles_io_error_obj(object, "Size set failed");
		ret = -ENOBUFS;
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * Create a temporary file and leave it unattached and un-xattr'd until the
 * time comes to discard the object from memory.
 */
static struct file *cachefiles_create_tmpfile(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache = object->cache;
	const struct cred *saved_cred;
	struct file *file;
	struct path path;
	uint64_t ni_size;
	long ret;

	ni_size = object->cookie->object_size;
	ni_size = round_up(ni_size, CACHEFILES_DIO_BLOCK_SIZE);

	cachefiles_begin_secure(cache, &saved_cred);

	path.mnt = cache->cache_path.mnt;
	path.dentry = vfs_tmpfile(&init_user_ns, cache->graveyard_path.dentry,
				  S_IFREG, O_RDWR);
	if (IS_ERR(path.dentry)) {
		if (PTR_ERR(path.dentry) == -EIO)
			cachefiles_io_error_obj(object, "Failed to create tmpfile");
		file = ERR_CAST(path.dentry);
		goto out;
	}

	trace_cachefiles_tmpfile(object, d_inode(path.dentry));

	if (ni_size > 0) {
		trace_cachefiles_trunc(object, d_inode(path.dentry), 0, ni_size,
				       cachefiles_trunc_expand_tmpfile);
		ret = vfs_truncate(&path, ni_size);
		if (ret < 0) {
			file = ERR_PTR(ret);
			goto out_dput;
		}
	}

	file = open_with_fake_path(&path,
				   O_RDWR | O_LARGEFILE | O_DIRECT,
				   d_backing_inode(path.dentry),
				   cache->cache_cred);
out_dput:
	dput(path.dentry);
out:
	cachefiles_end_secure(cache, saved_cred);
	return file;
}

/*
 * Invalidate the storage associated with a cookie.
 */
static bool cachefiles_invalidate_cookie(struct fscache_cookie *cookie,
					 unsigned int flags)
{
	struct cachefiles_object *object = cookie->cache_priv;
	struct file *file, *old_file;
	struct dentry *old_dentry;
	u8 *map, *old_map;
	unsigned int map_size;

	_enter("{OBJ%x},[%llu]", object->debug_id, object->cookie->object_size);

	if ((flags & FSCACHE_INVAL_LIGHT) &&
	    test_bit(CACHEFILES_OBJECT_USING_TMPFILE, &object->flags)) {
		_leave(" = t [light]");
		return true;
	}

	if (object->dentry) {
		ASSERT(d_is_reg(object->dentry));

		file = cachefiles_create_tmpfile(object);
		if (IS_ERR(file))
			goto failed;

		map = cachefiles_new_content_map(object, &map_size);
		if (IS_ERR(map))
			goto failed_fput;

		/* Substitute the VFS target */
		_debug("sub");
		dget(file->f_path.dentry); /* Do outside of content_map_lock */
		spin_lock(&object->lock);
		write_lock_bh(&object->content_map_lock);

		if (!object->old) {
			/* Save the dentry carrying the path information */
			object->old = object->dentry;
			old_dentry = NULL;
		} else {
			old_dentry = object->dentry;
		}

		old_file = object->backing_file;
		old_map = object->content_map;
		object->backing_file = file;
		object->dentry = file->f_path.dentry;
		object->content_info = CACHEFILES_CONTENT_NO_DATA;
		object->content_map = map;
		object->content_map_size = map_size;
		object->content_map_changed = true;
		set_bit(CACHEFILES_OBJECT_USING_TMPFILE, &object->flags);
		set_bit(FSCACHE_COOKIE_OBJ_NEEDS_UPDATE, &object->cookie->flags);

		write_unlock_bh(&object->content_map_lock);
		spin_unlock(&object->lock);
		_debug("subbed");

		kfree(old_map);
		fput(old_file);
		dput(old_dentry);
	}

	_leave(" = t [tmpfile]");
	return true;

failed_fput:
	fput(file);
failed:
	_leave(" = f");
	return false;
}

static void cachefiles_relinquish_volume(struct fscache_volume *volume)
{
	if (volume->cache_priv) {
		dput(volume->cache_priv);
		volume->cache_priv = NULL;
	}
}

const struct fscache_cache_ops cachefiles_cache_ops = {
	.name			= "cachefiles",
	.relinquish_volume	= cachefiles_relinquish_volume,
	.lookup_cookie		= cachefiles_lookup_cookie,
	.relinquish_cookie	= cachefiles_relinquish_cookie,
	.resize_cookie		= cachefiles_resize_cookie,
	.invalidate_cookie	= cachefiles_invalidate_cookie,
	.begin_operation	= cachefiles_begin_operation,
	.prepare_to_write	= cachefiles_prepare_to_write,
};
