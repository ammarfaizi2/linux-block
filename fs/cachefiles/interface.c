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
#include "internal.h"

static int cachefiles_attr_changed(struct cachefiles_object *object);

/*
 * Allocate an object record for a cookie lookup and prepare the lookup data.
 * Eats the caller's ref on parent.
 */
static
struct fscache_object *cachefiles_alloc_object(struct fscache_cookie *cookie,
					       struct fscache_cache *_cache,
					       struct fscache_object *parent)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;

	cache = container_of(_cache, struct cachefiles_cache, cache);

	_enter("{%s},%x,", cache->cache.identifier, cookie->debug_id);

	object = kmem_cache_zalloc(cachefiles_object_jar, cachefiles_gfp);
	if (!object) {
		cachefiles_put_object(parent, fscache_obj_put_alloc_fail);
		return NULL;
	}

	rwlock_init(&object->content_map_lock);
	fscache_object_init(&object->fscache, cookie, &cache->cache);
	object->fscache.parent = parent;
	object->fscache.stage = FSCACHE_OBJECT_STAGE_LOOKING_UP;
	atomic_set(&object->usage, 1);

	object->type = cookie->type;
	trace_cachefiles_ref(object, cookie,
			     (enum cachefiles_obj_ref_trace)fscache_obj_new, 1);
	return &object->fscache;
}

/*
 * Prepare data for use in lookup.  This involves cooking the binary key into
 * something that can be used as a filename.
 */
static void *cachefiles_prepare_lookup_data(struct fscache_object *object)
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

	/* turn the raw key into something that can work with as a filename */
	key = cachefiles_cook_key(buffer, keylen + 2, cookie->type);
	kfree(buffer);
	if (!key)
		goto nomem;

	_leave(" = %s", key);
	return key;

nomem:
	return ERR_PTR(-ENOMEM);
}

/*
 * Attempt to look up the nominated node in this cache
 */
static bool cachefiles_lookup_object(struct fscache_object *_object,
				     void *lookup_data)
{
	struct cachefiles_object *parent, *object;
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	char *lookup_key = lookup_data;
	bool success;

	_enter("{OBJ%x}", _object->debug_id);

	cache = container_of(_object->cache, struct cachefiles_cache, cache);
	parent = container_of(_object->parent,
			      struct cachefiles_object, fscache);
	object = container_of(_object, struct cachefiles_object, fscache);

	ASSERTCMP(lookup_key, !=, NULL);

	/* look up the key, creating any missing bits */
	cachefiles_begin_secure(cache, &saved_cred);
	success = cachefiles_walk_to_object(parent, object, lookup_key);
	cachefiles_end_secure(cache, saved_cred);

	/* polish off by setting the attributes of non-index files */
	if (success &&
	    object->fscache.cookie->type != FSCACHE_COOKIE_TYPE_INDEX)
		cachefiles_attr_changed(object);

	_leave(" [%d]", success);
	return success;
}

static void cachefiles_free_lookup_data(struct fscache_object *object, void *lookup_data)
{
	kfree(lookup_data);
}

/*
 * increment the usage count on an inode object (may fail if unmounting)
 */
struct fscache_object *cachefiles_grab_object(struct fscache_object *_object,
					      enum fscache_obj_ref_trace why)
{
	struct cachefiles_object *object =
		container_of(_object, struct cachefiles_object, fscache);
	int u;

	_enter("{OBJ%x,%d}", _object->debug_id, atomic_read(&object->usage));

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->usage) & 0xffff0000) != 0x6b6b0000);
#endif

	u = atomic_inc_return(&object->usage);
	trace_cachefiles_ref(object, _object->cookie,
			     (enum cachefiles_obj_ref_trace)why, u);
	return &object->fscache;
}

/*
 * Shorten the backing object to discard any dirty data and free up
 * any unused granules.
 */
static bool cachefiles_shorten_object(struct cachefiles_object *object, loff_t new_size)
{
	struct cachefiles_cache *cache;
	struct inode *inode;
	struct path path;
	loff_t i_size;
	int ret;

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);
	path.mnt = cache->mnt;
	path.dentry = object->dentry;

	inode = d_inode(object->dentry);
	trace_cachefiles_trunc(object, inode, i_size_read(inode), new_size);
	ret = vfs_truncate(&path, new_size);
	if (ret < 0) {
		cachefiles_io_error_obj(object, "Trunc-to-size failed %d", ret);
		cachefiles_remove_object_xattr(cache, object->dentry);
		return false;
	}

	new_size = round_up(new_size, CACHEFILES_DIO_BLOCK_SIZE);
	i_size = i_size_read(inode);
	if (i_size < new_size) {
		trace_cachefiles_trunc(object, inode, i_size, new_size);
		ret = vfs_truncate(&path, new_size);
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
static void cachefiles_resize_object(struct fscache_object *_object, loff_t new_size)
{
	struct cachefiles_object *object =
		container_of(_object, struct cachefiles_object, fscache);
	struct cachefiles_cache *cache =
		container_of(object->fscache.cache, struct cachefiles_cache, cache);
	const struct cred *saved_cred;
	loff_t old_size = object->fscache.cookie->object_size;

	_enter("%llu->%llu", old_size, new_size);

	if (new_size < old_size) {
		cachefiles_begin_secure(cache, &saved_cred);
		cachefiles_shorten_content_map(object, new_size);
		cachefiles_shorten_object(object, new_size);
		cachefiles_end_secure(cache, saved_cred);
		object->fscache.cookie->object_size = new_size;
		return;
	}

	/* The file is being expanded.  We don't need to do anything
	 * particularly.  cookie->initial_size doesn't change and so the point
	 * at which we have to download before doesn't change.
	 */
	object->fscache.cookie->object_size = new_size;
}

/*
 * Trim excess stored data off of an object.
 */
static bool cachefiles_trim_object(struct cachefiles_object *object)
{
	loff_t object_size;

	_enter("{OBJ%x}", object->fscache.debug_id);

	object_size = object->fscache.cookie->object_size;
	if (i_size_read(d_inode(object->dentry)) <= object_size)
		return true;

	return cachefiles_shorten_object(object, object_size);
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
	if (test_and_clear_bit(FSCACHE_OBJECT_LOCAL_WRITE, &object->fscache.flags))
		update = true;
	if (test_and_clear_bit(FSCACHE_OBJECT_NEEDS_UPDATE, &object->fscache.flags))
		update = true;
	if (update) {
		if (cachefiles_trim_object(object))
			cachefiles_set_object_xattr(object);
	}

	if (test_bit(CACHEFILES_OBJECT_USING_TMPFILE, &object->flags))
		return cachefiles_commit_tmpfile(cache, object);
	return true;
}

/*
 * Finalise and object and close the VFS structs that we have.
 */
static void cachefiles_clean_up_object(struct cachefiles_object *object,
				       struct cachefiles_cache *cache,
				       bool invalidate)
{
	if (invalidate && &object->fscache != cache->cache.fsdef) {
		_debug("- inval object OBJ%x", object->fscache.debug_id);
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

	cachefiles_unmark_inode_in_use(object, object->dentry);
	dput(object->dentry);
	object->dentry = NULL;
}

/*
 * discard the resources pinned by an object and effect retirement if
 * requested
 */
static void cachefiles_drop_object(struct fscache_object *_object,
				   bool invalidate)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;

	ASSERT(_object);

	object = container_of(_object, struct cachefiles_object, fscache);

	_enter("{OBJ%x,%d}",
	       object->fscache.debug_id, atomic_read(&object->usage));

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->usage) & 0xffff0000) != 0x6b6b0000);
#endif

	/* We need to tidy the object up if we did in fact manage to open it.
	 * It's possible for us to get here before the object is fully
	 * initialised if the parent goes away or the object gets retired
	 * before we set it up.
	 */
	if (object->dentry) {
		cachefiles_begin_secure(cache, &saved_cred);
		cachefiles_clean_up_object(object, cache, invalidate);
		cachefiles_end_secure(cache, saved_cred);
	}

	_leave("");
}

/*
 * dispose of a reference to an object
 */
void cachefiles_put_object(struct fscache_object *_object,
			   enum fscache_obj_ref_trace why)
{
	struct cachefiles_object *object;
	struct fscache_cache *cache;
	int u;

	ASSERT(_object);

	object = container_of(_object, struct cachefiles_object, fscache);

	_enter("{OBJ%x,%d}",
	       object->fscache.debug_id, atomic_read(&object->usage));

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->usage) & 0xffff0000) != 0x6b6b0000);
#endif

	u = atomic_dec_return(&object->usage);
	trace_cachefiles_ref(object, _object->cookie,
			     (enum cachefiles_obj_ref_trace)why, u);
	ASSERTCMP(u, !=, -1);
	if (u == 0) {
		_debug("- kill object OBJ%x", object->fscache.debug_id);

		ASSERTCMP(object->old, ==, NULL);
		ASSERTCMP(object->dentry, ==, NULL);
		ASSERTCMP(object->fscache.n_children, ==, 0);

		kfree(object->content_map);

		cache = object->fscache.cache;
		fscache_object_destroy(&object->fscache);
		kmem_cache_free(cachefiles_object_jar, object);
		fscache_object_destroyed(cache);
	}

	_leave("");
}

/*
 * sync a cache
 */
static void cachefiles_sync_cache(struct fscache_cache *_cache)
{
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	int ret;

	_enter("%s", _cache->tag->name);

	cache = container_of(_cache, struct cachefiles_cache, cache);

	/* make sure all pages pinned by operations on behalf of the netfs are
	 * written to disc */
	cachefiles_begin_secure(cache, &saved_cred);
	down_read(&cache->mnt->mnt_sb->s_umount);
	ret = sync_filesystem(cache->mnt->mnt_sb);
	up_read(&cache->mnt->mnt_sb->s_umount);
	cachefiles_end_secure(cache, saved_cred);

	if (ret == -EIO)
		cachefiles_io_error(cache,
				    "Attempt to sync backing fs superblock"
				    " returned error %d",
				    ret);
}

/*
 * notification the attributes on an object have changed
 * - called with reads/writes excluded by FS-Cache
 */
static int cachefiles_attr_changed(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	struct iattr newattrs;
	uint64_t ni_size;
	loff_t oi_size;
	int ret;

	ni_size = object->fscache.cookie->object_size;
	ni_size = round_up(ni_size, CACHEFILES_DIO_BLOCK_SIZE);

	_enter("{OBJ%x},[%llu]",
	       object->fscache.debug_id, (unsigned long long) ni_size);

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

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
		ret = notify_change(object->dentry, &newattrs, NULL);
		if (ret < 0)
			goto truncate_failed;
	}

	newattrs.ia_valid = ATTR_SIZE;
	newattrs.ia_size = ni_size;
	ret = notify_change(object->dentry, &newattrs, NULL);

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
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	struct file *file;
	struct path path;
	uint64_t ni_size;
	long ret;

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	ni_size = object->fscache.cookie->object_size;
	ni_size = round_up(ni_size, CACHEFILES_DIO_BLOCK_SIZE);

	cachefiles_begin_secure(cache, &saved_cred);

	path.mnt = cache->mnt;
	path.dentry = vfs_tmpfile(cache->graveyard, S_IFREG, O_RDWR);
	if (IS_ERR(path.dentry)) {
		if (PTR_ERR(path.dentry) == -EIO)
			cachefiles_io_error_obj(object, "Failed to create tmpfile");
		file = ERR_CAST(path.dentry);
		goto out;
	}

	trace_cachefiles_tmpfile(object, d_inode(path.dentry));

	if (ni_size > 0) {
		trace_cachefiles_trunc(object, d_inode(path.dentry), 0, ni_size);
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
 * Invalidate an object
 */
static bool cachefiles_invalidate_object(struct fscache_object *_object,
					 unsigned int flags)
{
	struct cachefiles_object *object;
	struct file *file, *old_file;
	struct dentry *old_dentry;
	u8 *map, *old_map;
	unsigned int map_size;

	object = container_of(_object, struct cachefiles_object, fscache);

	_enter("{OBJ%x},[%llu]",
	       object->fscache.debug_id, _object->cookie->object_size);

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
		spin_lock(&object->fscache.lock);
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
		set_bit(FSCACHE_OBJECT_NEEDS_UPDATE, &object->fscache.flags);

		write_unlock_bh(&object->content_map_lock);
		spin_unlock(&object->fscache.lock);
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

static unsigned int cachefiles_get_object_usage(const struct fscache_object *_object)
{
	struct cachefiles_object *object;

	object = container_of(_object, struct cachefiles_object, fscache);
	return atomic_read(&object->usage);
}

static const struct fscache_op_ops cachefiles_io_ops = {
	.wait_for_operation	= __fscache_wait_for_operation,
	.end_operation		= __fscache_end_operation,
	.read			= cachefiles_read,
	.write			= cachefiles_write,
	.expand_readahead	= cachefiles_expand_readahead,
	.prepare_read		= cachefiles_prepare_read,
	.prepare_write		= cachefiles_prepare_write,
};

static void cachefiles_begin_operation(struct fscache_op_resources *opr)
{
	opr->ops = &cachefiles_io_ops;
}

const struct fscache_cache_ops cachefiles_cache_ops = {
	.name			= "cachefiles",
	.alloc_object		= cachefiles_alloc_object,
	.prepare_lookup_data	= cachefiles_prepare_lookup_data,
	.lookup_object		= cachefiles_lookup_object,
	.free_lookup_data	= cachefiles_free_lookup_data,
	.grab_object		= cachefiles_grab_object,
	.resize_object		= cachefiles_resize_object,
	.invalidate_object	= cachefiles_invalidate_object,
	.drop_object		= cachefiles_drop_object,
	.put_object		= cachefiles_put_object,
	.get_object_usage	= cachefiles_get_object_usage,
	.sync_cache		= cachefiles_sync_cache,
	.begin_operation	= cachefiles_begin_operation,
	.prepare_to_write	= cachefiles_prepare_to_write,
	.display_object		= cachefiles_display_object,
};
