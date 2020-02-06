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
 * update the auxiliary data for an object object on disk
 */
static void cachefiles_update_object(struct fscache_object *_object)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	struct inode *inode;
	loff_t object_size, i_size;
	int ret;

	_enter("{OBJ%x}", _object->debug_id);

	object = container_of(_object, struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache, struct cachefiles_cache,
			     cache);

	cachefiles_begin_secure(cache, &saved_cred);

	object_size = object->fscache.cookie->object_size;
	inode = d_inode(object->dentry);
	i_size = i_size_read(inode);
	if (i_size > object_size) {
		struct path path = {
			.mnt	= cache->mnt,
			.dentry	= object->dentry
		};
		_debug("trunc %llx -> %llx", i_size, object_size);
		ret = vfs_truncate(&path, object_size);
		if (ret < 0) {
			cachefiles_io_error_obj(object, "Trunc-to-size failed");
			cachefiles_remove_object_xattr(cache, object->dentry);
			goto out;
		}

		object_size = round_up(object_size, CACHEFILES_DIO_BLOCK_SIZE);
		i_size = i_size_read(inode);
		_debug("trunc %llx -> %llx", i_size, object_size);
		if (i_size < object_size) {
			ret = vfs_truncate(&path, object_size);
			if (ret < 0) {
				cachefiles_io_error_obj(object, "Trunc-to-dio-size failed");
				cachefiles_remove_object_xattr(cache, object->dentry);
				goto out;
			}
		}
	}

	cachefiles_set_object_xattr(object, XATTR_REPLACE);

out:
	cachefiles_end_secure(cache, saved_cred);
	_leave("");
}

/*
 * Commit changes to the object as we drop it.
 */
static void cachefiles_commit_object(struct cachefiles_object *object,
				     struct cachefiles_cache *cache)
{
	if (object->content_map_changed)
		cachefiles_save_content_map(object);
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
 * Invalidate an object
 */
static bool cachefiles_invalidate_object(struct fscache_object *_object)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	struct path path;
	uint64_t ni_size;
	int ret;

	object = container_of(_object, struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	ni_size = object->fscache.cookie->object_size;
	ni_size = round_up(ni_size, CACHEFILES_DIO_BLOCK_SIZE);

	_enter("{OBJ%x},[%llu]",
	       object->fscache.debug_id, (unsigned long long)ni_size);

	if (object->dentry) {
		ASSERT(d_is_reg(object->dentry));

		path.dentry = object->dentry;
		path.mnt = cache->mnt;

		cachefiles_begin_secure(cache, &saved_cred);
		ret = vfs_truncate(&path, 0);
		if (ret == 0)
			ret = vfs_truncate(&path, ni_size);
		cachefiles_end_secure(cache, saved_cred);

		if (ret != 0) {
			if (ret == -EIO)
				cachefiles_io_error_obj(object,
							"Invalidate failed");
			return false;
		}
	}

	return true;
}

static unsigned int cachefiles_get_object_usage(const struct fscache_object *_object)
{
	struct cachefiles_object *object;

	object = container_of(_object, struct cachefiles_object, fscache);
	return atomic_read(&object->usage);
}

const struct fscache_cache_ops cachefiles_cache_ops = {
	.name			= "cachefiles",
	.alloc_object		= cachefiles_alloc_object,
	.prepare_lookup_data	= cachefiles_prepare_lookup_data,
	.lookup_object		= cachefiles_lookup_object,
	.free_lookup_data	= cachefiles_free_lookup_data,
	.grab_object		= cachefiles_grab_object,
	.update_object		= cachefiles_update_object,
	.invalidate_object	= cachefiles_invalidate_object,
	.drop_object		= cachefiles_drop_object,
	.put_object		= cachefiles_put_object,
	.get_object_usage	= cachefiles_get_object_usage,
	.sync_cache		= cachefiles_sync_cache,
	.begin_operation	= cachefiles_begin_operation,
};
