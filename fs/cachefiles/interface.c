// SPDX-License-Identifier: GPL-2.0-or-later
/* FS-Cache interface to CacheFiles
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include "internal.h"

static int cachefiles_attr_changed(struct cachefiles_object *object);

/*
 * allocate an object record for a cookie lookup and prepare the lookup data
 */
static struct cachefiles_object *cachefiles_alloc_object(
	struct fscache_cache *_cache,
	struct fscache_cookie *cookie)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;

	cache = container_of(_cache, struct cachefiles_cache, cache);

	_enter("{%s},%x,", cache->cache.identifier, cookie->debug_id);

	/* create a new object record and a temporary leaf image */
	object = kmem_cache_alloc(cachefiles_object_jar, cachefiles_gfp);
	if (!object)
		goto nomem_object;

	atomic_set(&object->usage, 1);

	fscache_object_init(object, cookie, &cache->cache);

	object->type = cookie->type;

	/* turn the raw key into something that can work with as a filename */
	if (!cachefiles_cook_key(object))
		goto nomem_key;

	_leave(" = %x [%s]", object->debug_id, object->d_name);
	return object;

nomem_key:
	kmem_cache_free(cachefiles_object_jar, object);
	fscache_object_destroyed(&cache->cache);
nomem_object:
	_leave(" = -ENOMEM");
	return ERR_PTR(-ENOMEM);
}

/*
 * attempt to look up the nominated node in this cache
 * - return -ETIMEDOUT to be scheduled again
 */
static int cachefiles_lookup_object(struct cachefiles_object *object)
{
	struct cachefiles_object *parent;
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	int ret;

	_enter("{OBJ%x}", object->debug_id);

	cache = container_of(object->cache, struct cachefiles_cache, cache);
	parent = object->parent;

	ASSERT(object->d_name);

	/* look up the key, creating any missing bits */
	cachefiles_begin_secure(cache, &saved_cred);
	ret = cachefiles_walk_to_object(parent, object);
	cachefiles_end_secure(cache, saved_cred);

	/* polish off by setting the attributes of non-index files */
	if (ret == 0 &&
	    object->cookie->type != FSCACHE_COOKIE_TYPE_INDEX)
		cachefiles_attr_changed(object);

	if (ret < 0 && ret != -ETIMEDOUT) {
		if (ret != -ENOBUFS)
			pr_warn("Lookup failed error %d\n", ret);
		fscache_object_lookup_error(object);
	}

	_leave(" [%d]", ret);
	return ret;
}

/*
 * indication of lookup completion
 */
static void cachefiles_lookup_complete(struct cachefiles_object *object)
{
	_enter("{OBJ%x}", object->debug_id);
}

/*
 * increment the usage count on an inode object (may fail if unmounting)
 */
static
struct cachefiles_object *cachefiles_grab_object(struct cachefiles_object *object,
						 enum fscache_obj_ref_trace why)
{
	int u;

	_enter("{OBJ%x,%d}", object->debug_id, atomic_read(&object->usage));

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->usage) & 0xffff0000) != 0x6b6b0000);
#endif

	u = atomic_inc_return(&object->usage);
	trace_cachefiles_ref(object, object->cookie,
			     (enum cachefiles_obj_ref_trace)why, u);
	return object;
}

/*
 * update the auxiliary data for an object object on disk
 */
static void cachefiles_update_object(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;

	_enter("{OBJ%x}", object->debug_id);

	cache = container_of(object->cache, struct cachefiles_cache, cache);

	cachefiles_begin_secure(cache, &saved_cred);
	cachefiles_set_object_xattr(object, XATTR_REPLACE);
	cachefiles_end_secure(cache, saved_cred);
	_leave("");
}

/*
 * discard the resources pinned by an object and effect retirement if
 * requested
 */
static void cachefiles_drop_object(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;

	ASSERT(object);

	_enter("{OBJ%x,%d}", object->debug_id, atomic_read(&object->usage));

	cache = container_of(object->cache, struct cachefiles_cache, cache);

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->usage) & 0xffff0000) != 0x6b6b0000);
#endif

	/* We need to tidy the object up if we did in fact manage to open it.
	 * It's possible for us to get here before the object is fully
	 * initialised if the parent goes away or the object gets retired
	 * before we set it up.
	 */
	if (object->file) {
		/* delete retired objects */
		if (test_bit(FSCACHE_OBJECT_RETIRED, &object->flags) &&
		    object != cache->cache.fsdef
		    ) {
			_debug("- retire object OBJ%x", object->debug_id);
			cachefiles_begin_secure(cache, &saved_cred);
			cachefiles_delete_object(cache, object);
			cachefiles_end_secure(cache, saved_cred);
		}

		/* close the filesystem stuff attached to the object */
		cachefiles_unmark_inode_in_use(object);
		fput(object->file);
		object->file = NULL;
	}

	_leave("");
}

/*
 * dispose of a reference to an object
 */
void cachefiles_put_object(struct cachefiles_object *object,
			   enum fscache_obj_ref_trace why)
{
	struct fscache_cache *cache;
	int u;

	ASSERT(object);

	_enter("{OBJ%x,%d}",
	       object->debug_id, atomic_read(&object->usage));

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->usage) & 0xffff0000) != 0x6b6b0000);
#endif

	ASSERTIFCMP(object->parent,
		    object->parent->n_children, >, 0);

	u = atomic_dec_return(&object->usage);
	trace_cachefiles_ref(object, object->cookie,
			     (enum cachefiles_obj_ref_trace)why, u);
	ASSERTCMP(u, !=, -1);
	if (u == 0) {
		_debug("- kill object OBJ%x", object->debug_id);

		ASSERTCMP(object->parent, ==, NULL);
		ASSERTCMP(object->file, ==, NULL);
		ASSERTCMP(object->n_ops, ==, 0);
		ASSERTCMP(object->n_children, ==, 0);

		kfree(object->d_name);

		cache = object->cache;
		fscache_object_destroy(object);
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
	struct file *file = object->file;
	uint64_t ni_size;
	loff_t oi_size;
	int ret;

	ni_size = object->cookie->object_size;

	_enter("{OBJ%x},[%llu]",
	       object->debug_id, (unsigned long long) ni_size);

	if (!file)
		return -ENOBUFS;

	cache = container_of(object->cache, struct cachefiles_cache, cache);

	if (ni_size == object->i_size)
		return 0;

	ASSERT(d_is_reg(file->f_path.dentry));

	oi_size = i_size_read(file_inode(file));
	if (oi_size == ni_size)
		return 0;

	cachefiles_begin_secure(cache, &saved_cred);
	inode_lock(file_inode(file));

	/* if there's an extension to a partial page at the end of the backing
	 * file, we need to discard the partial page so that we pick up new
	 * data after it */
	if (oi_size & ~PAGE_MASK && ni_size > oi_size) {
		_debug("discard tail %llx", oi_size);
		newattrs.ia_valid = ATTR_SIZE;
		newattrs.ia_size = oi_size & PAGE_MASK;
		ret = notify_change(&init_user_ns, file->f_path.dentry,
				    &newattrs, NULL);
		if (ret < 0)
			goto truncate_failed;
	}

	newattrs.ia_valid = ATTR_SIZE;
	newattrs.ia_size = ni_size;
	ret = notify_change(&init_user_ns, file->f_path.dentry, &newattrs, NULL);

truncate_failed:
	inode_unlock(file_inode(file));
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
static void cachefiles_invalidate_object(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache;
	const struct cred *saved_cred;
	struct file *file = object->file;
	uint64_t ni_size;
	int ret;

	cache = container_of(object->cache, struct cachefiles_cache, cache);

	ni_size = object->cookie->object_size;

	_enter("{OBJ%x},[%llu]",
	       object->debug_id, (unsigned long long)ni_size);

	if (file) {
		ASSERT(d_is_reg(file->f_path.dentry));

		cachefiles_begin_secure(cache, &saved_cred);
		ret = vfs_truncate(&file->f_path, 0);
		if (ret == 0)
			ret = vfs_truncate(&file->f_path, ni_size);
		cachefiles_end_secure(cache, saved_cred);

		if (ret != 0) {
			if (ret == -EIO)
				cachefiles_io_error_obj(object,
							"Invalidate failed");
		}
	}

	_leave("");
}

const struct fscache_cache_ops cachefiles_cache_ops = {
	.name			= "cachefiles",
	.alloc_object		= cachefiles_alloc_object,
	.lookup_object		= cachefiles_lookup_object,
	.lookup_complete	= cachefiles_lookup_complete,
	.grab_object		= cachefiles_grab_object,
	.update_object		= cachefiles_update_object,
	.invalidate_object	= cachefiles_invalidate_object,
	.drop_object		= cachefiles_drop_object,
	.put_object		= cachefiles_put_object,
	.sync_cache		= cachefiles_sync_cache,
	.begin_operation	= cachefiles_begin_operation,
};
