// SPDX-License-Identifier: GPL-2.0-or-later
/* Datafile content management
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/swap.h>
#include <linux/xattr.h>
#include "internal.h"

static const char cachefiles_xattr_content_map[] =
	XATTR_USER_PREFIX "CacheFiles.content";

static bool cachefiles_granule_is_present(struct cachefiles_object *object,
					  size_t granule)
{
	bool res;

	if (granule / 8 >= object->content_map_size)
		return false;
	read_lock_bh(&object->content_map_lock);
	res = test_bit_le(granule, object->content_map);
	read_unlock_bh(&object->content_map_lock);
	return res;
}

/*
 * Mark the content map to indicate stored granule.
 */
void cachefiles_mark_content_map(struct fscache_io_request *req)
{
	struct cachefiles_object *object =
		container_of(req->object, struct cachefiles_object, fscache);
	loff_t pos = req->pos;

	_enter("%llx", pos);

	read_lock_bh(&object->content_map_lock);

	if (object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK) {
		if (pos == 0) {
			object->content_info = CACHEFILES_CONTENT_SINGLE;
			set_bit(FSCACHE_OBJECT_NEEDS_UPDATE, &object->fscache.flags);
		}
	} else {
		pgoff_t granule;
		loff_t end = pos + req->len;

		do {
			granule = pos / CACHEFILES_GRAN_SIZE;
			if (granule / 8 >= object->content_map_size)
				break;

			set_bit_le(granule, object->content_map);
			object->content_map_changed = true;
			pos += CACHEFILES_GRAN_SIZE;

		} while (pos < end);

		if (object->content_info != CACHEFILES_CONTENT_MAP) {
			object->content_info = CACHEFILES_CONTENT_MAP;
			set_bit(FSCACHE_OBJECT_NEEDS_UPDATE, &object->fscache.flags);
		}
	}

	read_unlock_bh(&object->content_map_lock);
}

/*
 * Expand the content map to a larger file size.
 */
void cachefiles_expand_content_map(struct cachefiles_object *object, loff_t size)
{
	u8 *map, *zap;

	/* Determine the size.  There's one bit per granule.  We size it in
	 * terms of 8-byte chunks, where a 64-bit span * 256KiB bytes granules
	 * covers 16MiB of file space.  At that, 512B will cover 1GiB.
	 */
	if (size > 0) {
		size += CACHEFILES_GRAN_SIZE - 1;
		size /= CACHEFILES_GRAN_SIZE;
		size += 8 - 1;
		size /= 8;
		size = roundup_pow_of_two(size);
	} else {
		size = 8;
	}

	if (size <= object->content_map_size)
		return;

	map = kzalloc(size, GFP_KERNEL);
	if (!map)
		return;

	write_lock_bh(&object->content_map_lock);
	if (size > object->content_map_size) {
		zap = object->content_map;
		memcpy(map, zap, object->content_map_size);
		object->content_map = map;
		object->content_map_size = size;
	} else {
		zap = map;
	}
	write_unlock_bh(&object->content_map_lock);

	kfree(zap);
}

/*
 * Adjust the content map when we shorten a backing object.
 *
 * We need to unmark any granules that are going to be discarded.
 */
void cachefiles_shorten_content_map(struct cachefiles_object *object,
				    loff_t new_size)
{
	struct fscache_cookie *cookie = object->fscache.cookie;
	loff_t granule, o_granule;

	if (object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK)
		return;

	write_lock_bh(&object->content_map_lock);

	if (object->content_info == CACHEFILES_CONTENT_MAP) {
		if (cookie->zero_point > new_size)
			cookie->zero_point = new_size;

		granule = new_size;
		granule += CACHEFILES_GRAN_SIZE - 1;
		granule /= CACHEFILES_GRAN_SIZE;

		o_granule = cookie->object_size;
		o_granule += CACHEFILES_GRAN_SIZE - 1;
		o_granule /= CACHEFILES_GRAN_SIZE;

		for (; o_granule > granule; o_granule--)
			clear_bit_le(o_granule, object->content_map);
	}

	write_unlock_bh(&object->content_map_lock);
}

/*
 * Load the content map.
 */
bool cachefiles_load_content_map(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache = container_of(object->fscache.cache,
						      struct cachefiles_cache, cache);
	const struct cred *saved_cred;
	ssize_t got;
	loff_t size;
	u8 *map = NULL;

	_enter("c=%08x,%llx",
	       object->fscache.cookie->debug_id,
	       object->fscache.cookie->object_size);

	object->content_info = CACHEFILES_CONTENT_NO_DATA;
	if (object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK) {
		/* Single-chunk object.  The presence or absence of the content
		 * map xattr is sufficient indication.
		 */
		size = 0;
	} else {
		/* Granulated object.  There's one bit per granule.  We size it
		 * in terms of 8-byte chunks, where a 64-bit span * 256KiB
		 * bytes granules covers 16MiB of file space.  At that, 512B
		 * will cover 1GiB.
		 */
		size = object->fscache.cookie->object_size;
		if (size > 0) {
			size += CACHEFILES_GRAN_SIZE - 1;
			size /= CACHEFILES_GRAN_SIZE;
			size += 8 - 1;
			size /= 8;
			if (size < 8)
				size = 8;
			size = roundup_pow_of_two(size);
		} else {
			size = 8;
		}

		map = kzalloc(size, GFP_KERNEL);
		if (!map)
			return false;
	}

	cachefiles_begin_secure(cache, &saved_cred);
	got = vfs_getxattr(object->dentry, cachefiles_xattr_content_map,
			   map, size);
	cachefiles_end_secure(cache, saved_cred);
	if (got < 0 && got != -ENODATA) {
		kfree(map);
		_leave(" = f [%zd]", got);
		return false;
	}

	if (size == 0) {
		if (got != -ENODATA)
			object->content_info = CACHEFILES_CONTENT_SINGLE;
		_leave(" = t [%zd]", got);
	} else {
		object->content_map = map;
		object->content_map_size = size;
		object->content_info = CACHEFILES_CONTENT_MAP;
		_leave(" = t [%zd/%llu %*phN]", got, size, (int)size, map);
	}

	return true;
}

/*
 * Save the content map.
 */
void cachefiles_save_content_map(struct cachefiles_object *object)
{
	ssize_t ret;
	size_t size;
	u8 *map;

	_enter("c=%08x", object->fscache.cookie->debug_id);

	if (object->content_info != CACHEFILES_CONTENT_MAP)
		return;

	size = object->content_map_size;
	map = object->content_map;

	/* Don't save trailing zeros, but do save at least one byte */
	for (; size > 0; size--)
		if (map[size - 1])
			break;

	ret = vfs_setxattr(object->dentry, cachefiles_xattr_content_map,
			   map, size, 0);
	if (ret < 0) {
		cachefiles_io_error_obj(object, "Unable to set xattr");
		return;
	}

	_leave(" = %zd", ret);
}
