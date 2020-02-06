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

/*
 * Determine the map size for a granulated object.
 *
 * There's one bit per granule.  We size it in terms of 8-byte chunks, where a
 * 64-bit span * 256KiB bytes granules covers 16MiB of file space.  At that,
 * 512B will cover 1GiB.
 */
static size_t cachefiles_map_size(loff_t i_size)
{
	loff_t size;
	size_t granules, bits, bytes, map_size;

	if (i_size <= CACHEFILES_GRAN_SIZE * 64)
		return 8;

	size = min_t(loff_t, i_size + CACHEFILES_GRAN_SIZE - 1, CACHEFILES_SIZE_LIMIT);
	granules = size / CACHEFILES_GRAN_SIZE;
	bits = granules + (64 - 1);
	bits &= ~(64 - 1);
	bytes = bits / 8;
	map_size = roundup_pow_of_two(bytes);
	_leave(" = %zx [i=%llx g=%zu b=%zu]", map_size, i_size, granules, bits);
	return map_size;
}

/*
 * Mark the content map to indicate stored granule.
 */
void cachefiles_mark_content_map(struct cachefiles_object *object,
				 loff_t start, loff_t len)
{
	_enter("%llx", start);

	read_lock_bh(&object->content_map_lock);

	if (object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK) {
		if (start == 0) {
			object->content_info = CACHEFILES_CONTENT_SINGLE;
			set_bit(FSCACHE_OBJECT_NEEDS_UPDATE, &object->fscache.flags);
		}
	} else {
		pgoff_t granule;
		loff_t end = start + len;

		start = round_down(start, CACHEFILES_GRAN_SIZE);
		do {
			granule = start / CACHEFILES_GRAN_SIZE;
			if (granule / 8 >= object->content_map_size)
				break;

			set_bit_le(granule, object->content_map);
			object->content_map_changed = true;
			start += CACHEFILES_GRAN_SIZE;

		} while (start < end);

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
void cachefiles_expand_content_map(struct cachefiles_object *object, loff_t i_size)
{
	size_t size;
	u8 *map, *zap;

	size = cachefiles_map_size(i_size);

	_enter("%llx,%zx,%x", i_size, size, object->content_map_size);

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
	ssize_t granules_needed, bits_needed, bytes_needed;

	if (object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK)
		return;

	write_lock_bh(&object->content_map_lock);

	if (object->content_info == CACHEFILES_CONTENT_MAP) {
		if (cookie->zero_point > new_size)
			cookie->zero_point = new_size;

		granules_needed = new_size;
		granules_needed += CACHEFILES_GRAN_SIZE - 1;
		granules_needed /= CACHEFILES_GRAN_SIZE;
		bits_needed = round_up(granules_needed, 8);
		bytes_needed = bits_needed / 8;

		if (bytes_needed < object->content_map_size)
			memset(object->content_map + bytes_needed, 0,
			       object->content_map_size - bytes_needed);

		if (bits_needed > granules_needed) {
			size_t byte = (granules_needed - 1) / 8;
			unsigned int shift = granules_needed % 8;
			unsigned int mask = (1 << shift) - 1;
			object->content_map[byte] &= mask;
		}
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
	size_t size;
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
		size = cachefiles_map_size(object->fscache.cookie->object_size);
		map = kzalloc(size, GFP_KERNEL);
		if (!map)
			return false;
	}

	cachefiles_begin_secure(cache, &saved_cred);
	got = vfs_getxattr(&init_user_ns, object->dentry,
			   cachefiles_xattr_content_map, map, size);
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
		_leave(" = t [%zd/%zu %*phN]", got, size, (int)size, map);
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

	ret = vfs_setxattr(&init_user_ns, object->dentry,
			   cachefiles_xattr_content_map, map, size, 0);
	if (ret < 0) {
		cachefiles_io_error_obj(object, "Unable to set xattr e=%zd s=%zu",
					ret, size);
		return;
	}

	_leave(" = %zd", ret);
}
