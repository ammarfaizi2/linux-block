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

	size = i_size + CACHEFILES_GRAN_SIZE - 1;
	granules = size / CACHEFILES_GRAN_SIZE;
	bits = granules + (64 - 1);
	bits &= ~(64 - 1);
	bytes = bits / 8;
	map_size = roundup_pow_of_two(bytes);
	_leave(" = %zx [i=%llx g=%zu b=%zu]", map_size, i_size, granules, bits);
	return map_size;
}

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
 * Shape the extent of a single-chunk data object.
 */
static unsigned int cachefiles_shape_single(struct fscache_object *obj,
					    struct fscache_extent *extent,
					    loff_t i_size, bool for_write)
{
	struct cachefiles_object *object =
		container_of(obj, struct cachefiles_object, fscache);
	unsigned int ret;
	pgoff_t eof;

	_enter("{%lx,%lx,%lx},%llx,%d",
	       extent->start, extent->block_end, extent->limit,
	       i_size, for_write);

	extent->dio_block_size = CACHEFILES_DIO_BLOCK_SIZE;

	if (!for_write &&
	    object->content_info == CACHEFILES_CONTENT_SINGLE) {
		ret = FSCACHE_READ_FROM_CACHE;
	} else {
		eof = (i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

		extent->start = 0;
		extent->block_end = eof;
		extent->limit = eof;
		ret = FSCACHE_WRITE_TO_CACHE;
	}

	_leave(" = %u", ret);
	return ret;
}

/*
 * Determine the size of a data extent in a cache object.
 *
 * In cachefiles, a data cache object is divided into granules of 256KiB, each
 * of which must be written as a whole unit when the cache is being loaded.
 * Data may be read out piecemeal.
 *
 * The extent is resized, but the result will always contain the starting page
 * from the extent.
 *
 * If the granule does not exist in the cachefile, the start may be brought
 * forward to align with the beginning of a granule boundary, and the end may be
 * moved either way to align also.  The extent will be cut off it it would cross
 * over the boundary between what's cached and what's not.
 *
 * If the starting granule does exist in the cachefile, the extent will be
 * shortened, if necessary, so that it doesn't cross over into a region that is
 * not present.
 *
 * If the granule does not exist and we cannot cache it for lack of space, the
 * requested extent is left unaltered.
 */
unsigned int cachefiles_shape_extent(struct fscache_object *obj,
				     struct fscache_extent *extent,
				     loff_t i_size, bool for_write)
{
	struct cachefiles_object *object =
		container_of(obj, struct cachefiles_object, fscache);
	unsigned int ret = 0;
	pgoff_t start, end, limit, eof, bend;
	size_t granule;

	if (object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK)
		return cachefiles_shape_single(obj, extent, i_size, for_write);

	start = extent->start;
	end   = extent->block_end;
	limit = extent->limit;
	_enter("{%lx,%lx,%lx},%llx,%d", start, end, limit, i_size, for_write);

	granule = start / CACHEFILES_GRAN_PAGES;

	if (granule / 8 >= object->content_map_size) {
		cachefiles_expand_content_map(object, i_size);
		if (granule / 8 >= object->content_map_size)
			return 0;
	}

	if (for_write) {
		/* Assume that the preparation to write involved preloading any
		 * bits of the cache that weren't to be written and filling any
		 * gaps that didn't end up being written.
		 */
		bend = end;
		ret = FSCACHE_WRITE_TO_CACHE;
	} else if (cachefiles_granule_is_present(object, granule)) {
		/* The start of the requested extent is present in the cache -
		 * restrict the returned extent to the maximum length of what's
		 * available.
		 */
		bend = round_up(start + 1, CACHEFILES_GRAN_PAGES);
		while (bend < end) {
			pgoff_t i = round_up(bend + 1, CACHEFILES_GRAN_PAGES);
			granule = i / CACHEFILES_GRAN_PAGES;
			if (!cachefiles_granule_is_present(object, granule))
				break;
			bend = i;
		}

		if (bend > end)
			bend = end;
		end = bend;
		ret = FSCACHE_READ_FROM_CACHE;
	} else {
		/* Otherwise expand the extent in both directions to cover what
		 * we want for caching purposes.
		 */
		start = round_down(start, CACHEFILES_GRAN_PAGES);
		end   = round_up(end, CACHEFILES_GRAN_PAGES);

		if (limit != ULONG_MAX) {
			limit = round_down(limit, CACHEFILES_GRAN_PAGES);
			if (end > limit) {
				end = limit;
				if (end <= start) {
					_leave(" = don't");
					return 0;
				}
			}
		}

		/* But trim to the end of the file and the starting page */
		eof = (i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
		if (eof <= extent->start)
			eof = extent->start + 1;
		if (end > eof)
			end = eof;

		if ((start << PAGE_SHIFT) >= object->fscache.cookie->zero_point) {
			/* The start of the requested extent is beyond the
			 * original EOF of the file on the server - therefore
			 * it's not going to be found on the server.
			 */
			bend = round_up(start + 1, CACHEFILES_GRAN_PAGES);
			end = bend;
			ret = FSCACHE_FILL_WITH_ZERO;
		} else {
			bend = start + CACHEFILES_GRAN_PAGES;
			if (bend > eof)
				bend = eof;
			ret = FSCACHE_WRITE_TO_CACHE;
		}

		/* TODO: Check we have space in the cache */
	}

	extent->start = start;
	extent->block_end = bend;
	extent->limit = end;
	extent->dio_block_size = CACHEFILES_DIO_BLOCK_SIZE;

	_leave(" = %u {%lx,%lx,%lx}", ret, start, bend, end);
	return ret;
}

/*
 * Allocate a new content map.
 */
u8 *cachefiles_new_content_map(struct cachefiles_object *object,
			       unsigned int *_size)
{
	size_t size;
	u8 *map = NULL;

	_enter("");

	if (!(object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK)) {
		/* Single-chunk object.  The presence or absence of the content
		 * map xattr is sufficient indication.
		 */
		*_size = 0;
		return NULL;
	}

	/* Granular object. */
	size = cachefiles_map_size(object->fscache.cookie->object_size);
	map = kzalloc(size, GFP_KERNEL);
	if (!map)
		return ERR_PTR(-ENOMEM);
	*_size = size;
	return map;
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

	if (req->inval_counter != object->fscache.inval_counter) {
		_debug("inval mark");
	} else if (object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK) {
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
void cachefiles_expand_content_map(struct cachefiles_object *object, loff_t i_size)
{
	size_t size;
	u8 *map, *zap;

	size = cachefiles_map_size(i_size);

	_enter("%llx,%lx,%x", i_size, size, object->content_map_size);

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
	size_t granule, tmp, bytes;

	if (object->fscache.cookie->advice & FSCACHE_ADV_SINGLE_CHUNK)
		return;

	write_lock_bh(&object->content_map_lock);

	if (object->content_info == CACHEFILES_CONTENT_MAP) {
		if (cookie->zero_point > new_size)
			cookie->zero_point = new_size;

		granule = new_size;
		granule += CACHEFILES_GRAN_SIZE - 1;
		granule /= CACHEFILES_GRAN_SIZE;

		tmp = granule;
		tmp = round_up(granule, 64);
		bytes = tmp / 8;
		if (bytes < object->content_map_size)
			memset(object->content_map + bytes, 0,
			       object->content_map_size - bytes);

		if (tmp > granule)
			for (tmp--; tmp > granule; tmp--)
				clear_bit_le(tmp, object->content_map);
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

	ret = vfs_setxattr(object->dentry, cachefiles_xattr_content_map,
			   map, size, 0);
	if (ret < 0) {
		cachefiles_io_error_obj(object, "Unable to set xattr");
		return;
	}

	_leave(" = %zd", ret);
}

/*
 * Display object information in proc.
 */
int cachefiles_display_object(struct seq_file *m, struct fscache_object *_object)
{
	struct cachefiles_object *object =
		container_of(_object, struct cachefiles_object, fscache);

	if (object->fscache.cookie->type == FSCACHE_COOKIE_TYPE_INDEX) {
		if (object->content_info != CACHEFILES_CONTENT_NO_DATA)
			seq_printf(m, " ???%u???", object->content_info);
	} else {
		switch (object->content_info) {
		case CACHEFILES_CONTENT_NO_DATA:
			seq_puts(m, " <n>");
			break;
		case CACHEFILES_CONTENT_SINGLE:
			seq_puts(m, " <s>");
			break;
		case CACHEFILES_CONTENT_ALL:
			seq_puts(m, " <a>");
			break;
		case CACHEFILES_CONTENT_MAP:
			read_lock_bh(&object->content_map_lock);
			if (object->content_map) {
				seq_printf(m, " %*phN",
					   object->content_map_size,
					   object->content_map);
			}
			read_unlock_bh(&object->content_map_lock);
			break;
		default:
			seq_printf(m, " <%u>", object->content_info);
			break;
		}
	}

	seq_putc(m, '\n');
	return 0;
}
