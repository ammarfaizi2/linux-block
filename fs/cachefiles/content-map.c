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
#include <linux/netfs.h>
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

static bool cachefiles_granule_is_present(struct cachefiles_object *object,
					  long granule)
{
	bool res;

	if (granule / 8 >= object->content_map_size)
		return false;
	read_lock_bh(&object->content_map_lock);
	res = test_bit_le(granule, object->content_map);
	read_unlock_bh(&object->content_map_lock);
	return res;
}

static long cachefiles_find_next_granule(struct cachefiles_object *object,
					 long start_from, long *_limit)
{
	long result, limit;

	read_lock_bh(&object->content_map_lock);
	*_limit = limit = object->content_map_size * 8;
	result = find_next_bit_le(object->content_map, limit, start_from);
	read_unlock_bh(&object->content_map_lock);
	return result;
}

static long cachefiles_find_next_hole(struct cachefiles_object *object,
				      long start_from, long *_limit)
{
	long result, limit;

	read_lock_bh(&object->content_map_lock);
	*_limit = limit = object->content_map_size * 8;
	result = find_next_zero_bit_le(object->content_map, limit, start_from);
	read_unlock_bh(&object->content_map_lock);
	return result;
}

/*
 * Expand a readahead proposal from the VM to align with cache limits
 * and granularity.
 */
void cachefiles_expand_readahead(struct fscache_op_resources *opr,
				 loff_t *_start, size_t *_len, loff_t i_size)
{
	loff_t start = *_start, delta;
	size_t len = *_len;

	if (start >= CACHEFILES_SIZE_LIMIT)
		return;

	if (len > CACHEFILES_SIZE_LIMIT - start)
		len = *_len = CACHEFILES_SIZE_LIMIT - start;

	delta = start & (CACHEFILES_GRAN_SIZE - 1);
	if (start - delta < i_size) {
		start -= delta;
		len = round_up(len + delta, CACHEFILES_GRAN_SIZE);
		if (len > i_size - start) {
			_debug("overshot eof");
			len = i_size - start;
		}
	}

	*_start = start;
	*_len = len;
}

/*
 * Prepare a I/O subrequest of a read request.  We're asked to retrieve all the
 * remaining data in the read request, but we are allowed to shrink that and we
 * set flags to indicate where we want it read from.
 */
enum netfs_read_source cachefiles_prepare_read(struct netfs_read_subrequest *subreq,
					       loff_t i_size)
{
	struct cachefiles_object *object =
		container_of(subreq->rreq->cache_resources.object,
			     struct cachefiles_object, fscache);
	loff_t start = subreq->start, len = subreq->len, boundary;
	long granule, next, limit;

	_enter("%llx,%llx", start, len);

	if (start >= CACHEFILES_SIZE_LIMIT) {
		if (start >= i_size)
			goto zero_pages_nocache;
		goto on_server_nocache;
	}
	if (len > CACHEFILES_SIZE_LIMIT - start)
		len = CACHEFILES_SIZE_LIMIT - start;

	granule = start / CACHEFILES_GRAN_SIZE;
	if (granule / 8 >= object->content_map_size) {
		cachefiles_expand_content_map(object, i_size);
		if (granule / 8 >= object->content_map_size)
			goto maybe_on_server_nocache;
	}

	if (start >= i_size)
		goto zero_pages;

	if (cachefiles_granule_is_present(object, granule)) {
		/* The start of the request is present in the cache - restrict
		 * the length to what's available.
		 */
		if (start & (CACHEFILES_DIO_BLOCK_SIZE - 1)) {
			/* We should never see DIO-unaligned requests here. */
			WARN_ON_ONCE(1);
			len &= CACHEFILES_DIO_BLOCK_SIZE - 1;
			goto maybe_on_server;
		}

		next = cachefiles_find_next_hole(object, granule + 1, &limit);
		_debug("present %lx %lx", granule, limit);
		if (granule >= limit)
			goto maybe_on_server;
		boundary = next * CACHEFILES_GRAN_SIZE;
		if (len > boundary - start)
			len = boundary - start;
		goto in_cache;
	} else {
		/* The start of the request is not present in the cache -
		 * restrict the length to the size of the hole.
		 */
		next = cachefiles_find_next_granule(object, granule + 1, &limit);
		_debug("hole %lx %lx", granule, limit);
		if (granule >= limit)
			goto maybe_on_server;
		boundary = next * CACHEFILES_GRAN_SIZE;
		if (len > boundary - start)
			len = boundary - start;
		goto maybe_on_server;
	}

maybe_on_server:
	/* If the start of the request is beyond the original EOF of the file
	 * on the server then it's not going to be found on the server.
	 */
	if (start >= object->fscache.cookie->zero_point)
		goto zero_pages;
	goto on_server;
maybe_on_server_nocache:
	if (start >= object->fscache.cookie->zero_point)
		goto zero_pages_nocache;
	goto on_server_nocache;
on_server:
	__set_bit(NETFS_SREQ_WRITE_TO_CACHE, &subreq->flags);
on_server_nocache:
	subreq->len = len;
	_leave(" = down %llx", len);
	return NETFS_DOWNLOAD_FROM_SERVER;
zero_pages:
	__set_bit(NETFS_SREQ_WRITE_TO_CACHE, &subreq->flags);
zero_pages_nocache:
	subreq->len = len;
	_leave(" = zero %llx", len);
	return NETFS_FILL_WITH_ZEROES;
in_cache:
	subreq->len = len;
	_leave(" = read %llx", len);
	return NETFS_READ_FROM_CACHE;
}

/*
 * Prepare for a write to occur.
 */
int cachefiles_prepare_write(struct fscache_op_resources *opr,
			     loff_t *_start, size_t *_len, loff_t i_size)
{
	struct cachefiles_object *object =
		container_of(opr->object, struct cachefiles_object, fscache);
	loff_t start = *_start, map_limit;
	size_t len = *_len, down;
	long granule = start / CACHEFILES_GRAN_SIZE;

	if (start >= CACHEFILES_SIZE_LIMIT)
		return -ENOBUFS;

	if (granule / 8 >= object->content_map_size) {
		cachefiles_expand_content_map(object, i_size);
		if (granule / 8 >= object->content_map_size)
			return -ENOBUFS;
	}

	map_limit = object->content_map_size * 8 * CACHEFILES_GRAN_SIZE;
	if (start >= map_limit)
		return -ENOBUFS;
	if (len > map_limit - start)
		len = map_limit - start;

	/* Assume that the preparation to write involved preloading any
	 * bits of the cache that weren't to be written and filling any
	 * gaps that didn't end up being written.
	 */

	down = start - round_down(start, CACHEFILES_DIO_BLOCK_SIZE);
	*_start = start - down;
	*_len = round_up(down + len, CACHEFILES_DIO_BLOCK_SIZE);
	return 0;
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
void cachefiles_mark_content_map(struct cachefiles_object *object,
				 loff_t start, loff_t len,
				 unsigned int inval_counter)
{
	_enter("%llx", start);

	read_lock_bh(&object->content_map_lock);

	if (object->fscache.inval_counter != inval_counter) {
		_debug("inval mark");
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
		cachefiles_io_error_obj(object, "Unable to set xattr e=%zd s=%zu",
					ret, size);
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
