// SPDX-License-Identifier: GPL-2.0-or-later
/* Miscellaneous object routines.
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * See Documentation/filesystems/caching/netfs-api.txt for more information on
 * the netfs API.
 */

#define FSCACHE_DEBUG_LEVEL OBJECT
#include <linux/module.h>
#include <linux/slab.h>
#include "internal.h"

static atomic_t fscache_object_debug_id;

/**
 * fscache_object_init - Initialise a cache object description
 * @object: Object description
 * @cookie: Cookie object will be attached to
 * @cache: Cache in which backing object will be found
 *
 * Initialise a cache object description to its basic values.
 *
 * See Documentation/filesystems/caching/backend-api.txt for a complete
 * description.
 */
void fscache_object_init(struct fscache_object *object,
			 struct fscache_cookie *cookie,
			 struct fscache_cache *cache)
{
	atomic_inc(&cache->object_count);

	spin_lock_init(&object->lock);
	INIT_LIST_HEAD(&object->cache_link);
	INIT_HLIST_NODE(&object->cookie_link);
	object->n_children = 0;
	object->cache = cache;
	object->cookie = fscache_cookie_get(cookie, fscache_cookie_get_attach_object);
	object->parent = NULL;
#ifdef CONFIG_FSCACHE_OBJECT_LIST
	RB_CLEAR_NODE(&object->objlist_link);
#endif
	object->debug_id = atomic_inc_return(&fscache_object_debug_id);
}
EXPORT_SYMBOL(fscache_object_init);

/**
 * fscache_object_destroy - Note that a cache object is about to be destroyed
 * @object: The object to be destroyed
 *
 * Note the imminent destruction and deallocation of a cache object record.
 */
void fscache_object_destroy(struct fscache_object *object)
{
	_enter("%u", atomic_read(&object->cache->object_count));

	fscache_objlist_remove(object);

	/* We can get rid of the cookie now */
	fscache_cookie_put(object->cookie, fscache_cookie_put_object);
	object->cookie = NULL;
}
EXPORT_SYMBOL(fscache_object_destroy);

/**
 * fscache_object_destroyed - Note destruction of an object in a cache
 * @cache: The cache from which the object came
 *
 * Note the destruction and deallocation of an object record in a cache.
 */
void fscache_object_destroyed(struct fscache_cache *cache)
{
	_enter("%d", atomic_read(&cache->object_count));
	if (atomic_dec_and_test(&cache->object_count))
		wake_up_all(&fscache_cache_cleared_wq);
}
EXPORT_SYMBOL(fscache_object_destroyed);

/**
 * fscache_object_mark_killed - Note that an object was killed
 * @object: The object that was culled
 * @why: The reason the object was killed.
 *
 * Note that an object was killed.  Returns true if the object was
 * already marked killed, false if it wasn't.
 */
void fscache_object_mark_killed(struct fscache_object *object,
				enum fscache_why_object_killed why)
{
	switch (why) {
	case FSCACHE_OBJECT_NO_SPACE:
		fscache_stat(&fscache_n_cache_no_space_reject);
		break;
	case FSCACHE_OBJECT_IS_STALE:
		fscache_stat(&fscache_n_cache_stale_objects);
		break;
	case FSCACHE_OBJECT_WAS_RETIRED:
		fscache_stat(&fscache_n_cache_retired_objects);
		break;
	case FSCACHE_OBJECT_WAS_CULLED:
		fscache_stat(&fscache_n_cache_culled_objects);
		break;
	}
}
EXPORT_SYMBOL(fscache_object_mark_killed);

/**
 * fscache_object_retrying_stale - Note retrying stale object
 * @object: The object that will be retried
 *
 * Note that an object lookup found an on-disk object that was adjudged to be
 * stale and has been deleted.  The lookup will be retried.
 */
void fscache_object_retrying_stale(struct fscache_object *object)
{
	fscache_stat(&fscache_n_cache_stale_objects);
}
EXPORT_SYMBOL(fscache_object_retrying_stale);
