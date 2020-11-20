// SPDX-License-Identifier: GPL-2.0-or-later
/* Cache object management
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * See Documentation/filesystems/caching/netfs-api.txt for more information on
 * the netfs API.
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
#include <linux/module.h>
#include <linux/slab.h>
#include "internal.h"

static struct fscache_object *fscache_do_alloc_object(struct fscache_cookie *cookie,
						      struct fscache_cache *cache,
						      struct fscache_object *parent)
{
	struct fscache_object *object;

	fscache_stat(&fscache_n_cop_alloc_object);
	object = cache->ops->alloc_object(cookie, cache, parent);
	fscache_stat_d(&fscache_n_cop_alloc_object);

	if (object) {
		ASSERTCMP(object->cookie, ==, cookie);
		_debug("ALLOC o=%08x: %s", object->debug_id, cookie->type_name);
		fscache_stat(&fscache_n_object_alloc);
	} else {
		fscache_stat(&fscache_n_object_no_alloc);
	}

	return object;
}

static int fscache_do_lookup_object(struct fscache_object *object, void *data)
{
	int ret;
	fscache_stat(&fscache_n_object_lookups);
	fscache_stat(&fscache_n_cop_lookup_object);
	ret = object->cache->ops->lookup_object(object, data);
	fscache_stat_d(&fscache_n_cop_lookup_object);
	return ret;
}

static int fscache_do_create_object(struct fscache_object *object, void *data)
{
	int ret;
	fscache_stat(&fscache_n_object_creates);
	fscache_stat(&fscache_n_cop_create_object);
	ret = object->cache->ops->create_object(object, data);
	fscache_stat_d(&fscache_n_cop_create_object);
	return ret;
}

static void fscache_do_drop_object(struct fscache_cache *cache,
				   struct fscache_object *object,
				   bool invalidate)
{
	fscache_stat(&fscache_n_cop_drop_object);
	cache->ops->drop_object(object, invalidate);
	fscache_stat_d(&fscache_n_cop_drop_object);
}

static void fscache_do_put_object(struct fscache_object *object,
				  enum fscache_obj_ref_trace why)
{
	fscache_stat(&fscache_n_cop_put_object);
	object->cache->ops->put_object(object, why);
	fscache_stat_d(&fscache_n_cop_put_object);
}

/*
 * Do the actual on-disk wrangling involved in object lookup/creation.
 */
static bool fscache_wrangle_object(struct fscache_cookie *cookie,
				   struct fscache_cache *cache,
				   struct fscache_object *object)
{

	void *lookup_data;
	bool ret = false;

	lookup_data = cache->ops->prepare_lookup_data(object);
	if (IS_ERR(lookup_data))
		goto out;

	if (!fscache_do_lookup_object(object, lookup_data))
		goto out_free;

	if (object->stage < FSCACHE_OBJECT_STAGE_LIVE_EMPTY &&
	    !fscache_do_create_object(object, lookup_data))
		goto out_free;

	fscache_set_cookie_stage(cookie,
				 (object->stage < FSCACHE_OBJECT_STAGE_LIVE ?
				  FSCACHE_COOKIE_STAGE_NO_DATA_YET :
				  FSCACHE_COOKIE_STAGE_ACTIVE));
	ret = true;

out_free:
	cache->ops->free_lookup_data(object, lookup_data);
out:
	return ret;
}

/*
 * Create an object chain, making sure that the index chain is fully created.
 */
static struct fscache_object *fscache_lookup_object_chain(struct fscache_cookie *cookie,
							  struct fscache_cache *cache,
							  bool will_modify)
{
	struct fscache_object *object = NULL, *parent, *xobject;

	_enter("c=%08x", cookie->debug_id);

	spin_lock(&cookie->lock);
	hlist_for_each_entry(object, &cookie->backing_objects, cookie_link) {
		if (object->cache == cache)
			goto object_exists_grab;
	}
	spin_unlock(&cookie->lock);

	/* Recurse to look up/create the parent index. */
	parent = fscache_lookup_object_chain(cookie->parent, cache, false);
	if (!parent)
		goto error;

	/* Ask the cache to allocate an object (we may end up with duplicate
	 * objects at this stage, but we sort that out later).
	 *
	 * The object may be created, say, with O_TMPFILE at this point if the
	 * parent index was unpopulated.  Note that this may race on index
	 * creation with other callers.
	 */
	object = fscache_do_alloc_object(cookie, cache, parent);
	if (!object)
		goto error;

	if (will_modify)
		__set_bit(FSCACHE_OBJECT_LOCAL_WRITE, &object->flags);

	xobject = fscache_attach_object(cookie, object);
	if (xobject != object) {
		fscache_do_put_object(object, fscache_obj_put_alloc_dup);
		if (!xobject)
			goto error;
		object = xobject;
		if (fscache_cache_is_broken(object))
			goto error_put;
		goto object_exists;
	}

	if (!fscache_wrangle_object(cookie, cache, object))
		goto error_detach;

	_leave(" = new [o=%08x]", object->debug_id);
	return object;

object_exists_grab:
	object = cache->ops->grab_object(object, fscache_obj_get_exists);
	if (fscache_cache_is_broken(object)) {
		spin_unlock(&cookie->lock);
		goto error_put;
	}

	spin_unlock(&cookie->lock);

object_exists:
	wait_var_event(&object->stage,
		       READ_ONCE(object->stage) >= FSCACHE_OBJECT_STAGE_LIVE_EMPTY);

	if (object->stage >= FSCACHE_OBJECT_STAGE_DESTROYING)
		goto error_put;

	_leave(" = share [o=%08x]", object->debug_id);
	return object;

error_detach:
	spin_lock(&cookie->lock);
	spin_lock(&object->lock);
	object->parent = NULL;
	object->stage = FSCACHE_OBJECT_STAGE_DEAD;
	cookie->stage = FSCACHE_COOKIE_STAGE_FAILED;
	hlist_del_init(&object->cookie_link);
	spin_unlock(&object->lock);
	spin_unlock(&cookie->lock);
	wake_up_cookie_stage(cookie);
	fscache_drop_object(cookie, object, false);
error_put:
	fscache_do_put_object(object, fscache_obj_put_lookup_fail);
error:
	if (cookie->stage != FSCACHE_COOKIE_STAGE_FAILED)
		fscache_set_cookie_stage(cookie, FSCACHE_COOKIE_STAGE_QUIESCENT);
	_leave(" = NULL");
	return NULL;
}

/*
 * Create an object in the cache.
 * - this must make sure the index chain is instantiated and instantiate the
 *   object representation too
 */
static void fscache_lookup_object_locked(struct fscache_cookie *cookie,
					 bool will_modify)
{
	struct fscache_object *object;
	struct fscache_cache *cache;

	_enter("");

	/* select a cache in which to store the object */
	cache = fscache_select_cache_for_object(cookie);
	if (!cache) {
		fscache_stat(&fscache_n_acquires_no_cache);
		fscache_set_cookie_stage(cookie, FSCACHE_COOKIE_STAGE_QUIESCENT);
		_leave(" [no cache]");
		return;
	}

	_debug("cache %s", cache->tag->name);

	object = fscache_lookup_object_chain(cookie, cache, will_modify);
	if (!object) {
		_leave(" [fail]");
		return;
	}

	if (will_modify &&
	    test_and_set_bit(FSCACHE_OBJECT_LOCAL_WRITE, &object->flags))
		fscache_prepare_to_write(cookie, object, 0);

	fscache_do_put_object(object, fscache_obj_put);
	_leave(" [done]");
}

void fscache_lookup_object(struct fscache_cookie *cookie,
			   struct fscache_object *object, int param)
{
	down_read(&fscache_addremove_sem);
	fscache_lookup_object_locked(cookie, param);
	up_read(&fscache_addremove_sem);
	__fscache_unuse_cookie(cookie, NULL, NULL);
}

/*
 * Invalidate an object.  param passes the invalidation flags.
 */
void fscache_invalidate_object(struct fscache_cookie *cookie,
			       struct fscache_object *object, int flags)
{
	bool success;

	success = object->cache->ops->invalidate_object(object, flags);
	fscache_do_put_object(object, fscache_obj_put_inval);

	if (success)
		fscache_set_cookie_stage(cookie, FSCACHE_COOKIE_STAGE_NO_DATA_YET);
	else
		fscache_set_cookie_stage(cookie, FSCACHE_COOKIE_STAGE_FAILED);
	fscache_uncount_io_operation(cookie);
}

/*
 * Drop an object's attachments
 */
void fscache_drop_object(struct fscache_cookie *cookie,
			 struct fscache_object *object,
			 bool invalidate)
{
	struct fscache_object *parent = object->parent;
	struct fscache_cache *cache = object->cache;

	if (WARN(cookie->stage != FSCACHE_COOKIE_STAGE_INDEX &&
		 cookie->stage != FSCACHE_COOKIE_STAGE_WITHDRAWING &&
		 cookie->stage != FSCACHE_COOKIE_STAGE_FAILED &&
		 cookie->stage != FSCACHE_COOKIE_STAGE_RELINQUISHING,
		 "Can't drop object in stage %u\n", cookie->stage))
		return;

	_enter("{o=%08x,%d},%u",
	       object->debug_id, object->n_children, invalidate);

	spin_lock(&cache->object_list_lock);
	list_del_init(&object->cache_link);
	spin_unlock(&cache->object_list_lock);

	fscache_do_drop_object(cache, object, invalidate);

	/* The parent object wants to know when all it dependents have gone */
	if (parent) {
		bool wake = false;

		_debug("release parent o=%08x {%d}",
		       parent->debug_id, parent->n_children);

		spin_lock(&parent->lock);
		parent->n_children--;
		if (parent->n_children == 0)
			wake = true;
		spin_unlock(&parent->lock);
		if (wake) {
			smp_mb();
			wake_up_var(&parent->n_children);
		}
		fscache_do_put_object(parent, fscache_obj_put_drop_child);
	}

	fscache_do_put_object(object, fscache_obj_put_drop_obj);
	fscache_stat(&fscache_n_object_dead);
	_leave("");
}

/*
 * Discard objects on cookie relinquishement.  param==1 to invalidate it at the
 * same time.
 */
void fscache_relinquish_objects(struct fscache_cookie *cookie,
				struct fscache_object *unused, int param)
{
	_enter("c=%08x", cookie->debug_id);

	wait_var_event(&cookie->n_active, atomic_read(&cookie->n_active) == 0);
	WARN_ON(cookie->stage != FSCACHE_COOKIE_STAGE_RELINQUISHING);

	for (;;) {
		struct fscache_object *object = NULL;

		trace_fscache_cookie(cookie, fscache_cookie_see_discard,
				     atomic_read(&cookie->usage));

		spin_lock(&cookie->lock);
		if (!hlist_empty(&cookie->backing_objects)) {
			object = hlist_entry(cookie->backing_objects.first,
					     struct fscache_object,
					     cookie_link);
			hlist_del_init(&object->cookie_link);
		}
		spin_unlock(&cookie->lock);

		if (!object)
			break;

		_debug("DISCARD o=%08x", object->debug_id);
		fscache_drop_object(cookie, object, param);
	}

	fscache_drop_cookie(cookie);
}

/*
 * Prepare a cache object to be written to.
 */
void fscache_prepare_to_write(struct fscache_cookie *cookie,
			      struct fscache_object *object, int param)
{
	object->cache->ops->prepare_to_write(object);
}
