// SPDX-License-Identifier: GPL-2.0-or-later
/* FS-Cache cache handling
 *
 * Copyright (C) 2007, 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/module.h>
#include <linux/slab.h>
#include "internal.h"

LIST_HEAD(fscache_cache_list);
DECLARE_RWSEM(fscache_addremove_sem);
DECLARE_WAIT_QUEUE_HEAD(fscache_cache_cleared_wq);
EXPORT_SYMBOL(fscache_cache_cleared_wq);

static LIST_HEAD(fscache_cache_tag_list);

/*
 * look up a cache tag
 */
struct fscache_cache_tag *__fscache_lookup_cache_tag(const char *name)
{
	struct fscache_cache_tag *tag, *xtag;

	/* firstly check for the existence of the tag under read lock */
	down_read(&fscache_addremove_sem);

	list_for_each_entry(tag, &fscache_cache_tag_list, link) {
		if (strcmp(tag->name, name) == 0) {
			atomic_inc(&tag->usage);
			refcount_inc(&tag->ref);
			up_read(&fscache_addremove_sem);
			return tag;
		}
	}

	up_read(&fscache_addremove_sem);

	/* the tag does not exist - create a candidate */
	xtag = kzalloc(sizeof(*xtag) + strlen(name) + 1, GFP_KERNEL);
	if (!xtag)
		/* return a dummy tag if out of memory */
		return ERR_PTR(-ENOMEM);

	atomic_set(&xtag->usage, 1);
	refcount_set(&xtag->ref, 1);
	strcpy(xtag->name, name);

	/* write lock, search again and add if still not present */
	down_write(&fscache_addremove_sem);

	list_for_each_entry(tag, &fscache_cache_tag_list, link) {
		if (strcmp(tag->name, name) == 0) {
			atomic_inc(&tag->usage);
			refcount_inc(&tag->ref);
			up_write(&fscache_addremove_sem);
			kfree(xtag);
			return tag;
		}
	}

	list_add_tail(&xtag->link, &fscache_cache_tag_list);
	up_write(&fscache_addremove_sem);
	return xtag;
}

/*
 * Unuse a cache tag
 */
void __fscache_release_cache_tag(struct fscache_cache_tag *tag)
{
	if (tag != ERR_PTR(-ENOMEM)) {
		down_write(&fscache_addremove_sem);

		if (atomic_dec_and_test(&tag->usage))
			list_del_init(&tag->link);
		else
			tag = NULL;

		up_write(&fscache_addremove_sem);
		fscache_put_cache_tag(tag);
	}
}

/*
 * select a cache in which to store an object
 * - the cache addremove semaphore must be at least read-locked by the caller
 * - the object will never be an index
 */
struct fscache_cache *fscache_select_cache_for_object(
	struct fscache_cookie *cookie)
{
	struct fscache_cache_tag *tag;
	struct fscache_cookie *parent = cookie->parent;
	struct fscache_object *object;
	struct fscache_cache *cache;

	_enter("");

	if (list_empty(&fscache_cache_list)) {
		_leave(" = NULL [no cache]");
		return NULL;
	}

	/* we check the parent to determine the cache to use */
	spin_lock(&parent->lock);

	/* the first in the parent's backing list should be the preferred
	 * cache */
	if (!hlist_empty(&parent->backing_objects)) {
		object = hlist_entry(parent->backing_objects.first,
				     struct fscache_object, cookie_link);

		cache = object->cache;
		if (test_bit(FSCACHE_IOERROR, &cache->flags))
			cache = NULL;

		spin_unlock(&parent->lock);
		_leave(" = %s [parent]", cache ? cache->tag->name : "NULL");
		return cache;
	}

	/* the parent is unbacked */
	if (parent->type != FSCACHE_COOKIE_TYPE_INDEX) {
		/* cookie not an index and is unbacked */
		spin_unlock(&parent->lock);
		_leave(" = NULL [parent ub,ni]");
		return NULL;
	}

	spin_unlock(&parent->lock);

	tag = cookie->preferred_cache;
	if (!tag)
		goto no_preference;

	if (!tag->cache) {
		_leave(" = NULL [unbacked tag]");
		return NULL;
	}

	if (test_bit(FSCACHE_IOERROR, &tag->cache->flags))
		return NULL;

	_leave(" = %s [specific]", tag->name);
	return tag->cache;

no_preference:
	/* netfs has no preference - just select first cache */
	cache = list_entry(fscache_cache_list.next,
			   struct fscache_cache, link);
	_leave(" = %s [first]", cache->tag->name);
	return cache;
}

/**
 * fscache_init_cache - Initialise a cache record
 * @cache: The cache record to be initialised
 * @ops: The cache operations to be installed in that record
 * @idfmt: Format string to define identifier
 * @...: sprintf-style arguments
 *
 * Initialise a record of a cache and fill in the name.
 *
 * See Documentation/filesystems/caching/backend-api.rst for a complete
 * description.
 */
void fscache_init_cache(struct fscache_cache *cache,
			const struct fscache_cache_ops *ops,
			const char *idfmt,
			...)
{
	va_list va;

	memset(cache, 0, sizeof(*cache));

	cache->ops = ops;

	va_start(va, idfmt);
	vsnprintf(cache->identifier, sizeof(cache->identifier), idfmt, va);
	va_end(va);

	INIT_LIST_HEAD(&cache->link);
	INIT_LIST_HEAD(&cache->object_list);
	spin_lock_init(&cache->object_list_lock);
}
EXPORT_SYMBOL(fscache_init_cache);

/**
 * fscache_add_cache - Declare a cache as being open for business
 * @cache: The record describing the cache
 * @ifsdef: The record of the cache object describing the top-level index
 * @tagname: The tag describing this cache
 *
 * Add a cache to the system, making it available for netfs's to use.
 *
 * See Documentation/filesystems/caching/backend-api.rst for a complete
 * description.
 */
int fscache_add_cache(struct fscache_cache *cache,
		      struct fscache_object *ifsdef,
		      const char *tagname)
{
	struct fscache_cache_tag *tag;

	ASSERTCMP(ifsdef->cookie, ==, &fscache_fsdef_index);
	BUG_ON(!cache->ops);
	BUG_ON(!ifsdef);

	cache->flags = 0;
	ifsdef->stage = FSCACHE_OBJECT_STAGE_LIVE;

	if (!tagname)
		tagname = cache->identifier;

	BUG_ON(!tagname[0]);

	_enter("{%s.%s},,%s", cache->ops->name, cache->identifier, tagname);

	/* we use the cache tag to uniquely identify caches */
	tag = __fscache_lookup_cache_tag(tagname);
	if (IS_ERR(tag))
		goto nomem;

	if (test_and_set_bit(FSCACHE_TAG_RESERVED, &tag->flags))
		goto tag_in_use;

	cache->kobj = kobject_create_and_add(tagname, fscache_root);
	if (!cache->kobj)
		goto error;

	ifsdef->cache = cache;
	cache->fsdef = ifsdef;

	down_write(&fscache_addremove_sem);

	tag->cache = cache;
	cache->tag = tag;

	/* add the cache to the list */
	list_add(&cache->link, &fscache_cache_list);

	/* add the cache's netfs definition index object to the cache's
	 * list */
	spin_lock(&cache->object_list_lock);
	list_add_tail(&ifsdef->cache_link, &cache->object_list);
	spin_unlock(&cache->object_list_lock);
	fscache_objlist_add(ifsdef);

	/* add the cache's netfs definition index object to the top level index
	 * cookie as a known backing object */
	spin_lock(&fscache_fsdef_index.lock);

	hlist_add_head(&ifsdef->cookie_link,
		       &fscache_fsdef_index.backing_objects);

	atomic_inc(&fscache_fsdef_index.usage);

	/* done */
	spin_unlock(&fscache_fsdef_index.lock);
	up_write(&fscache_addremove_sem);

	pr_notice("Cache \"%s\" added (type %s)\n",
		  cache->tag->name, cache->ops->name);
	kobject_uevent(cache->kobj, KOBJ_ADD);

	_leave(" = 0 [%s]", cache->identifier);
	return 0;

tag_in_use:
	pr_err("Cache tag '%s' already in use\n", tagname);
	__fscache_release_cache_tag(tag);
	_leave(" = -EXIST");
	return -EEXIST;

error:
	__fscache_release_cache_tag(tag);
	_leave(" = -EINVAL");
	return -EINVAL;

nomem:
	_leave(" = -ENOMEM");
	return -ENOMEM;
}
EXPORT_SYMBOL(fscache_add_cache);

/**
 * fscache_io_error - Note a cache I/O error
 * @cache: The record describing the cache
 *
 * Note that an I/O error occurred in a cache and that it should no longer be
 * used for anything.  This also reports the error into the kernel log.
 *
 * See Documentation/filesystems/caching/backend-api.rst for a complete
 * description.
 */
void fscache_io_error(struct fscache_cache *cache)
{
	if (!test_and_set_bit(FSCACHE_IOERROR, &cache->flags))
		pr_err("Cache '%s' stopped due to I/O error\n",
		       cache->ops->name);
}
EXPORT_SYMBOL(fscache_io_error);

/*
 * Withdraw an object.
 */
static void fscache_withdraw_object(struct fscache_cookie *cookie,
				    struct fscache_object *object,
				    int param)
{
	_enter("c=%08x o=%08x", cookie ? cookie->debug_id : 0, object->debug_id);

	_debug("WITHDRAW %x", object->debug_id);

retry:
	spin_lock(&cookie->lock);
	if (cookie->stage == FSCACHE_COOKIE_STAGE_RELINQUISHING) {
		spin_unlock(&cookie->lock);
		wait_var_event(&cookie->stage,
			       READ_ONCE(cookie->stage) != FSCACHE_COOKIE_STAGE_RELINQUISHING);
		cond_resched();
		goto retry;
	}

	if (cookie->stage == FSCACHE_COOKIE_STAGE_DROPPED) {
		spin_unlock(&cookie->lock);
		kleave(" [dropped]");
		return;
	}

	if (cookie->stage != FSCACHE_COOKIE_STAGE_INDEX)
		cookie->stage = FSCACHE_COOKIE_STAGE_WITHDRAWING;
	hlist_del_init(&object->cookie_link);
	spin_unlock(&cookie->lock);
	wake_up_cookie_stage(cookie);

	if (cookie->stage == FSCACHE_COOKIE_STAGE_WITHDRAWING) {
		atomic_dec(&cookie->n_ops);
		wait_var_event(&cookie->n_ops, atomic_read(&cookie->n_ops) == 0);
		atomic_inc(&cookie->n_ops);
	}

	fscache_drop_object(cookie, object, param);

	spin_lock(&cookie->lock);
	if (cookie->stage == FSCACHE_COOKIE_STAGE_WITHDRAWING)
		cookie->stage = FSCACHE_COOKIE_STAGE_QUIESCENT;
	spin_unlock(&cookie->lock);
	wake_up_cookie_stage(cookie);
	object->cache->ops->put_object(object, fscache_obj_put_withdraw);
}

/*
 * Request withdrawal of all the objects in a cache.
 */
static void fscache_withdraw_all_objects(struct fscache_cache *cache)
{
	struct fscache_object *object;

	_enter("");

	spin_lock(&cache->object_list_lock);
	while (!list_empty(&cache->object_list)) {
		/* Go through the list backwards so that we do children before
		 * their parents.
		 */
		object = list_entry(cache->object_list.prev,
				    struct fscache_object, cache_link);
		list_del_init(&object->cache_link);
		cache->ops->grab_object(object, fscache_obj_get_withdraw);
		spin_unlock(&cache->object_list_lock);

		_debug("o=%08x n=%u", object->debug_id, object->n_children);
		wait_var_event(&object->n_children, READ_ONCE(object->n_children) == 0);

		fscache_dispatch(object->cookie, object, 0,
				 fscache_withdraw_object);

		cond_resched();
		spin_lock(&cache->object_list_lock);
	}
	spin_unlock(&cache->object_list_lock);

	_leave("");
}

/**
 * fscache_withdraw_cache - Withdraw a cache from the active service
 * @cache: The record describing the cache
 *
 * Withdraw a cache from service, unbinding all its cache objects from the
 * netfs cookies they're currently representing.
 *
 * See Documentation/filesystems/caching/backend-api.rst for a complete
 * description.
 */
void fscache_withdraw_cache(struct fscache_cache *cache)
{
	_enter("");

	pr_notice("Withdrawing cache \"%s\" (%u objs)\n",
		  cache->tag->name, atomic_read(&cache->object_count));

	/* make the cache unavailable for cookie acquisition */
	if (test_and_set_bit(FSCACHE_CACHE_WITHDRAWN, &cache->flags))
		BUG();

	down_write(&fscache_addremove_sem);
	list_del_init(&cache->link);
	cache->tag->cache = NULL;
	up_write(&fscache_addremove_sem);

	/* we now have to destroy all the active objects pertaining to this
	 * cache - which we do by passing them off to thread pool to be
	 * disposed of */
	_debug("destroy");

	fscache_withdraw_all_objects(cache);

	/* make sure all outstanding data is written to disk */
	fscache_stat(&fscache_n_cop_sync_cache);
	cache->ops->sync_cache(cache);
	fscache_stat_d(&fscache_n_cop_sync_cache);

	/* wait for all extant objects to finish their outstanding operations
	 * and go away */
	_debug("wait for finish %u", atomic_read(&cache->object_count));
	wait_event(fscache_cache_cleared_wq,
		   atomic_read(&cache->object_count) == 0);
	_debug("wait for clearance");
	wait_event(fscache_cache_cleared_wq,
		   list_empty(&cache->object_list));
	_debug("cleared");

	kobject_put(cache->kobj);

	clear_bit(FSCACHE_TAG_RESERVED, &cache->tag->flags);
	fscache_release_cache_tag(cache->tag);
	cache->tag = NULL;

	_leave("");
}
EXPORT_SYMBOL(fscache_withdraw_cache);
