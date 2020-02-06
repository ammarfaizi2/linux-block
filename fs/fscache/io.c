// SPDX-License-Identifier: GPL-2.0-or-later
/* Cache data I/O routines
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#define FSCACHE_DEBUG_LEVEL OPERATION
#include <linux/module.h>
#include <linux/fscache-cache.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * Wait for a cookie to reach the specified stage.
 */
void __fscache_wait_for_operation(struct netfs_cache_resources *cres,
				  enum fscache_want_stage want_stage)
{
	struct fscache_object *object = fscache_cres_object(cres);
	struct fscache_cookie *cookie = object->cookie;
	enum fscache_cookie_stage stage;

again:
	stage = READ_ONCE(cookie->stage);
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want_stage);

	if (fscache_cache_is_broken(object)) {
		_leave(" [broken]");
		return;
	}

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_INITIALISING:
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		wait_var_event(&cookie->stage, READ_ONCE(cookie->stage) != stage);
		goto again;

	case FSCACHE_COOKIE_STAGE_NO_DATA_YET:
	case FSCACHE_COOKIE_STAGE_ACTIVE:
		return;
	case FSCACHE_COOKIE_STAGE_INDEX:
	case FSCACHE_COOKIE_STAGE_DROPPED:
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
	default:
		_leave(" [not live]");
		return;
	}
}
EXPORT_SYMBOL(__fscache_wait_for_operation);

/*
 * Release the resources needed by an operation.
 */
void __fscache_end_operation(struct netfs_cache_resources *cres)
{
	struct fscache_object *object = fscache_cres_object(cres);

	fscache_uncount_io_operation(object->cookie);
	object->cache->ops->put_object(object, fscache_obj_put_ioreq);
}
EXPORT_SYMBOL(__fscache_end_operation);

/*
 * Begin an I/O operation on the cache, waiting till we reach the right state.
 *
 * Attaches the resources required to the operation resources record.
 */
static int fscache_begin_operation(struct netfs_cache_resources *cres,
				   struct fscache_cookie *cookie,
				   enum fscache_want_stage want_stage)
{
	struct fscache_object *object;
	enum fscache_cookie_stage stage;
	long timeo;
	bool once_only = false;

again:
	spin_lock(&cookie->lock);

	stage = cookie->stage;
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want_stage);

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_INITIALISING:
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		goto wait_and_validate;

	case FSCACHE_COOKIE_STAGE_NO_DATA_YET:
		if (want_stage == FSCACHE_WANT_READ)
			goto no_data_yet;
		fallthrough;
	case FSCACHE_COOKIE_STAGE_ACTIVE:
		goto ready;
	case FSCACHE_COOKIE_STAGE_INDEX:
	case FSCACHE_COOKIE_STAGE_DROPPED:
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
		WARN(1, "Can't use cookie in stage %u\n", cookie->stage);
		goto not_live;
	default:
		goto not_live;
	}

ready:
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	if (fscache_cache_is_broken(object))
		goto not_live;

	cres->debug_id = cookie->debug_id;
	cres->cache_priv = object;
	object->cache->ops->grab_object(object, fscache_obj_get_ioreq);
	object->cache->ops->begin_operation(cres);

	fscache_count_io_operation(cookie);
	spin_unlock(&cookie->lock);
	return 0;

wait_and_validate:
	spin_unlock(&cookie->lock);
	timeo = wait_var_event_timeout(&cookie->stage,
				       READ_ONCE(cookie->stage) != stage, 20 * HZ);
	if (timeo <= 1 && !once_only) {
		pr_warn("%s: cookie stage change wait timed out: cookie->stage=%u stage=%u",
			__func__, READ_ONCE(cookie->stage), stage);
		fscache_print_cookie(cookie, 'O');
		once_only = true;
	}
	goto again;

no_data_yet:
	spin_unlock(&cookie->lock);
	cres->cache_priv = NULL;
	_leave(" = -ENODATA");
	return -ENODATA;

not_live:
	spin_unlock(&cookie->lock);
	cres->cache_priv = NULL;
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}

int __fscache_begin_read_operation(struct netfs_read_request *rreq,
				   struct fscache_cookie *cookie)
{
	return fscache_begin_operation(&rreq->cache_resources, cookie,
				       FSCACHE_WANT_READ);
}
EXPORT_SYMBOL(__fscache_begin_read_operation);
