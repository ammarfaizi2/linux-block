// SPDX-License-Identifier: GPL-2.0-or-later
/* Data I/O routines
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
#include <linux/module.h>
#include <linux/fscache-cache.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * Initialise an I/O request
 */
void __fscache_init_io_request(struct fscache_io_request *req,
			       struct fscache_cookie *cookie)
{
	req->cookie = fscache_cookie_get(cookie, fscache_cookie_get_ioreq);
}
EXPORT_SYMBOL(__fscache_init_io_request);

/*
 * Clean up an I/O request
 */
void __fscache_free_io_request(struct fscache_io_request *req)
{
	if (req->object)
		req->object->cache->ops->put_object(req->object,
						    fscache_obj_put_ioreq);
	fscache_cookie_put(req->cookie, fscache_cookie_put_ioreq);
}
EXPORT_SYMBOL(__fscache_free_io_request);

enum fscache_want_stage {
	FSCACHE_WANT_PARAMS,
	FSCACHE_WANT_WRITE,
	FSCACHE_WANT_READ,
};

/*
 * Begin an I/O operation on the cache, waiting till we reach the right state.
 *
 * Returns a pointer to the object to use or an error.  If an object is
 * returned, it will have an extra ref on it.
 */
static struct fscache_object *fscache_begin_io_operation(
	struct fscache_cookie *cookie,
	enum fscache_want_stage want,
	struct fscache_io_request *req)
{
	struct fscache_object *object;
	enum fscache_cookie_stage stage;

again:
	spin_lock(&cookie->lock);

	stage = cookie->stage;
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want);

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_QUIESCENT:
	case FSCACHE_COOKIE_STAGE_DEAD:
		goto not_live;
	case FSCACHE_COOKIE_STAGE_INITIALISING:
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		goto wait_and_validate;

	case FSCACHE_COOKIE_STAGE_NO_DATA_YET:
		if (want == FSCACHE_WANT_READ)
			goto no_data_yet;
		/* Fall through */
	case FSCACHE_COOKIE_STAGE_ACTIVE:
		goto ready;
	}

ready:
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	if (fscache_cache_is_broken(object))
		goto not_live;

	object->cache->ops->grab_object(object, fscache_obj_get_ioreq);

	atomic_inc(&cookie->n_ops);
	spin_unlock(&cookie->lock);
	return object;

wait_and_validate:
	spin_unlock(&cookie->lock);
	wait_var_event(&cookie->stage, cookie->stage != stage);
	if (req &&
	    req->ops->is_still_valid &&
	    !req->ops->is_still_valid(req)) {
		_leave(" = -ESTALE");
		return ERR_PTR(-ESTALE);
	}
	goto again;

no_data_yet:
	spin_unlock(&cookie->lock);
	_leave(" = -ENODATA");
	return ERR_PTR(-ENODATA);

not_live:
	spin_unlock(&cookie->lock);
	_leave(" = -ENOBUFS");
	return ERR_PTR(-ENOBUFS);
}

/*
 * Determine the size of an allocation granule or a region of data in the
 * cache.
 */
unsigned int __fscache_shape_extent(struct fscache_cookie *cookie,
				    struct fscache_extent *extent,
				    loff_t i_size, bool for_write)
{
	struct fscache_object *object =
		fscache_begin_io_operation(cookie, FSCACHE_WANT_PARAMS, NULL);
	unsigned int ret = 0;

	if (!IS_ERR(object)) {
		ret = object->cache->ops->shape_extent(object, extent, i_size, for_write);
		object->cache->ops->put_object(object, fscache_obj_put_ioreq);
		fscache_end_io_operation(cookie);
	}
	return ret;
}
EXPORT_SYMBOL(__fscache_shape_extent);

/*
 * Read data from the cache.
 */
int __fscache_read(struct fscache_io_request *req, struct iov_iter *iter)
{
	struct fscache_object *object =
		fscache_begin_io_operation(req->cookie, FSCACHE_WANT_READ, req);

	if (!IS_ERR(object)) {
		req->object = object;
		return object->cache->ops->read(object, req, iter);
	} else {
		req->error = PTR_ERR(object);
		if (req->io_done)
			req->io_done(req);
		return req->error;
	}
}
EXPORT_SYMBOL(__fscache_read);

/*
 * Write data to the cache.
 */
int __fscache_write(struct fscache_io_request *req, struct iov_iter *iter)
{
	struct fscache_object *object =
		fscache_begin_io_operation(req->cookie, FSCACHE_WANT_WRITE, req);

	if (!IS_ERR(object)) {
		req->object = object;
		return object->cache->ops->write(object, req, iter);
	} else {
		req->error = PTR_ERR(object);
		if (req->io_done)
			req->io_done(req);
		return req->error;
	}
}
EXPORT_SYMBOL(__fscache_write);
