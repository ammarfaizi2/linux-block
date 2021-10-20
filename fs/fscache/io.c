// SPDX-License-Identifier: GPL-2.0-or-later
/* Cache data I/O routines
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#define FSCACHE_DEBUG_LEVEL OPERATION
#define FSCACHE_USE_NEW_IO_API
#define FSCACHE_USE_FALLBACK_IO_API
#include <linux/fscache-cache.h>
#include <linux/uio.h>
#include <linux/bvec.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include "internal.h"

/**
 * fscache_wait_for_operation - Wait for an object become accessible
 * @cres: The cache resources for the operation being performed
 * @want_stage: The minimum stage the object must be at
 *
 * See if the target cache object is at the specified minimum stage of
 * accessibility yet, and if not, wait for it.
 */
bool fscache_wait_for_operation(struct netfs_cache_resources *cres,
				enum fscache_want_stage want_stage)
{
	struct fscache_cookie *cookie = fscache_cres_cookie(cres);
	enum fscache_cookie_stage stage;

again:
	if (!fscache_cache_is_live(cookie->volume->cache)) {
		_leave(" [broken]");
		return false;
	}

	stage = READ_ONCE(cookie->stage);
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want_stage);

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_CREATING:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		if (want_stage == FSCACHE_WANT_PARAMS)
			goto ready; /* There can be no content */
		fallthrough;
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_COMMITTING:
		wait_var_event(&cookie->stage, READ_ONCE(cookie->stage) != stage);
		goto again;

	case FSCACHE_COOKIE_STAGE_ACTIVE:
		goto ready;
	case FSCACHE_COOKIE_STAGE_DROPPED:
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
	default:
		_leave(" [not live]");
		return false;
	}

ready:
	if (!cres->cache_priv2)
		return cookie->volume->cache->ops->begin_operation(cres, want_stage);
	return true;
}
EXPORT_SYMBOL(fscache_wait_for_operation);

/*
 * Begin an I/O operation on the cache, waiting till we reach the right state.
 *
 * Attaches the resources required to the operation resources record.
 */
static int fscache_begin_operation(struct netfs_cache_resources *cres,
				   struct fscache_cookie *cookie,
				   enum fscache_want_stage want_stage,
				   enum fscache_access_trace why)
{
	enum fscache_cookie_stage stage;
	long timeo;
	bool once_only = false;

	cres->ops		= NULL;
	cres->cache_priv	= cookie;
	cres->cache_priv2	= NULL;
	cres->debug_id		= cookie->debug_id;
	cres->inval_counter	= cookie->inval_counter;

	if (!fscache_begin_cookie_access(cookie, why))
		return -ENOBUFS;

again:
	spin_lock(&cookie->lock);

	stage = cookie->stage;
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want_stage);

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_COMMITTING:
		goto wait_and_validate;
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
	case FSCACHE_COOKIE_STAGE_CREATING:
		if (want_stage == FSCACHE_WANT_PARAMS)
			goto ready; /* There can be no content */
		goto wait_and_validate;
	case FSCACHE_COOKIE_STAGE_ACTIVE:
		goto ready;
	case FSCACHE_COOKIE_STAGE_DROPPED:
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
		WARN(1, "Can't use cookie in stage %u\n", cookie->stage);
		goto not_live;
	default:
		goto not_live;
	}

ready:
	spin_unlock(&cookie->lock);
	if (!cookie->volume->cache->ops->begin_operation(cres, want_stage))
		goto failed;
	return 0;

wait_and_validate:
	spin_unlock(&cookie->lock);
	trace_fscache_access(cookie->debug_id, refcount_read(&cookie->ref),
			     atomic_read(&cookie->n_accesses),
			     fscache_access_io_wait);
	timeo = wait_var_event_timeout(&cookie->stage,
				       READ_ONCE(cookie->stage) != stage, 20 * HZ);
	if (timeo <= 1 && !once_only) {
		pr_warn("%s: cookie stage change wait timed out: cookie->stage=%u stage=%u",
			__func__, READ_ONCE(cookie->stage), stage);
		fscache_print_cookie(cookie, 'O');
		once_only = true;
	}
	goto again;

not_live:
	spin_unlock(&cookie->lock);
failed:
	cres->cache_priv = NULL;
	cres->ops = NULL;
	fscache_end_cookie_access(cookie, fscache_access_io_not_live);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}

int __fscache_begin_read_operation(struct netfs_cache_resources *cres,
				   struct fscache_cookie *cookie)
{
	return fscache_begin_operation(cres, cookie, FSCACHE_WANT_PARAMS,
				       fscache_access_io_read);
}
EXPORT_SYMBOL(__fscache_begin_read_operation);
