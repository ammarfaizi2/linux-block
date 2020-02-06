// SPDX-License-Identifier: GPL-2.0-or-later
/* Cache page management and data I/O routines
 *
 * Copyright (C) 2004-2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL PAGE
#include <linux/module.h>
#include <linux/fscache-cache.h>
#include <linux/buffer_head.h>
#include <linux/pagevec.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * wait for a deferred lookup to complete
 */
int fscache_wait_for_deferred_lookup(struct fscache_cookie *cookie)
{
	_enter("");

	if (!test_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags)) {
		_leave(" = 0 [imm]");
		return 0;
	}

	fscache_stat(&fscache_n_retrievals_wait);

	if (wait_on_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP,
			TASK_INTERRUPTIBLE) != 0) {
		fscache_stat(&fscache_n_retrievals_intr);
		_leave(" = -ERESTARTSYS");
		return -ERESTARTSYS;
	}

	ASSERT(!test_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags));

	smp_rmb();
	_leave(" = 0 [dly]");
	return 0;
}

/*
 * wait for an object to become active (or dead)
 */
int fscache_wait_for_operation_activation(struct fscache_object *object,
					  struct fscache_operation *op,
					  atomic_t *stat_op_waits,
					  atomic_t *stat_object_dead)
{
	int ret;

	if (!test_bit(FSCACHE_OP_WAITING, &op->flags))
		goto check_if_dead;

	_debug(">>> WT");
	if (stat_op_waits)
		fscache_stat(stat_op_waits);
	if (wait_on_bit(&op->flags, FSCACHE_OP_WAITING,
			TASK_INTERRUPTIBLE) != 0) {
		trace_fscache_op(object->cookie, op, fscache_op_signal);
		ret = fscache_cancel_op(op, false);
		if (ret == 0)
			return -ERESTARTSYS;

		/* it's been removed from the pending queue by another party,
		 * so we should get to run shortly */
		wait_on_bit(&op->flags, FSCACHE_OP_WAITING,
			    TASK_UNINTERRUPTIBLE);
	}
	_debug("<<< GO");

check_if_dead:
	if (op->state == FSCACHE_OP_ST_CANCELLED) {
		if (stat_object_dead)
			fscache_stat(stat_object_dead);
		_leave(" = -ENOBUFS [cancelled]");
		return -ENOBUFS;
	}
	if (unlikely(fscache_object_is_dying(object) ||
		     fscache_cache_is_broken(object))) {
		enum fscache_operation_state state = op->state;
		trace_fscache_op(object->cookie, op, fscache_op_signal);
		fscache_cancel_op(op, true);
		if (stat_object_dead)
			fscache_stat(stat_object_dead);
		_leave(" = -ENOBUFS [obj dead %d]", state);
		return -ENOBUFS;
	}
	return 0;
}
