// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem write flushing
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include "internal.h"

/*
 * See if there are any conflicting dirty regions in the specified range.  The
 * caller must hold the dirty_regions lock or the RCU read lock.
 */
static bool netfs_check_for_conflicting_regions(struct netfs_i_context *ctx,
						struct file *file,
						loff_t start, size_t len)
{
	struct netfs_dirty_region *r;
	unsigned long long from = start;
	unsigned long long to = from + len;
	size_t min_bsize = 1UL << ctx->min_bshift;
	pgoff_t first = round_down(from, min_bsize) / PAGE_SIZE;
	pgoff_t last  = round_up(from + len - 1, min_bsize) / PAGE_SIZE;
	bool conflicts = false;

	MA_STATE(mas, &ctx->dirty_regions, first, first);

	_debug("check %lx-%lx", first, last);

	/* See if there are any dirty regions that need flushing first. */
	mas_for_each(&mas, r, last) {
		_debug("confl? [D=%x] %lx-%lx",
		       netfs_mas_is_valid(r) ? r->debug_id : 0,
		       mas.index, mas.last);

		if (!netfs_mas_is_valid(r))
			continue;
		if (ctx->ops->is_write_compatible &&
		    !ctx->ops->is_write_compatible(ctx, file, r))
			goto conflict;
		if (from >= ctx->zero_point || r->from >= ctx->zero_point)
			continue;
		if (from > r->to || to < r->from)
			goto conflict;
	}

out:
	mas_destroy(&mas);
	return conflicts;
conflict:
	trace_netfs_dirty(ctx, r, NULL, mas.index, mas.last,
			  netfs_dirty_trace_flush_conflict);
	conflicts = true;
	goto out;
}

int netfs_flush_conflicting_writes(struct netfs_i_context *ctx,
				   struct file *file,
				   loff_t start, size_t len,
				   struct folio *unlock_this)
{
	bool check;

	mtree_lock(&ctx->dirty_regions);
	check = netfs_check_for_conflicting_regions(ctx, file, start, len);
	mtree_unlock(&ctx->dirty_regions);

	if (check) {
		folio_unlock(unlock_this);
		pr_warn("NEED TO FLUSH CONFLICTING REGIONS\n");
		return -EAGAIN;
	}
	return 0;
}
