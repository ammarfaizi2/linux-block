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
static bool netfs_check_for_conflicting_regions(struct netfs_inode *ctx,
						struct file *file,
						loff_t start, size_t len)
{
	struct netfs_dirty_region *r;
	unsigned long long from = start;
	unsigned long long to = from + len;
	size_t min_bsize = 1UL << ctx->min_bshift;
	pgoff_t first = round_down(from, min_bsize) / PAGE_SIZE;
	pgoff_t last  = round_up(from + len - 1, min_bsize) / PAGE_SIZE;

	_debug("check %lx-%lx", first, last);

	/* See if there are any dirty regions that need flushing first. */
	list_for_each_entry(r, &ctx->dirty_regions, dirty_link) {
		if (r->last < first)
			continue;
		if (r->first > last)
			break;
		_debug("confl? [D=%x] %lx-%lx", r->debug_id, r->first, r->last);

		if (ctx->ops->is_write_compatible &&
		    !ctx->ops->is_write_compatible(ctx, file, r))
			goto conflict;
		if (from >= ctx->zero_point || r->from >= ctx->zero_point)
			continue;
		if (from > r->to || to < r->from)
			goto conflict;
	}

	return false;
conflict:
	trace_netfs_dirty(ctx, r, NULL, netfs_dirty_trace_flush_conflict);
	return true;
}

int netfs_flush_conflicting_writes(struct netfs_inode *ctx,
				   struct file *file,
				   loff_t start, size_t len,
				   struct folio *unlock_this)
{
	bool check;

	spin_lock(&ctx->dirty_lock);
	check = netfs_check_for_conflicting_regions(ctx, file, start, len);
	spin_unlock(&ctx->dirty_lock);

	if (check) {
		folio_unlock(unlock_this);
		pr_warn("NEED TO FLUSH CONFLICTING REGIONS\n");
		return -EAGAIN;
	}
	return 0;
}
