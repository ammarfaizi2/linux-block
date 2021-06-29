// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem write flushing
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/pagevec.h>
#include "internal.h"

/* Round up the last page of a region where the range is inclusive.  */
#define round_up_incl(x, to) (round_up((x) + 1, (to)) - 1)

/*
 * Unmark for writeback the pages attached to the writeback record.  Pages from
 * the pagecache containing the raw data are attached to wreq->buffer and
 * marked with NETFS_BUF_PAGECACHE_MARK.  There may be other pages interspersed
 * that we shouldn't change (for instance the ZERO_PAGE).
 */
static void netfs_writeback_end(struct netfs_io_request *wreq)
{
	struct folio *folio;
	unsigned long index;

	trace_netfs_rreq(wreq, netfs_rreq_trace_unmark);
	xa_for_each_range(&wreq->buffer, index, folio, wreq->first, wreq->last) {
		if (xa_get_mark(&wreq->buffer, index, NETFS_BUF_PAGECACHE_MARK))
			folio_end_writeback(folio);
	}
}

/*
 * Fix up the list of dirty regions upon completion of write.
 */
static void netfs_clean_dirty_range(struct netfs_io_request *wreq)
{
	struct netfs_dirty_region *r, *a, *b, *to_put[2] = {};
	struct netfs_i_context *ctx = netfs_i_context(wreq->inode);
	pgoff_t tmp;
	bool merge_first = false, merge_last = false, no_merge = false;
	bool visible = false, overlain = false, created_xa_zero = false;

	MA_STATE(mas, &ctx->dirty_regions, wreq->first, wreq->last);

	_enter("");

	netfs_writeback_end(wreq);

	if (mas_expected_entries(&mas, 2) < 0)
		no_merge = true; /* ENOMEM.  Ugh.  But we can skip the merge. */

	mtree_lock(&ctx->dirty_regions);

	/* Assess the region of pagecache that we've just written back.  There
	 * are a number of possibilities: It could be unchanged, in which case
	 * we just erase the markers we left, or it could have been partially
	 * or totally overwritten, in which case we need to erase any places
	 * the markers show through and de-flag the overwrites.  If we de-flag
	 * some overwrites, we should try and merge with adjacent regions.
	 */
	mas_for_each(&mas, r, wreq->last) {
		if (netfs_mas_is_flushing(r)) {
			visible = true;
		} else {
			overlain = true;
			if (mas.index == wreq->first)
				merge_first = true;
			if (mas.last == wreq->last)
				merge_last = true;
		}
	}

	if (visible && !overlain) {
		_debug("not overwritten");
		mas_set_range(&mas, wreq->first, wreq->last);
		mas_store(&mas, NULL);
		goto done;
	}

	if (visible) {
		/* Some parts got overlain.  Just clear the flushing state on
		 * each redirtied region.  The edges may merge into the
		 * background if we null them.
		 *
		 * Flushed region pointers are converted to NULL and
		 * flush-to-cache markers to XA_ZERO_ENTRY.  This prevents them
		 * from merging at this point, which could require allocation.
		 *
		 * TODO: Consider doing this by tagging the pointer in the
		 * dirty region list.
		 */
		_debug("overlain, no-merge");
		mas_set_range(&mas, wreq->first, wreq->last);
		mas_for_each(&mas, r, wreq->last) {
			if (r == NETFS_FLUSH_TO_CACHE) {
				mas_store(&mas, XA_ZERO_ENTRY);
				created_xa_zero = true;
			} else if (netfs_mas_is_flushing(r)) {
				mas_store(&mas, NULL);
			} else {
				r->waiting_on_wb = NULL;
				wake_up_var(&r->waiting_on_wb);
			}
		}
		goto done;
	}

	/* If the edge regions are mergeable, then try to merge them with
	 * regions either side of the flushed region.
	 */
	if (no_merge)
		goto done;

	if (merge_first && wreq->first > 0) {
		mas_set(&mas, wreq->first);
		b = mas_walk(&mas);
		tmp = mas.last;
		a = mas_prev(&mas, wreq->first - 1);
		if (netfs_are_regions_mergeable(ctx, a, b)) {
			mas_set_range(&mas, mas.index, tmp);
			if (netfs_mas_is_valid(a))
				a->to = b->to;
			mas_store(&mas, a);
			to_put[0] = b;
		}
	}

	if (merge_last && wreq->last < ULONG_MAX) {
		mas_set(&mas, wreq->last);
		a = mas_walk(&mas);
		tmp = mas.index;
		b = mas_next(&mas, wreq->last + 1);
		if (netfs_are_regions_mergeable(ctx, a, b)) {
			mas_set_range(&mas, tmp, mas.last);
			if (netfs_mas_is_valid(a))
				a->to = b->to;
			mas_store(&mas, a);
			to_put[1] = b;
		}
	}

done:
	mtree_unlock(&ctx->dirty_regions);

	/* Erase any XA_ZERO_ENTRY marks - but we need to drop the lock each
	 * time to do allocation.
	 */
	if (created_xa_zero) {
		mas_expected_entries(&mas, 1);

		mtree_lock(&ctx->dirty_regions);
		mas_set(&mas, wreq->first);
		mas_for_each(&mas, r, wreq->last) {
			if (!netfs_mas_is_flushing(r)) {
				smp_store_release(&r->waiting_on_wb, NULL);
				wake_up_var(&r->waiting_on_wb);
				continue;
			}
			mas_erase(&mas);
			mas_pause(&mas);
			mtree_lock(&ctx->dirty_regions);
			mas_expected_entries(&mas, 1);
			cond_resched();
			mtree_unlock(&ctx->dirty_regions);
		}

		mtree_unlock(&ctx->dirty_regions);
	}

	mas_destroy(&mas);

	netfs_put_dirty_region(ctx, to_put[0], netfs_region_trace_put_merged);
	netfs_put_dirty_region(ctx, to_put[1], netfs_region_trace_put_merged);
}

/*
 * The write failed to some extent.  We need to work out which bits we managed
 * to do - for instance, we might have managed to write stuff to the cache, but
 * not upload to the server.
 */
static void netfs_redirty_range(struct netfs_io_request *wreq)
{
	trace_netfs_rreq(wreq, netfs_rreq_trace_redirty);
	BUG();
}

static void netfs_cleanup_buffered_write(struct netfs_io_request *wreq)
{
	if (wreq->error)
		netfs_redirty_range(wreq);
	else
		netfs_clean_dirty_range(wreq);
}

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

/*
 * Split the front off of the dirty region whose bounds are described by
 * mas->index and mas->last.  mas is left referring to the bounds of the front
 * region, a pointer to which is returned.
 */
static struct netfs_dirty_region *netfs_split_off_front(
	struct netfs_i_context *ctx,
	struct ma_state *mas,
	struct netfs_dirty_region *region,
	struct netfs_dirty_region **_spare,
	pgoff_t front_last,
	enum netfs_dirty_trace why)
{
	struct netfs_dirty_region *front = NETFS_COPY_TO_CACHE;

	if (region != NETFS_COPY_TO_CACHE) {
		front = *_spare;
		*_spare = NULL;

		front->debug_id = atomic_inc_return(&netfs_region_debug_ids);
		front->from	= region->from;
		front->to	= front_last * PAGE_SIZE;
		region->from	= front->to;

		_debug("front %04lx-%04lx %08llx-%08llx",
		       mas->index, front_last, front->from, front->to);
		_debug("tail  %04lx-%04lx %08llx-%08llx",
		       front_last + 1, mas->last, region->from, region->to);

		_debug("split D=%x from D=%x", front->debug_id, region->debug_id);

		if (ctx->ops->split_dirty_region)
			ctx->ops->split_dirty_region(front);

		list_add(&front->flush_link, &region->flush_link);
	}

	mas_set_range(mas, mas->index, front_last);
	mas_store(mas, front);

	trace_netfs_dirty(ctx, front == NETFS_COPY_TO_CACHE ? NULL : front,
			  region == NETFS_COPY_TO_CACHE ? NULL : region,
			  mas->index, mas->last, why);
	return front;
}

/*
 * Load pages into the writeback buffer.
 *
 * If this page holds new content, then we can include filler zeros in the
 * writeback.
 */
static int netfs_flush_get_pages(struct netfs_io_request *wreq,
				 struct netfs_i_context *ctx)
{
	struct folio_batch batch;
	struct folio *folio;
	void *x;
	unsigned int n, i = 0;
	pgoff_t indices[PAGEVEC_SIZE], first = wreq->first, index;
	int ret;

	folio_batch_init(&batch);

	_enter("%lx-%lx", first, wreq->last);

	do {
		/* Grab the folios that we're going to need from the pagecache
		 * a batch at a time.  There may be holes in what we get back,
		 * but that's fine.  We can fill those in later.
		 */
		n = find_get_entries(wreq->mapping, first, wreq->last,
				     &batch, indices);
		_debug("found %lx %u %lx", first, n, indices[0]);
		if (n == 0)
			break;

		for (i = 0; i < folio_batch_count(&batch); i++) {
			index = indices[i];

			if (first != index) {
				/* There's a hole in the pagecache, probably
				 * because the file got expanded by something
				 * like pwrite(), leaving a partial granule.
				 * We need to insert filler pages.
				 */
				BUG_ON(first > index || !ctx->cache_order);
				x = xa_store_range(&wreq->buffer, first, index - 1,
						   ZERO_PAGE(0), GFP_NOFS);
				if (xa_is_err(x)) {
					ret = xa_err(x);
					goto out;
				}
			}

			folio = batch.folios[i];
			_debug("- folio %lx", folio->index);
			ret = netfs_xa_store_and_mark(&wreq->buffer, folio->index,
						      folio, true, true, GFP_NOFS);
			if (ret < 0)
				goto out;

			first = folio_next_index(folio);
		}

		/* Don't release the batch - we're keeping the refs */
		cond_resched();
		folio_batch_init(&batch);
	} while (first <= wreq->last);

	if (first < wreq->last) {
		/* There's a trailing hole in the pagecache, probably because
		 * the block is at EOF.  We need to insert filler pages.
		 */
		x = xa_store_range(&wreq->buffer, first, wreq->last,
				   ZERO_PAGE(0), GFP_NOFS);
		if (xa_is_err(x)) {
			ret = xa_err(x);
			goto out;
		}
	}

	ret = 0;
out:
	for (; i < folio_batch_count(&batch); i++)
		folio_put(batch.folios[i]);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Lock the pages that we previously added to the writeback buffer.  The first
 * page is already locked.  We wait for locks on pages that lie in the middle
 * of granules, but we can cut short the range if we can't immediately lock the
 * first page in a granule.
 */
static void netfs_writeback_lock(struct netfs_io_request *wreq)
{
	struct folio *folio;

	XA_STATE(xas, &wreq->buffer, wreq->first);

	_enter("%lx-%lx", wreq->first, wreq->last);

	rcu_read_lock();
	xas_for_each_marked(&xas, folio, wreq->last, NETFS_BUF_PAGECACHE_MARK) {
		if (!folio_trylock(folio)) {
			xas_pause(&xas);
			rcu_read_unlock();
			folio_lock(folio);
			rcu_read_lock();
		}
	}
	rcu_read_unlock();
	return;
}

/*
 * Clear the dirty flags on the pages in the writeback buffer, mark them for
 * writeback and unlock them.
 */
static void netfs_writeback_start(struct netfs_io_request *wreq)
{
	struct folio *folio;
	unsigned long index;

	_enter("%lx-%lx", wreq->first, wreq->last);

	xa_for_each_marked(&wreq->buffer, index, folio, NETFS_BUF_PAGECACHE_MARK) {
		if (!folio_clear_dirty_for_io(folio))
			BUG();
		if (folio_start_writeback(folio))
			BUG();
		folio_unlock(folio);
	}
}

/*
 * Flush some of the dirty queue, transforming a part of a sequence of dirty
 * regions into a block we can flush.
 *
 * A number of things constrain us:
 *  - The region we write out should not be undergoing modification
 *  - We may need to expand or split the region for a number of reasons:
 *    - Filesystem storage block/object size
 *    - Filesystem RPC size (wsize)
 *    - Cache block size
 *    - Cache DIO block size
 *    - Crypto/compression block size
 *
 * This may be entered multiple times simultaneously.  Automatic flushing by
 * the VM is serialised on I_SYNC, but things like fsync() may enter multiple
 * times simultaneously.
 */
static int netfs_flush_dirty(struct netfs_io_request *wreq,
			     struct writeback_control *wbc,
			     struct netfs_i_context *ctx,
			     struct ma_state *mas,
			     pgoff_t *_first, pgoff_t last,
			     struct netfs_dirty_region *spares[2])
{
	struct netfs_dirty_region *region;
	struct folio *folio;
	unsigned long long end;
	pgoff_t first = *_first;
	pgoff_t csize = 1UL << ctx->cache_order;
	long ret;

	XA_STATE(xas, &wreq->mapping->i_pages, 0);

	/* Round out the range we're looking through to accommodate whole cache
	 * blocks.  The cache may only be able to store blocks of that size, in
	 * which case we may need to add non-dirty pages to the buffer too.
	 */
	if (ctx->cache_order) {
		first = round_down(first, csize);
		last = round_up_incl(last, csize);
	}

	_enter("%lx-%lx", first, last);

	rcu_read_lock();
	mtree_lock(&ctx->dirty_regions);

	/* Find the first dirty region that overlaps the requested range */
	mas_set(mas, first);
	do {
		region = mas_find(mas, last);
		if (!region)
			goto found_nothing;
	} while (netfs_mas_is_flushing(region) ||
		 (netfs_mas_is_valid(region) && region->waiting_on_wb));

	_debug("query D=%x %lx-%lx",
	       netfs_mas_is_valid(region) ? region->debug_id : 0,
	       mas->index, mas->last);

	wreq->first = max(mas->index, first);
	if (wreq->first > 0) {
		/* The first folio might extend backwards beyond the start of
		 * the proposed region - in which case we need to include that
		 * also.  But at least, in such a case, the folio size has to
		 * be an integer multiple of the cache blocksize.
		 */
		if (mas->index < wreq->first) {
			_debug("check folio %lx", wreq->first);
			xas_set(&xas, wreq->first);
			do {
				xas_reset(&xas);
				folio = xas_load(&xas);
			} while (xas_retry(&xas, folio));

			if (folio && !xa_is_value(folio)) {
				/* A region span *should not* end in the middle
				 * of a folio.
				 */
				BUG_ON(folio->index < mas->index);
				if (folio->index < wreq->first) {
					wreq->first = folio->index;
					mas_set_range(mas, wreq->first, mas->last);
				}
			}
		}

		if (mas->index < wreq->first) {
			pgoff_t saved_last = mas->last;
			_debug("splitf %lx-%lx %lx", mas->index, mas->last, first);
			netfs_split_off_front(ctx, mas, region, &spares[0], first - 1,
					      netfs_dirty_trace_split_off_front);
			mas_set_range(mas, first, saved_last);
		}

		wreq->last = mas->last;
	}


	end = wreq->start = wreq->first * PAGE_SIZE;
	while (mas->last < last) {
		_debug("flip %lx-%lx", mas->index, mas->last);
		wreq->last = mas->last;
		mas_store(mas, netfs_mas_set_flushing(region));
		if (region != NETFS_COPY_TO_CACHE) {
			__set_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags);
			list_add_tail(&region->flush_link, &wreq->regions);
			trace_netfs_dirty(ctx, region, 0, mas->index, mas->last,
					  netfs_dirty_trace_flush);
			end = region->to;
		}

		region = mas_next(mas, mas->last + 1);
		if (!region || netfs_mas_is_flushing(region) ||
		    region->waiting_on_wb)
			goto no_more;
		if (mas->last >= last)
			break;
		_debug("query+ D=%x %lx-%lx",
		       netfs_mas_is_valid(region) ? region->debug_id : 0,
		       mas->index, mas->last);
	}

	/* Deal with the region we're looking at exceeding the specified range.
	 * In such a case, we need to split the region - and the last folio may
	 * extend beyond the end of the proposed region - in which case we need
	 * to include that also.  And, again, the folio size has to be an
	 * integer multiple of the cache blocksize.
	 */
	if (mas->last > last) {
		xas_set(&xas, last);
		do {
			xas_reset(&xas);
			folio = xas_load(&xas);
		} while (xas_retry(&xas, folio));

		if (folio && !xa_is_value(folio)) {
			pgoff_t flast = folio_next_index(folio) - 1;

			_debug("flast %lx %lx %lx", flast, mas->last, last);
			/* A region span *should not* end in the middle of a folio. */
			BUG_ON(flast > mas->last);
			if (flast > last) {
				last = flast;
				mas_set_range(mas, mas->index, last);
			}
		}

		region = netfs_split_off_front(ctx, mas, region, &spares[1], last,
					       netfs_dirty_trace_split_off_back);
	}

	wreq->last = mas->last;
	mas_store(mas, netfs_mas_set_flushing(region));
	if (region != NETFS_COPY_TO_CACHE) {
		__set_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags);
		list_add_tail(&region->flush_link, &wreq->regions);
		trace_netfs_dirty(ctx, region, 0, mas->index, mas->last,
				  netfs_dirty_trace_flush2);
	}

no_more:
	/* We've now got a contiguous span.  Some of the subspans may only need
	 * writing to the cache, whilst others need writing to both the server
	 * and the cache.
	 */
	_debug("span %lx-%lx", wreq->first, wreq->last);
	*_first = last + 1;
	mtree_unlock(&ctx->dirty_regions);
	rcu_read_unlock();

	if (wreq->i_size > end)
		end = min_t(unsigned long long, wreq->i_size, (wreq->last + 1) * PAGE_SIZE);
	wreq->len = end - wreq->start;

	/* Load the pages into the raw-data buffer and transition them over to
	 * the writeback state.
	 */
	ret = netfs_flush_get_pages(wreq, ctx);
	if (ret < 0)
		goto undo;

	if (wreq->buffering == NETFS_ENC_BUFFER_TO_BOUNCE) {
		ret = netfs_alloc_buffer(&wreq->bounce, wreq->first,
					 wreq->last - wreq->first + 1);
		if (ret < 0)
			goto undo;
	}

	netfs_writeback_lock(wreq);
	netfs_writeback_start(wreq);

	wbc->nr_to_write -= wreq->last - wreq->first + 1;
	*_first = wreq->last + 1;
	_leave(" = %lx [%lx]", wreq->last - wreq->first + 1, *_first);
	return 1;

found_nothing:
	*_first = last + 1;
	mtree_unlock(&ctx->dirty_regions);
	rcu_read_unlock();
	return 0;

undo:
	BUG(); // TODO
}

/*
 * Flush a range of pages.
 */
static int netfs_flush_range(struct address_space *mapping,
			     struct writeback_control *wbc,
			     pgoff_t *_first, pgoff_t last)
{
	struct netfs_dirty_region *spares[2] = {};
	struct netfs_io_request *wreq = NULL;
	struct netfs_i_context *ctx = netfs_i_context(mapping->host);
	long ret;

	MA_STATE(mas, &ctx->dirty_regions, *_first, last);

	_enter("%lx-%lx", *_first, last);

retry:
	/* Preallocate the space we need in the list of dirty regions.  We may
	 * need to split the region(s) overlapping either end of the range.
	 */
	ret = mas_expected_entries(&mas, 2);
	if (ret < 0)
		return ret;

	ret = -ENOMEM;
	if (!spares[0]) {
		spares[0] = netfs_alloc_dirty_region();
		if (!spares[0])
			goto out_unlocked;
	}
	if (!spares[1]) {
		spares[1] = netfs_alloc_dirty_region();
		if (!spares[1])
			goto out_unlocked;
	}

	ret = netfs_wait_for_credit(wbc);
	if (ret < 0)
		goto out_unlocked;

	if (!wreq) {
		ret = -ENOMEM;
		wreq = netfs_alloc_request(mapping, NULL, 0, 0, NETFS_WRITEBACK);
		if (!wreq)
			goto out_unlocked;
		wreq->cleanup = netfs_cleanup_buffered_write;
		wreq->buffering = NETFS_BUFFER;
		if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags))
			wreq->buffering = NETFS_ENC_BUFFER_TO_BOUNCE;
	}

	ret = netfs_flush_dirty(wreq, wbc, ctx, &mas, _first, last, spares);
	switch (ret) {
	case -ENOBUFS:
		goto need_spares;
	case -EAGAIN:
		//goto retry;
		goto out_unlocked;
	default:
		goto out_unlocked;
	case 1:
		break;
	}

	/* Finish preparing the write request. */
	ret = netfs_begin_write(wreq, wbc->sync_mode != WB_SYNC_NONE);

	wreq = NULL;

	/* Flush more. */
	if (wbc->nr_to_write <= 0)
		goto out_unlocked;
	if (*_first >= last)
		goto out_unlocked;
	_debug("go again");
	goto retry;

out_unlocked:
	netfs_free_dirty_region(ctx, spares[0]);
	netfs_free_dirty_region(ctx, spares[1]);
	netfs_put_request(wreq, false, netfs_rreq_trace_put_discard);
	mas_destroy(&mas);
	return ret;
need_spares:
	ret = -ENOMEM;
	if (!spares[0]) {
		spares[0] = netfs_alloc_dirty_region();
		if (!spares[0])
			goto out_unlocked;
	}
	if (!spares[1]) {
		spares[1] = netfs_alloc_dirty_region();
		if (!spares[1])
			goto out_unlocked;
	}
	goto retry;
}

/**
 * netfs_writepages - Initiate writeback to the server and cache
 * @mapping: The pagecache to write from
 * @wbc: Hints from the VM as to what to write
 *
 * This is a helper intended to be called directly from a network filesystem's
 * address space operations table to perform writeback to the server and the
 * cache.
 *
 * We have to be careful as we can end up racing with setattr() truncating the
 * pagecache since the caller doesn't take a lock here to prevent it.
 */
int netfs_writepages(struct address_space *mapping,
		     struct writeback_control *wbc)
{
	struct netfs_i_context *ctx = netfs_i_context(mapping->host);
	unsigned long nr_to_write = wbc->nr_to_write;
	pgoff_t min_bsize = min_t(pgoff_t, (1UL << ctx->min_bshift) / PAGE_SIZE, 1);
	pgoff_t first, last;
	int ret;

	_enter("%lx,%llx-%llx,%u,%c%c%c%c,%u,%u",
	       wbc->nr_to_write,
	       wbc->range_start, wbc->range_end,
	       wbc->sync_mode,
	       wbc->for_kupdate		? 'k' : '-',
	       wbc->for_background	? 'b' : '-',
	       wbc->for_reclaim		? 'r' : '-',
	       wbc->for_sync		? 's' : '-',
	       wbc->tagged_writepages,
	       wbc->range_cyclic);

	if (wbc->range_cyclic) {
		first = round_down(mapping->writeback_index, min_bsize);
		last  = ULONG_MAX;
		ret = netfs_flush_range(mapping, wbc, &first, last);
		if (ret == 0 && first > 0 && wbc->nr_to_write > 0) {
			last  = first - 1;
			first = 0;
			ret = netfs_flush_range(mapping, wbc, &first, last);
		}
		mapping->writeback_index = first;
	} else {
		first = wbc->range_start / PAGE_SIZE;
		last  = wbc->range_end / PAGE_SIZE;
		ret = netfs_flush_range(mapping, wbc, &first, last);
	}

	_leave(" = %d [%lx/%lx]", ret, wbc->nr_to_write, nr_to_write);
	if (ret == -EBUSY)
		ret = 0;
	return ret;
}
EXPORT_SYMBOL(netfs_writepages);
