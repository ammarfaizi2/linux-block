// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem high-level write support.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include "internal.h"

static bool __within(unsigned long long start1, unsigned long long end1,
		     unsigned long long start2, unsigned long long end2)
{
	return start1 >= start2 && end1 <= end2;
}

static bool within(struct netfs_range *a, struct netfs_range *b)
{
	return __within(a->start, a->end, b->start, b->end);
}

static int netfs_redirty_iterator(struct xa_state *xas, struct page *page)
{
	__set_page_dirty_nobuffers(page);
	account_page_redirty(page);
	end_page_writeback(page);
	return 0;
}

/*
 * Redirty all the pages in a given range.
 */
static void netfs_redirty_pages(struct netfs_write_request *wreq)
{
	_enter("%lx-%lx", wreq->first, wreq->last);

	netfs_iterate_pinned_pages(wreq->mapping, wreq->first, wreq->last,
				   netfs_redirty_iterator);
	_leave("");
}

static int netfs_end_writeback_iterator(struct xa_state *xas, struct page *page,
					struct netfs_write_request *wreq,
					struct netfs_i_context *ctx)
{
	struct netfs_dirty_region *region = wreq->region, *r;
	struct netfs_range range;
	bool clear_wb = true;

	range.start = page_offset(page);
	range.end   = range.start + thp_size(page);

	/* Now we need to clear the wb flags on any page that's not shared with
	 * any other region undergoing writing.
	 */
	if (within(&range, &region->dirty)) {
		end_page_writeback(page);
		return 0;
	}

	spin_lock(&ctx->lock);
	if (range.start < region->dirty.start) {
		r = region;
		list_for_each_entry_continue_reverse(r, &ctx->dirty_regions, dirty_link) {
			if (r->dirty.end <= range.start)
				break;
			if (r->state < NETFS_REGION_IS_FLUSHING)
				continue;
			kdebug("keep-wback-b %lx reg=%x r=%x W=%x",
			       page->index, region->debug_id, r->debug_id, wreq->debug_id);
			clear_wb = false;
		}
	}

	if (range.end > region->dirty.end) {
		r = region;
		list_for_each_entry_continue(r, &ctx->dirty_regions, dirty_link) {
			if (r->dirty.start >= range.end)
				break;
			if (r->state < NETFS_REGION_IS_FLUSHING)
				continue;
			kdebug("keep-wback-f %lx reg=%x r=%x W=%x",
			       page->index, region->debug_id, r->debug_id, wreq->debug_id);
			clear_wb = false;
		}
	}

	if (clear_wb)
		end_page_writeback(page);
	spin_unlock(&ctx->lock);
	return 0;
}

/*
 * Fix up the dirty list upon completion of write.
 */
static void netfs_fix_up_dirty_list(struct netfs_write_request *wreq)
{
	struct netfs_dirty_region *region = wreq->region, *r;
	struct netfs_i_context *ctx = netfs_i_context(wreq->inode);
	unsigned long long available_to;
	struct list_head *lower, *upper, *p;

	netfs_iterate_pinned_pages(wreq->mapping, wreq->first, wreq->last,
				   netfs_end_writeback_iterator, wreq, ctx);

	spin_lock(&ctx->lock);

	/* Find the bounds of the region we're going to make available. */
	lower = &ctx->dirty_regions;
	r = region;
	list_for_each_entry_continue_reverse(r, &ctx->dirty_regions, dirty_link) {
		_debug("- back %x", r->debug_id);
		if (r->state >= NETFS_REGION_IS_DIRTY) {
			lower = &r->dirty_link;
			break;
		}
	}

	available_to = ULLONG_MAX;
	upper = &ctx->dirty_regions;
	r = region;
	list_for_each_entry_continue(r, &ctx->dirty_regions, dirty_link) {
		_debug("- forw %x", r->debug_id);
		if (r->state >= NETFS_REGION_IS_DIRTY) {
			available_to = r->dirty.start;
			upper = &r->dirty_link;
			break;
		}
	}

	/* Remove this region and we can start any waiters that are wholly
	 * inside of the now-available region.
	 */
	list_del_init(&region->dirty_link);

	for (p = lower->next; p != upper; p = p->next) {
		r = list_entry(p, struct netfs_dirty_region, dirty_link);
		if (r->reserved.end <= available_to) {
			smp_store_release(&r->state, NETFS_REGION_IS_ACTIVE);
			trace_netfs_dirty(ctx, r, NULL, netfs_dirty_trace_activate);
			wake_up_var(&r->state);
		}
	}

	spin_unlock(&ctx->lock);
	netfs_put_dirty_region(ctx, region, netfs_region_trace_put_dirty);
}

/*
 * Process a completed write request once all the component streams have been
 * completed.
 */
static void netfs_write_completed(struct netfs_write_request *wreq, bool was_async)
{
	struct netfs_i_context *ctx = netfs_i_context(wreq->inode);
	unsigned int s;

	for (s = 0; s < wreq->n_streams; s++) {
		struct netfs_write_stream *stream = &wreq->streams[s];
		if (!stream->error)
			continue;
		switch (stream->dest) {
		case NETFS_UPLOAD_TO_SERVER:
			/* Depending on the type of failure, this may prevent
			 * writeback completion unless we're in disconnected
			 * mode.
			 */
			if (!wreq->error)
				wreq->error = stream->error;
			break;

		case NETFS_WRITE_TO_CACHE:
			/* Failure doesn't prevent writeback completion unless
			 * we're in disconnected mode.
			 */
			if (stream->error != -ENOBUFS)
				ctx->ops->invalidate_cache(wreq);
			break;

		default:
			WARN_ON_ONCE(1);
			if (!wreq->error)
				wreq->error = -EIO;
			return;
		}
	}

	if (wreq->error)
		netfs_redirty_pages(wreq);
	else
		netfs_fix_up_dirty_list(wreq);
	netfs_put_write_request(wreq, was_async, netfs_wreq_trace_put_for_outstanding);
}

/*
 * Deal with the completion of writing the data to the cache.
 */
void netfs_write_stream_completed(void *_stream, ssize_t transferred_or_error,
				  bool was_async)
{
	struct netfs_write_stream *stream = _stream;
	struct netfs_write_request *wreq = netfs_stream_to_wreq(stream);

	if (IS_ERR_VALUE(transferred_or_error))
		stream->error = transferred_or_error;
	switch (stream->dest) {
	case NETFS_UPLOAD_TO_SERVER:
		if (stream->error)
			netfs_stat(&netfs_n_wh_upload_failed);
		else
			netfs_stat(&netfs_n_wh_upload_done);
		break;
	case NETFS_WRITE_TO_CACHE:
		if (stream->error)
			netfs_stat(&netfs_n_wh_write_failed);
		else
			netfs_stat(&netfs_n_wh_write_done);
		break;
	case NETFS_INVALID_WRITE:
		break;
	}

	trace_netfs_wstr(stream, netfs_write_stream_complete);
	if (atomic_dec_and_test(&wreq->outstanding))
		netfs_write_completed(wreq, was_async);
}
EXPORT_SYMBOL(netfs_write_stream_completed);

static void netfs_write_to_cache_stream(struct netfs_write_stream *stream,
					struct netfs_write_request *wreq)
{
	trace_netfs_wstr(stream, netfs_write_stream_submit);
	fscache_write_to_cache(netfs_i_cookie(wreq->inode), wreq->mapping,
			       wreq->start, wreq->len, wreq->region->i_size,
			       netfs_write_stream_completed, stream);
}

static void netfs_write_to_cache_stream_worker(struct work_struct *work)
{
	struct netfs_write_stream *stream = container_of(work, struct netfs_write_stream, work);
	struct netfs_write_request *wreq = netfs_stream_to_wreq(stream);

	netfs_write_to_cache_stream(stream, wreq);
	netfs_put_write_request(wreq, false, netfs_wreq_trace_put_stream_work);
}

/**
 * netfs_set_up_write_stream - Allocate, set up and launch a write stream.
 * @wreq: The write request this is storing from.
 * @dest: The destination type
 * @worker: The worker function to handle the write(s)
 *
 * Allocate the next write stream from a write request and queue the worker to
 * make it happen.
 */
void netfs_set_up_write_stream(struct netfs_write_request *wreq,
			       enum netfs_write_dest dest, work_func_t worker)
{
	struct netfs_write_stream *stream;
	unsigned int s = wreq->n_streams++;

	kenter("%u,%u", s, dest);

	stream		= &wreq->streams[s];
	stream->dest	= dest;
	stream->index	= s;
	INIT_WORK(&stream->work, worker);
	atomic_inc(&wreq->outstanding);
	trace_netfs_wstr(stream, netfs_write_stream_setup);

	switch (stream->dest) {
	case NETFS_UPLOAD_TO_SERVER:
		netfs_stat(&netfs_n_wh_upload);
		break;
	case NETFS_WRITE_TO_CACHE:
		netfs_stat(&netfs_n_wh_write);
		break;
	case NETFS_INVALID_WRITE:
		BUG();
	}

	netfs_get_write_request(wreq, netfs_wreq_trace_get_stream_work);
	if (!queue_work(system_unbound_wq, &stream->work))
		netfs_put_write_request(wreq, false, netfs_wreq_trace_put_wip);
}
EXPORT_SYMBOL(netfs_set_up_write_stream);

/*
 * Set up a stream for writing to the cache.
 */
static void netfs_set_up_write_to_cache(struct netfs_write_request *wreq)
{
	netfs_set_up_write_stream(wreq, NETFS_WRITE_TO_CACHE,
				  netfs_write_to_cache_stream_worker);
}

/*
 * Process a write request.
 *
 * All the pages in the bounding box have had a ref taken on them and those
 * covering the dirty region have been marked as being written back and their
 * dirty bits provisionally cleared.
 */
static void netfs_writeback(struct netfs_write_request *wreq)
{
	struct netfs_i_context *ctx = netfs_i_context(wreq->inode);

	kenter("");

	/* TODO: Encrypt or compress the region as appropriate */

	/* ->outstanding > 0 carries a ref */
	netfs_get_write_request(wreq, netfs_wreq_trace_get_for_outstanding);

	if (test_bit(NETFS_WREQ_WRITE_TO_CACHE, &wreq->flags))
		netfs_set_up_write_to_cache(wreq);
	ctx->ops->add_write_streams(wreq);
	if (atomic_dec_and_test(&wreq->outstanding))
		netfs_write_completed(wreq, false);
}

void netfs_writeback_worker(struct work_struct *work)
{
	struct netfs_write_request *wreq =
		container_of(work, struct netfs_write_request, work);

	netfs_see_write_request(wreq, netfs_wreq_trace_see_work);
	netfs_writeback(wreq);
	netfs_put_write_request(wreq, false, netfs_wreq_trace_put_work);
}

/*
 * Flush some of the dirty queue.
 */
static int netfs_flush_dirty(struct address_space *mapping,
			     struct writeback_control *wbc,
			     struct netfs_range *range,
			     loff_t *next)
{
	struct netfs_dirty_region *p, *q;
	struct netfs_i_context *ctx = netfs_i_context(mapping->host);

	kenter("%llx-%llx", range->start, range->end);

	spin_lock(&ctx->lock);

	/* Scan forwards to find dirty regions containing the suggested start
	 * point.
	 */
	list_for_each_entry_safe(p, q, &ctx->dirty_regions, dirty_link) {
		_debug("D=%x %llx-%llx", p->debug_id, p->dirty.start, p->dirty.end);
		if (p->dirty.end <= range->start)
			continue;
		if (p->dirty.start >= range->end)
			break;
		if (p->state != NETFS_REGION_IS_DIRTY)
			continue;
		if (test_bit(NETFS_REGION_FLUSH_Q, &p->flags))
			continue;

		netfs_flush_region(ctx, p, netfs_dirty_trace_flush_writepages);
	}

	spin_unlock(&ctx->lock);
	return 0;
}

static int netfs_unlock_pages_iterator(struct page *page)
{
	unlock_page(page);
	put_page(page);
	return 0;
}

/*
 * Unlock all the pages in a range.
 */
static void netfs_unlock_pages(struct address_space *mapping,
			       pgoff_t start, pgoff_t end)
{
	netfs_iterate_pages(mapping, start, end, netfs_unlock_pages_iterator);
}

static int netfs_lock_pages_iterator(struct xa_state *xas,
				     struct page *page,
				     struct netfs_write_request *wreq,
				     struct writeback_control *wbc)
{
	int ret;

	/* At this point we hold neither the i_pages lock nor the
	 * page lock: the page may be truncated or invalidated
	 * (changing page->mapping to NULL), or even swizzled
	 * back from swapper_space to tmpfs file mapping
	 */
	if (wbc->sync_mode != WB_SYNC_NONE) {
		xas_pause(xas);
		rcu_read_unlock();
		ret = lock_page_killable(page);
		rcu_read_lock();
	} else {
		if (!trylock_page(page))
			ret = -EBUSY;
	}

	return ret;
}

/*
 * Lock all the pages in a range and add them to the write request.
 */
static int netfs_lock_pages(struct address_space *mapping,
			    struct writeback_control *wbc,
			    struct netfs_write_request *wreq)
{
	pgoff_t last = wreq->last;
	int ret;

	_enter("%lx-%lx", wreq->first, wreq->last);
	ret = netfs_iterate_get_pages(mapping, wreq->first, wreq->last,
				      netfs_lock_pages_iterator, wreq, wbc);
	if (ret < 0) {
		netfs_see_write_request(wreq, netfs_wreq_trace_see_lock_conflict);
		goto failed;
	}

	if (wreq->last < last) {
		kdebug("Some pages missing %lx < %lx", wreq->last, last);
		netfs_see_write_request(wreq, netfs_wreq_trace_see_pages_missing);
		ret = -EIO;
		goto failed;
	}

	return 0;

failed:
	netfs_unlock_pages(mapping, wreq->first, wreq->last);
	return ret;
}

static int netfs_set_page_writeback(struct page *page,
				    struct netfs_i_context *ctx,
				    struct netfs_write_request *wreq)
{
	struct netfs_dirty_region *region = wreq->region, *r;
	enum netfs_region_state state;
	struct netfs_range range;
	bool clear_dirty = true;

	range.start = page_offset(page);
	range.end   = range.start + thp_size(page);

	/* Now we need to clear the dirty flags on any page that's not shared
	 * with any other dirty region.
	 */
	if (within(&range, &region->dirty))
		goto completely_inside;

	spin_lock(&ctx->lock);
	if (range.start < region->dirty.start) {
		r = region;
		list_for_each_entry_continue_reverse(r, &ctx->dirty_regions, dirty_link) {
			kdebug("maybe-b %lx reg=%x r=%x W=%x",
			       page->index, region->debug_id, r->debug_id, wreq->debug_id);
			if (r->dirty.end <= range.start)
				break;
			state = READ_ONCE(r->state);
			if (state != NETFS_REGION_IS_ACTIVE &&
			    state != NETFS_REGION_IS_DIRTY)
				continue;
			kdebug("keep-dirty-b %lx reg=%x r=%x W=%x",
			       page->index, region->debug_id, r->debug_id, wreq->debug_id);
			clear_dirty = false;
		}
	}

	if (range.end > region->dirty.end) {
		r = region;
		list_for_each_entry_continue(r, &ctx->dirty_regions, dirty_link) {
			kdebug("maybe-f %lx reg=%x r=%x W=%x",
			       page->index, region->debug_id, r->debug_id, wreq->debug_id);
			if (r->dirty.start >= range.end)
				break;
			state = READ_ONCE(r->state);
			if (state != NETFS_REGION_IS_ACTIVE &&
			    state != NETFS_REGION_IS_DIRTY)
				continue;
			kdebug("keep-dirty-f %lx reg=%x r=%x W=%x",
			       page->index, region->debug_id, r->debug_id, wreq->debug_id);
			clear_dirty = false;
		}
	}
	spin_unlock(&ctx->lock);
	if (!clear_dirty) {
		kdebug("no-clear-dirty %lx", page->index);
		goto no_clear;
	}

completely_inside:
	if (!clear_page_dirty_for_io(page)) {
		pr_err("page %lx is not dirty W=%x", page->index, wreq->debug_id);
		BUG();
	}

no_clear:
	/* We set writeback unconditionally because a page may participate in
	 * more than one simultaneous writeback.
	 */
	set_page_writeback(page);
	return 0;
}

/*
 * Extract a region to write back.
 */
static struct netfs_dirty_region *netfs_extract_dirty_region(
	struct netfs_i_context *ctx,
	struct netfs_write_request *wreq)
{
	struct netfs_dirty_region *region = NULL, *spare;

	spare = netfs_alloc_dirty_region();
	if (!spare)
		return NULL;

	spin_lock(&ctx->lock);

	if (list_empty(&ctx->flush_queue))
		goto out;

	region = list_first_entry(&ctx->flush_queue,
				  struct netfs_dirty_region, flush_link);

	wreq->region = netfs_get_dirty_region(ctx, region, netfs_region_trace_get_wreq);
	wreq->start  = region->dirty.start;
	wreq->len    = region->dirty.end - region->dirty.start;
	wreq->first  =  region->dirty.start    / PAGE_SIZE;
	wreq->last   = (region->dirty.end - 1) / PAGE_SIZE;

	/* TODO: Split the region if it's larger than a certain size.  This is
	 * tricky as we need to observe page, crypto and compression block
	 * boundaries.  The crypto/comp bounds are defined by ctx->bsize, but
	 * we don't know where the page boundaries are.
	 *
	 * All of these boundaries, however, must be pow-of-2 sized and
	 * pow-of-2 aligned, so they never partially overlap
	 */

	smp_store_release(&region->state, NETFS_REGION_IS_FLUSHING);
	trace_netfs_dirty(ctx, region, NULL, netfs_dirty_trace_flushing);
	wake_up_var(&region->state);
	list_del_init(&region->flush_link);

out:
	spin_unlock(&ctx->lock);
	netfs_free_dirty_region(ctx, spare);
	kleave(" = D=%x", region ? region->debug_id : 0);
	return region;
}

/*
 * Schedule a write for the first region on the flush queue.
 */
static int netfs_begin_write(struct address_space *mapping,
			     struct writeback_control *wbc)
{
	struct netfs_write_request *wreq;
	struct netfs_dirty_region *region;
	struct netfs_i_context *ctx = netfs_i_context(mapping->host);
	int ret;

	wreq = netfs_alloc_write_request(mapping, false);
	if (!wreq)
		return -ENOMEM;

	ret = 0;
	region = netfs_extract_dirty_region(ctx, wreq);
	if (!region)
		goto error;

	ret = netfs_lock_pages(mapping, wbc, wreq);
	if (ret < 0)
		goto error;

	trace_netfs_wreq(wreq);

	netfs_iterate_pages(mapping, wreq->first, wreq->last,
			    netfs_set_page_writeback, ctx, wreq);
	netfs_unlock_pages(mapping, wreq->first, wreq->last);
	iov_iter_xarray(&wreq->source, WRITE, &wreq->mapping->i_pages,
			wreq->start, wreq->len);

	if (!queue_work(system_unbound_wq, &wreq->work))
		BUG();

	kleave(" = %lu", wreq->last - wreq->first + 1);
	return wreq->last - wreq->first + 1;

error:
	netfs_put_write_request(wreq, wbc->sync_mode != WB_SYNC_NONE,
				netfs_wreq_trace_put_discard);
	kleave(" = %d", ret);
	return ret;
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
	struct netfs_range range;
	loff_t next;
	int ret;

	kenter("%lx,%llx-%llx,%u,%c%c%c%c,%u,%u",
	       wbc->nr_to_write,
	       wbc->range_start, wbc->range_end,
	       wbc->sync_mode,
	       wbc->for_kupdate		? 'k' : '-',
	       wbc->for_background	? 'b' : '-',
	       wbc->for_reclaim		? 'r' : '-',
	       wbc->for_sync		? 's' : '-',
	       wbc->tagged_writepages,
	       wbc->range_cyclic);

	//dump_stack();

	if (wbc->range_cyclic) {
		range.start = mapping->writeback_index * PAGE_SIZE;
		range.end   = ULLONG_MAX;
		ret = netfs_flush_dirty(mapping, wbc, &range, &next);
		if (range.start > 0 && wbc->nr_to_write > 0 && ret == 0) {
			range.start = 0;
			range.end   = mapping->writeback_index * PAGE_SIZE;
			ret = netfs_flush_dirty(mapping, wbc, &range, &next);
		}
		mapping->writeback_index = next / PAGE_SIZE;
	} else if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX) {
		range.start = 0;
		range.end   = ULLONG_MAX;
		ret = netfs_flush_dirty(mapping, wbc, &range, &next);
		if (wbc->nr_to_write > 0 && ret == 0)
			mapping->writeback_index = next;
	} else {
		range.start = wbc->range_start;
		range.end   = wbc->range_end + 1;
		ret = netfs_flush_dirty(mapping, wbc, &range, &next);
	}

	if (ret == 0)
		ret = netfs_begin_write(mapping, wbc);

	_leave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(netfs_writepages);
