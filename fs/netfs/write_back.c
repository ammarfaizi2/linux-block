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

/*
 * Process a write request.
 */
static void netfs_writeback(struct netfs_write_request *wreq)
{
	kdebug("--- WRITE ---");
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

static int netfs_set_page_writeback(struct page *page)
{
	/* Now we need to clear the dirty flags on any page that's not shared
	 * with any other dirty region.
	 */
	if (!clear_page_dirty_for_io(page))
		BUG();

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
			    netfs_set_page_writeback);
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
