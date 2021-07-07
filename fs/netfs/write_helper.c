// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem high-level write support.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include "internal.h"

static atomic_t netfs_region_debug_ids;

static bool __overlaps(unsigned long long start1, unsigned long long end1,
		       unsigned long long start2, unsigned long long end2)
{
	return (start1 < start2) ? end1 > start2 : end2 > start1;
}

static bool overlaps(struct netfs_range *a, struct netfs_range *b)
{
	return __overlaps(a->start, a->end, b->start, b->end);
}

static int wait_on_region(struct netfs_dirty_region *region,
			  enum netfs_region_state state)
{
	return wait_var_event_interruptible(&region->state,
					    READ_ONCE(region->state) >= state);
}

/*
 * Grab a page for writing.  We don't lock it at this point as we have yet to
 * preemptively trigger a fault-in - but we need to know how large the page
 * will be before we try that.
 */
static struct page *netfs_grab_page_for_write(struct address_space *mapping,
					      loff_t pos, size_t len_remaining)
{
	struct page *page;
	int fgp_flags = FGP_LOCK | FGP_WRITE | FGP_CREAT;

	page = pagecache_get_page(mapping, pos >> PAGE_SHIFT, fgp_flags,
				  mapping_gfp_mask(mapping));
	if (!page)
		return ERR_PTR(-ENOMEM);
	wait_for_stable_page(page);
	return page;
}

/*
 * Initialise a new dirty page group.  The caller is responsible for setting
 * the type and any flags that they want.
 */
static void netfs_init_dirty_region(struct netfs_dirty_region *region,
				    struct inode *inode, struct file *file,
				    enum netfs_region_type type,
				    unsigned long flags,
				    loff_t start, loff_t end)
{
	struct netfs_flush_group *group;
	struct netfs_i_context *ctx = netfs_i_context(inode);

	region->state		= NETFS_REGION_IS_PENDING;
	region->type		= type;
	region->flags		= flags;
	region->reserved.start	= start;
	region->reserved.end	= end;
	region->dirty.start	= start;
	region->dirty.end	= start;
	region->bounds.start	= round_down(start, ctx->bsize);
	region->bounds.end	= round_up(end, ctx->bsize);
	region->i_size		= i_size_read(inode);
	region->debug_id	= atomic_inc_return(&netfs_region_debug_ids);
	INIT_LIST_HEAD(&region->active_link);
	INIT_LIST_HEAD(&region->dirty_link);
	INIT_LIST_HEAD(&region->flush_link);
	refcount_set(&region->ref, 1);
	spin_lock_init(&region->lock);
	if (type == NETFS_REGION_CACHE_COPY) {
		region->state = NETFS_REGION_IS_DIRTY;
		region->dirty.end = end;
	}

	if (file && ctx->ops->init_dirty_region)
		ctx->ops->init_dirty_region(region, file);
	if (!region->group) {
		group = list_last_entry(&ctx->flush_groups,
					struct netfs_flush_group, group_link);
		region->group = netfs_get_flush_group(group);
		spin_lock(&ctx->lock);
		list_add_tail(&region->flush_link, &group->region_list);
		spin_unlock(&ctx->lock);
	}
	trace_netfs_ref_region(region->debug_id, 1, netfs_region_trace_new);
	trace_netfs_dirty(ctx, region, NULL, netfs_dirty_trace_new);
	netfs_proc_add_region(region);
}

/*
 * Queue a region for flushing.  Regions may need to be flushed in the right
 * order (e.g. ceph snaps) and so we may need to chuck other regions onto the
 * flush queue first.
 *
 * The caller must hold ctx->lock.
 */
void netfs_flush_region(struct netfs_i_context *ctx,
			struct netfs_dirty_region *region,
			enum netfs_dirty_trace why)
{
	struct netfs_flush_group *group;

	LIST_HEAD(flush_queue);

	_enter("%x", region->debug_id);

	if (test_bit(NETFS_REGION_FLUSH_Q, &region->flags) ||
	    region->group->flush)
		return;

	trace_netfs_dirty(ctx, region, NULL, why);

	/* If the region isn't in the bottom flush group, we need to flush out
	 * all of the flush groups below it.
	 */
	while (!list_is_first(&region->group->group_link, &ctx->flush_groups)) {
		group = list_first_entry(&ctx->flush_groups,
					 struct netfs_flush_group, group_link);
		group->flush = true;
		list_del_init(&group->group_link);
		list_splice_tail_init(&group->region_list, &ctx->flush_queue);
		netfs_put_flush_group(group);
	}

	set_bit(NETFS_REGION_FLUSH_Q, &region->flags);
	list_move_tail(&region->flush_link, &ctx->flush_queue);
}

/*
 * Decide if/how a write can be merged with a dirty region.
 */
static enum netfs_write_compatibility netfs_write_compatibility(
	struct netfs_i_context *ctx,
	struct netfs_dirty_region *old,
	struct netfs_dirty_region *candidate)
{
	/* Regions being actively flushed can't be merged with */
	if (old->state >= NETFS_REGION_IS_FLUSHING ||
	    candidate->group != old->group ||
	    old->group->flush) {
		_leave(" = INCOM [flush]");
		return NETFS_WRITES_INCOMPATIBLE;
	}

	/* The bounding boxes of DSYNC writes can overlap with those of other
	 * DSYNC writes and ordinary writes.  DIO writes cannot overlap at all.
	 */
	if (candidate->type == NETFS_REGION_DIO ||
	    old->type == NETFS_REGION_DIO ||
	    old->type == NETFS_REGION_DSYNC) {
		_leave(" = INCOM [dio/dsy]");
		return NETFS_WRITES_INCOMPATIBLE;
	}

	/* Pending writes to the cache alone (ie. copy from a read) can be
	 * merged or superseded by a modification that will require writing to
	 * the server too.
	 */
	if (old->type == NETFS_REGION_CACHE_COPY) {
		if (candidate->type == NETFS_REGION_CACHE_COPY) {
			_leave(" = COMPT [ccopy]");
			return NETFS_WRITES_COMPATIBLE;
		}
		_leave(" = SUPER [ccopy]");
		return NETFS_WRITES_SUPERSEDE;
	}

	if (!ctx->ops->is_write_compatible) {
		if (candidate->type == NETFS_REGION_DSYNC) {
			_leave(" = SUPER [dsync]");
			return NETFS_WRITES_SUPERSEDE;
		}
		_leave(" = COMPT");
		return NETFS_WRITES_COMPATIBLE;
	}
	return ctx->ops->is_write_compatible(ctx, old, candidate);
}

/*
 * Split a dirty region.
 */
static struct netfs_dirty_region *netfs_split_dirty_region(
	struct netfs_i_context *ctx,
	struct netfs_dirty_region *region,
	struct netfs_dirty_region **spare,
	unsigned long long pos)
{
	struct netfs_dirty_region *tail = *spare;

	*spare = NULL;
	*tail = *region;
	region->dirty.end = pos;
	tail->dirty.start = pos;
	tail->debug_id = atomic_inc_return(&netfs_region_debug_ids);

	refcount_set(&tail->ref, 1);
	INIT_LIST_HEAD(&tail->active_link);
	netfs_get_flush_group(tail->group);
	spin_lock_init(&tail->lock);
	// TODO: grab cache resources

	// need to split the bounding box?
	__set_bit(NETFS_REGION_SUPERSEDED, &tail->flags);
	if (ctx->ops->split_dirty_region)
		ctx->ops->split_dirty_region(tail);
	list_add(&tail->dirty_link, &region->dirty_link);
	list_add(&tail->flush_link, &region->flush_link);
	trace_netfs_dirty(ctx, tail, region, netfs_dirty_trace_split);
	netfs_proc_add_region(tail);
	return tail;
}

/*
 * Queue a write for access to the pagecache.  The caller must hold ctx->lock.
 * The NETFS_REGION_PENDING flag will be cleared when it's possible to proceed.
 */
static void netfs_queue_write(struct netfs_i_context *ctx,
			      struct netfs_dirty_region *candidate)
{
	struct netfs_dirty_region *r;
	struct list_head *p;

	/* We must wait for any overlapping pending writes */
	list_for_each_entry(r, &ctx->pending_writes, active_link) {
		if (overlaps(&candidate->bounds, &r->bounds)) {
			if (overlaps(&candidate->reserved, &r->reserved) ||
			    netfs_write_compatibility(ctx, r, candidate) ==
			    NETFS_WRITES_INCOMPATIBLE) {
				kdebug("conflict %x with pend %x",
				       candidate->debug_id, r->debug_id);
				goto add_to_pending_queue;
			}
		}
	}

	/* We mustn't let the request overlap with the reservation of any other
	 * active writes, though it can overlap with a bounding box if the
	 * writes are compatible.
	 */
	list_for_each(p, &ctx->active_writes) {
		r = list_entry(p, struct netfs_dirty_region, active_link);
		if (r->bounds.end <= candidate->bounds.start)
			continue;
		if (r->bounds.start >= candidate->bounds.end)
			break;
		if (overlaps(&candidate->bounds, &r->bounds)) {
			if (overlaps(&candidate->reserved, &r->reserved) ||
			    netfs_write_compatibility(ctx, r, candidate) ==
			    NETFS_WRITES_INCOMPATIBLE) {
				kdebug("conflict %x with actv %x",
				       candidate->debug_id, r->debug_id);
				goto add_to_pending_queue;
			}
		}
	}

	/* We can install the record in the active list to reserve our slot */
	list_add(&candidate->active_link, p);

	/* Okay, we've reserved our slot in the active queue */
	smp_store_release(&candidate->state, NETFS_REGION_IS_RESERVED);
	trace_netfs_dirty(ctx, candidate, NULL, netfs_dirty_trace_reserved);
	wake_up_var(&candidate->state);
	_leave(" [go]");
	return;

add_to_pending_queue:
	/* We get added to the pending list and then we have to wait */
	list_add(&candidate->active_link, &ctx->pending_writes);
	trace_netfs_dirty(ctx, candidate, NULL, netfs_dirty_trace_wait_pend);
	kleave(" [wait pend]");
}

/*
 * Make sure there's a flush group.
 */
static int netfs_require_flush_group(struct inode *inode)
{
	struct netfs_flush_group *group;
	struct netfs_i_context *ctx = netfs_i_context(inode);

	if (list_empty(&ctx->flush_groups)) {
		kdebug("new flush group");
		group = netfs_new_flush_group(inode, NULL);
		if (!group)
			return -ENOMEM;
	}
	return 0;
}

/*
 * Create a dirty region record for the write we're about to do and add it to
 * the list of regions.  We may need to wait for conflicting writes to
 * complete.
 */
static struct netfs_dirty_region *netfs_prepare_region(struct inode *inode,
						       struct file *file,
						       loff_t start, size_t len,
						       enum netfs_region_type type,
						       unsigned long flags)
{
	struct netfs_dirty_region *candidate;
	struct netfs_i_context *ctx = netfs_i_context(inode);
	loff_t end = start + len;
	int ret;

	ret = netfs_require_flush_group(inode);
	if (ret < 0)
		return ERR_PTR(ret);

	candidate = netfs_alloc_dirty_region();
	if (!candidate)
		return ERR_PTR(-ENOMEM);

	netfs_init_dirty_region(candidate, inode, file, type, flags, start, end);

	spin_lock(&ctx->lock);
	netfs_queue_write(ctx, candidate);
	spin_unlock(&ctx->lock);
	return candidate;
}

/*
 * Activate a write.  This adds it to the dirty list and does any necessary
 * flushing and superceding there.  The caller must provide a spare region
 * record so that we can split a dirty record if we need to supersede it.
 */
static void __netfs_activate_write(struct netfs_i_context *ctx,
				   struct netfs_dirty_region *candidate,
				   struct netfs_dirty_region **spare)
{
	struct netfs_dirty_region *r;
	struct list_head *p;
	enum netfs_write_compatibility comp;
	bool conflicts = false;

	/* See if there are any dirty regions that need flushing first. */
	list_for_each(p, &ctx->dirty_regions) {
		r = list_entry(p, struct netfs_dirty_region, dirty_link);
		if (r->bounds.end <= candidate->bounds.start)
			continue;
		if (r->bounds.start >= candidate->bounds.end)
			break;

		if (list_empty(&candidate->dirty_link) &&
		    r->dirty.start > candidate->dirty.start)
			list_add_tail(&candidate->dirty_link, p);

		comp = netfs_write_compatibility(ctx, r, candidate);
		switch (comp) {
		case NETFS_WRITES_INCOMPATIBLE:
			netfs_flush_region(ctx, r, netfs_dirty_trace_flush_conflict);
			conflicts = true;
			continue;

		case NETFS_WRITES_SUPERSEDE:
			if (!overlaps(&candidate->reserved, &r->dirty))
				continue;
			if (r->dirty.start < candidate->dirty.start) {
				/* The region overlaps the beginning of our
				 * region, we split it and mark the overlapping
				 * part as superseded.  We insert ourself
				 * between.
				 */
				r = netfs_split_dirty_region(ctx, r, spare,
							     candidate->reserved.start);
				list_add_tail(&candidate->dirty_link, &r->dirty_link);
				p = &r->dirty_link; /* Advance the for-loop */
			} else  {
				/* The region is after ours, so make sure we're
				 * inserted before it.
				 */
				if (list_empty(&candidate->dirty_link))
					list_add_tail(&candidate->dirty_link, &r->dirty_link);
				set_bit(NETFS_REGION_SUPERSEDED, &r->flags);
				trace_netfs_dirty(ctx, candidate, r, netfs_dirty_trace_supersedes);
			}
			continue;

		case NETFS_WRITES_COMPATIBLE:
			continue;
		}
	}

	if (list_empty(&candidate->dirty_link))
		list_add_tail(&candidate->dirty_link, p);
	netfs_get_dirty_region(ctx, candidate, netfs_region_trace_get_dirty);

	if (conflicts) {
		/* The caller must wait for the flushes to complete. */
		trace_netfs_dirty(ctx, candidate, NULL, netfs_dirty_trace_wait_active);
		kleave(" [wait flush D=%x]", candidate->debug_id);
		return;
	}

	/* Okay, we're cleared to proceed. */
	smp_store_release(&candidate->state, NETFS_REGION_IS_ACTIVE);
	trace_netfs_dirty(ctx, candidate, NULL, netfs_dirty_trace_active);
	wake_up_var(&candidate->state);
	_leave(" [go]");
	return;
}

static int netfs_activate_write(struct netfs_i_context *ctx,
				struct netfs_dirty_region *region)
{
	struct netfs_dirty_region *spare;

	spare = netfs_alloc_dirty_region();
	if (!spare)
		return -ENOMEM;

	spin_lock(&ctx->lock);
	__netfs_activate_write(ctx, region, &spare);
	spin_unlock(&ctx->lock);
	netfs_free_dirty_region(ctx, spare);
	return 0;
}

/*
 * Merge a completed active write into the list of dirty regions.  The region
 * can be in one of a number of states:
 *
 * - Ordinary write, error, no data copied.		Discard.
 * - Ordinary write, unflushed.				Dirty
 * - Ordinary write, flush started.			Dirty
 * - Ordinary write, completed/failed.			Discard.
 * - DIO write,      completed/failed.			Discard.
 * - DSYNC write, error before flush.			As ordinary.
 * - DSYNC write, flushed in progress, EINTR.		Dirty (supersede).
 * - DSYNC write, written to server and cache.		Dirty (supersede)/Discard.
 * - DSYNC write, written to server but not yet cache.	Dirty.
 *
 * Once we've dealt with this record, we see about activating some other writes
 * to fill the activity hole.
 *
 * This eats the caller's ref on the region.
 */
static void netfs_merge_dirty_region(struct netfs_i_context *ctx,
				     struct netfs_dirty_region *region)
{
	struct netfs_dirty_region *p, *q, *front;
	bool new_content = test_bit(NETFS_ICTX_NEW_CONTENT, &ctx->flags);
	LIST_HEAD(graveyard);

	list_del_init(&region->active_link);

	switch (region->type) {
	case NETFS_REGION_DIO:
		list_move_tail(&region->dirty_link, &graveyard);
		goto discard;

	case NETFS_REGION_DSYNC:
		/* A DSYNC write may have overwritten some dirty data
		 * and caused the writeback of other dirty data.
		 */
		goto scan_forwards;

	case NETFS_REGION_ORDINARY:
		if (region->dirty.end == region->dirty.start) {
			list_move_tail(&region->dirty_link, &graveyard);
			goto discard;
		}
		goto scan_backwards;

	case NETFS_REGION_CACHE_COPY:
		goto scan_backwards;
	}

scan_backwards:
	_debug("scan_backwards");
	/* Search backwards for a preceding record that we might be able to
	 * merge with.  We skip over any intervening flush-in-progress records.
	 */
	p = front = region;
	list_for_each_entry_continue_reverse(p, &ctx->dirty_regions, dirty_link) {
		_debug("- back %x", p->debug_id);
		if (p->state >= NETFS_REGION_IS_FLUSHING)
			continue;
		if (p->state == NETFS_REGION_IS_ACTIVE)
			break;
		if (p->bounds.end < region->bounds.start)
			break;
		if (p->dirty.end >= region->dirty.start || new_content)
			goto merge_backwards;
	}
	goto scan_forwards;

merge_backwards:
	_debug("merge_backwards");
	if (test_bit(NETFS_REGION_SUPERSEDED, &p->flags) ||
	    netfs_write_compatibility(ctx, p, region) != NETFS_WRITES_COMPATIBLE)
		goto scan_forwards;

	front = p;
	front->bounds.end = max(front->bounds.end, region->bounds.end);
	front->dirty.end  = max(front->dirty.end,  region->dirty.end);
	set_bit(NETFS_REGION_SUPERSEDED, &region->flags);
	list_del_init(&region->flush_link);
	trace_netfs_dirty(ctx, front, region, netfs_dirty_trace_merged_back);

scan_forwards:
	/* Subsume forwards any records this one covers.  There should be no
	 * non-supersedeable incompatible regions in our range as we would have
	 * flushed and waited for them before permitting this write to start.
	 *
	 * There can, however, be regions undergoing flushing which we need to
	 * skip over and not merge with.
	 */
	_debug("scan_forwards");
	p = region;
	list_for_each_entry_safe_continue(p, q, &ctx->dirty_regions, dirty_link) {
		_debug("- forw %x", p->debug_id);
		if (p->state >= NETFS_REGION_IS_FLUSHING)
			continue;
		if (p->state == NETFS_REGION_IS_ACTIVE)
			break;
		if (p->dirty.start > region->dirty.end &&
		    (!new_content || p->bounds.start > p->bounds.end))
			break;

		if (region->dirty.end >= p->dirty.end) {
			/* Entirely subsumed */
			list_move_tail(&p->dirty_link, &graveyard);
			list_del_init(&p->flush_link);
			trace_netfs_dirty(ctx, front, p, netfs_dirty_trace_merged_sub);
			continue;
		}

		goto merge_forwards;
	}
	goto merge_complete;

merge_forwards:
	_debug("merge_forwards");
	if (test_bit(NETFS_REGION_SUPERSEDED, &p->flags) ||
	    netfs_write_compatibility(ctx, p, front) == NETFS_WRITES_SUPERSEDE) {
		/* If a region was partially superseded by us, we need to roll
		 * it forwards and remove the superseded flag.
		 */
		if (p->dirty.start < front->dirty.end) {
			p->dirty.start = front->dirty.end;
			clear_bit(NETFS_REGION_SUPERSEDED, &p->flags);
		}
		trace_netfs_dirty(ctx, p, front, netfs_dirty_trace_superseded);
		goto merge_complete;
	}

	/* Simply merge overlapping/contiguous ordinary areas together. */
	front->bounds.end = max(front->bounds.end, p->bounds.end);
	front->dirty.end  = max(front->dirty.end,  p->dirty.end);
	list_move_tail(&p->dirty_link, &graveyard);
	list_del_init(&p->flush_link);
	trace_netfs_dirty(ctx, front, p, netfs_dirty_trace_merged_forw);

merge_complete:
	if (test_bit(NETFS_REGION_SUPERSEDED, &region->flags)) {
		list_move_tail(&region->dirty_link, &graveyard);
	}
discard:
	while (!list_empty(&graveyard)) {
		p = list_first_entry(&graveyard, struct netfs_dirty_region, dirty_link);
		list_del_init(&p->dirty_link);
		smp_store_release(&p->state, NETFS_REGION_IS_COMPLETE);
		trace_netfs_dirty(ctx, p, NULL, netfs_dirty_trace_complete);
		wake_up_var(&p->state);
		netfs_put_dirty_region(ctx, p, netfs_region_trace_put_merged);
	}
}

/*
 * Start pending writes in a window we've created by the removal of an active
 * write.  The writes are bundled onto the given queue and it's left as an
 * exercise for the caller to actually start them.
 */
static void netfs_start_pending_writes(struct netfs_i_context *ctx,
				       struct list_head *prev_p,
				       struct list_head *queue)
{
	struct netfs_dirty_region *prev = NULL, *next = NULL, *p, *q;
	struct netfs_range window = { 0, ULLONG_MAX };

	if (prev_p != &ctx->active_writes) {
		prev = list_entry(prev_p, struct netfs_dirty_region, active_link);
		window.start = prev->reserved.end;
		if (!list_is_last(prev_p, &ctx->active_writes)) {
			next = list_next_entry(prev, active_link);
			window.end = next->reserved.start;
		}
	} else if (!list_empty(&ctx->active_writes)) {
		next = list_last_entry(&ctx->active_writes,
				       struct netfs_dirty_region, active_link);
		window.end = next->reserved.start;
	}

	list_for_each_entry_safe(p, q, &ctx->pending_writes, active_link) {
		bool skip = false;

		if (!overlaps(&p->reserved, &window))
			continue;

		/* Narrow the window when we find a region that requires more
		 * than we can immediately provide.  The queue is in submission
		 * order and we need to prevent starvation.
		 */
		if (p->type == NETFS_REGION_DIO) {
			if (p->bounds.start < window.start) {
				window.start = p->bounds.start;
				skip = true;
			}
			if (p->bounds.end > window.end) {
				window.end = p->bounds.end;
				skip = true;
			}
		} else {
			if (p->reserved.start < window.start) {
				window.start = p->reserved.start;
				skip = true;
			}
			if (p->reserved.end > window.end) {
				window.end = p->reserved.end;
				skip = true;
			}
		}
		if (window.start >= window.end)
			break;
		if (skip)
			continue;

		/* Okay, we have a gap that's large enough to start this write
		 * in.  Make sure it's compatible with any region its bounds
		 * overlap.
		 */
		if (prev &&
		    p->bounds.start < prev->bounds.end &&
		    netfs_write_compatibility(ctx, prev, p) == NETFS_WRITES_INCOMPATIBLE) {
			window.start = max(window.start, p->bounds.end);
			skip = true;
		}

		if (next &&
		    p->bounds.end > next->bounds.start &&
		    netfs_write_compatibility(ctx, next, p) == NETFS_WRITES_INCOMPATIBLE) {
			window.end = min(window.end, p->bounds.start);
			skip = true;
		}
		if (window.start >= window.end)
			break;
		if (skip)
			continue;

		/* Okay, we can start this write. */
		trace_netfs_dirty(ctx, p, NULL, netfs_dirty_trace_start_pending);
		list_move(&p->active_link,
			  prev ? &prev->active_link : &ctx->pending_writes);
		list_add_tail(&p->dirty_link, queue);
		if (p->type == NETFS_REGION_DIO)
			window.start = p->bounds.end;
		else
			window.start = p->reserved.end;
		prev = p;
	}
}

/*
 * We completed the modification phase of a write.  We need to fix up the dirty
 * list, remove this region from the active list and start waiters.
 */
static void netfs_commit_write(struct netfs_i_context *ctx,
			       struct netfs_dirty_region *region)
{
	struct netfs_dirty_region *p;
	struct list_head *prev;
	LIST_HEAD(queue);

	spin_lock(&ctx->lock);
	smp_store_release(&region->state, NETFS_REGION_IS_DIRTY);
	trace_netfs_dirty(ctx, region, NULL, netfs_dirty_trace_commit);
	wake_up_var(&region->state);

	prev = region->active_link.prev;
	netfs_merge_dirty_region(ctx, region);
	if (!list_empty(&ctx->pending_writes))
		netfs_start_pending_writes(ctx, prev, &queue);
	spin_unlock(&ctx->lock);

	while (!list_empty(&queue)) {
		p = list_first_entry(&queue, struct netfs_dirty_region, dirty_link);
		list_del_init(&p->dirty_link);
		smp_store_release(&p->state, NETFS_REGION_IS_DIRTY);
		wake_up_var(&p->state);
	}
}

/*
 * Write data into a prereserved region of the pagecache attached to a netfs
 * inode.
 */
static ssize_t netfs_perform_write(struct netfs_dirty_region *region,
				   struct kiocb *iocb, struct iov_iter *i)
{
	struct file *file = iocb->ki_filp;
	struct netfs_i_context *ctx = netfs_i_context(file_inode(file));
	struct page *page;
	ssize_t written = 0, ret;
	loff_t new_pos, i_size;
	bool always_fill = false;

	do {
		size_t plen;
		size_t offset;	/* Offset into pagecache page */
		size_t bytes;	/* Bytes to write to page */
		size_t copied;	/* Bytes copied from user */
		bool relock = false;

		page = netfs_grab_page_for_write(file->f_mapping, region->dirty.end,
						 iov_iter_count(i));
		if (!page)
			return -ENOMEM;

		plen = thp_size(page);
		offset = region->dirty.end - page_file_offset(page);
		bytes = min_t(size_t, plen - offset, iov_iter_count(i));

		if (!PageUptodate(page)) {
			unlock_page(page); /* Avoid deadlocking fault-in */
			relock = true;
		}

		/* Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 *
		 * Not only is this an optimisation, but it is also required
		 * to check that the address is actually valid, when atomic
		 * usercopies are used, below.
		 */
		if (unlikely(iov_iter_fault_in_readable(i, bytes))) {
			ret = -EFAULT;
			goto error_page;
		}

		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto error_page;
		}

		if (relock) {
			ret = lock_page_killable(page);
			if (ret < 0)
				goto error_page;
		}

redo_prefetch:
		/* Prefetch area to be written into the cache if we're caching
		 * this file.  We need to do this before we get a lock on the
		 * page in case there's more than one writer competing for the
		 * same cache block.
		 */
		if (!PageUptodate(page)) {
			ret = netfs_prefetch_for_write(file, page, region->dirty.end,
						       bytes, always_fill);
			if (ret < 0) {
				kdebug("prefetch %zx", ret);
				goto error_page;
			}
		}

		if (mapping_writably_mapped(page->mapping))
			flush_dcache_page(page);
		copied = copy_page_from_iter_atomic(page, offset, bytes, i);
		flush_dcache_page(page);

		/*  Deal with a (partially) failed copy */
		if (!PageUptodate(page)) {
			if (copied == 0) {
				ret = -EFAULT;
				goto error_page;
			}
			if (copied < bytes) {
				iov_iter_revert(i, copied);
				always_fill = true;
				goto redo_prefetch;
			}
			SetPageUptodate(page);
		}

		/* Update the inode size if we moved the EOF marker */
		new_pos = region->dirty.end + copied;
		i_size = i_size_read(file_inode(file));
		if (new_pos > i_size) {
			if (ctx->ops->update_i_size) {
				ctx->ops->update_i_size(file, new_pos);
			} else {
				i_size_write(file_inode(file), new_pos);
				fscache_update_cookie(ctx->cache, NULL, &new_pos);
			}
		}

		/* Update the region appropriately */
		if (i_size > region->i_size)
			region->i_size = i_size;
		smp_store_release(&region->dirty.end, new_pos);

		trace_netfs_dirty(ctx, region, NULL, netfs_dirty_trace_modified);
		set_page_dirty(page);
		unlock_page(page);
		put_page(page);
		page = NULL;

		cond_resched();

		written += copied;

		balance_dirty_pages_ratelimited(file->f_mapping);
	} while (iov_iter_count(i));

out:
	if (likely(written)) {
		iocb->ki_pos += written;

		/* Flush and wait for a write that requires immediate synchronisation. */
		if (region->type == NETFS_REGION_DSYNC) {
			kdebug("dsync");
			spin_lock(&ctx->lock);
			netfs_flush_region(ctx, region, netfs_dirty_trace_flush_dsync);
			spin_unlock(&ctx->lock);

			ret = wait_on_region(region, NETFS_REGION_IS_COMPLETE);
			if (ret < 0)
				written = ret;
		}
	}

	netfs_commit_write(ctx, region);
	return written ? written : ret;

error_page:
	unlock_page(page);
	put_page(page);
	goto out;
}

/**
 * netfs_file_write_iter - write data to a file
 * @iocb:	IO state structure
 * @from:	iov_iter with data to write
 *
 * This is a wrapper around __generic_file_write_iter() to be used by most
 * filesystems. It takes care of syncing the file in case of O_SYNC file
 * and acquires i_mutex as needed.
 * Return:
 * * negative error code if no data has been written at all of
 *   vfs_fsync_range() failed for a synchronous write
 * * number of bytes written, even for truncated writes
 */
ssize_t netfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct netfs_dirty_region *region = NULL;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct netfs_i_context *ctx = netfs_i_context(inode);
	enum netfs_region_type type;
	unsigned long flags = 0;
	ssize_t ret;

	_enter("%llx,%zx,%llx", iocb->ki_pos, iov_iter_count(from), i_size_read(inode));

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto error_unlock;

	if (iocb->ki_flags & IOCB_DIRECT)
		type = NETFS_REGION_DIO;
	if (iocb->ki_flags & IOCB_DSYNC)
		type = NETFS_REGION_DSYNC;
	else
		type = NETFS_REGION_ORDINARY;
	if (iocb->ki_flags & IOCB_SYNC)
		__set_bit(NETFS_REGION_SYNC, &flags);

	region = netfs_prepare_region(inode, file, iocb->ki_pos,
				      iov_iter_count(from), type, flags);
	if (IS_ERR(region)) {
		ret = PTR_ERR(region);
		goto error_unlock;
	}

	trace_netfs_write_iter(region, iocb, from);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	ret = file_remove_privs(file);
	if (ret)
		goto error_unlock;

	ret = file_update_time(file);
	if (ret)
		goto error_unlock;

	inode_unlock(inode);

	ret = wait_on_region(region, NETFS_REGION_IS_RESERVED);
	if (ret < 0)
		goto error;

	ret = netfs_activate_write(ctx, region);
	if (ret < 0)
		goto error;

	/* The region excludes overlapping writes and is used to synchronise
	 * versus flushes.
	 */
	if (iocb->ki_flags & IOCB_DIRECT)
		ret = -EOPNOTSUPP; //netfs_file_direct_write(region, iocb, from);
	else
		ret = netfs_perform_write(region, iocb, from);

out:
	netfs_put_dirty_region(ctx, region, netfs_region_trace_put_write_iter);
	current->backing_dev_info = NULL;
	return ret;

error_unlock:
	inode_unlock(inode);
error:
	if (region)
		netfs_commit_write(ctx, region);
	goto out;
}
EXPORT_SYMBOL(netfs_file_write_iter);

/*
 * Add a region that's just been read as a region on the dirty list to
 * schedule a write to the cache.
 */
static bool netfs_copy_to_cache(struct netfs_read_request *rreq,
				struct netfs_read_subrequest *subreq)
{
	struct netfs_dirty_region *candidate, *r;
	struct netfs_i_context *ctx = netfs_i_context(rreq->inode);
	struct list_head *p;
	loff_t end = subreq->start + subreq->len;
	int ret;

	ret = netfs_require_flush_group(rreq->inode);
	if (ret < 0)
		return false;

	candidate = netfs_alloc_dirty_region();
	if (!candidate)
		return false;

	netfs_init_dirty_region(candidate, rreq->inode, NULL,
				NETFS_REGION_CACHE_COPY, 0, subreq->start, end);

	spin_lock(&ctx->lock);

	/* Find a place to insert.  There can't be any dirty regions
	 * overlapping with the region we're adding.
	 */
	list_for_each(p, &ctx->dirty_regions) {
		r = list_entry(p, struct netfs_dirty_region, dirty_link);
		if (r->bounds.end <= candidate->bounds.start)
			continue;
		if (r->bounds.start >= candidate->bounds.end)
			break;
	}

	list_add_tail(&candidate->dirty_link, p);
	netfs_merge_dirty_region(ctx, candidate);

	spin_unlock(&ctx->lock);
	return true;
}

/*
 * If we downloaded some data and it now needs writing to the cache, we add it
 * to the dirty region list and let that flush it.  This way it can get merged
 * with writes.
 *
 * We inherit a ref from the caller.
 */
void netfs_rreq_do_write_to_cache(struct netfs_read_request *rreq)
{
	struct netfs_read_subrequest *subreq, *next, *p;

	trace_netfs_rreq(rreq, netfs_rreq_trace_write);

	list_for_each_entry_safe(subreq, p, &rreq->subrequests, rreq_link) {
		if (!test_bit(NETFS_SREQ_WRITE_TO_CACHE, &subreq->flags)) {
			list_del_init(&subreq->rreq_link);
			netfs_put_subrequest(subreq, false);
		}
	}

	list_for_each_entry(subreq, &rreq->subrequests, rreq_link) {
		/* Amalgamate adjacent writes */
		while (!list_is_last(&subreq->rreq_link, &rreq->subrequests)) {
			next = list_next_entry(subreq, rreq_link);
			if (next->start != subreq->start + subreq->len)
				break;
			subreq->len += next->len;
			list_del_init(&next->rreq_link);
			netfs_put_subrequest(next, false);
		}

		netfs_copy_to_cache(rreq, subreq);
	}

	netfs_rreq_completed(rreq, false);
}
