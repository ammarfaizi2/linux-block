// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem high-level write support.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/netfs.h>
#include "internal.h"

static inline bool netfs_bounds_dont_touch(const struct netfs_dirty_region *a,
					   const struct netfs_dirty_region *b)
{
	return a->last < b->first && a->last + 1 != b->first;
}

static inline bool netfs_pgoff_before_touch(pgoff_t a, pgoff_t b)
{
	return a < b && a + 1 == b;
}

/* Round up the last page of a region where the range is inclusive.  */
#define round_up_incl(x, to) (round_up((x) + 1, (to)) - 1)

static size_t copy_folio_from_iter_atomic(struct folio *folio,
					  unsigned int offset, size_t size,
					  struct iov_iter *i)
{
	size_t copied = 0, n;

	do {
		pgoff_t index  = offset / PAGE_SIZE;
		size_t poffset = offset % PAGE_SIZE;
		size_t psize   = min_t(size_t, PAGE_SIZE - offset, size);

		n = copy_page_from_iter_atomic(folio_file_page(folio, index),
					       poffset, psize, i);
		copied += n;
		if (n < psize)
			break;
		size -= n;
	} while (size);
	return copied;
}

/*
 * Initialise a new dirty folio group.  We have to round it out to any crypto
 * alignment.
 */
static void netfs_init_dirty_region(struct netfs_inode *ctx,
				    struct netfs_dirty_region *region,
				    struct file *file)
{
	region->debug_id = atomic_inc_return(&netfs_region_debug_ids);

	if (file && ctx->ops->init_dirty_region)
		ctx->ops->init_dirty_region(region, file);

	trace_netfs_ref_region(region->debug_id, refcount_read(&region->ref),
			       netfs_region_trace_new);
	netfs_proc_add_region(region);
}

/*
 * Find the region covering, immediately before or immediately after a
 * range of pages.
 */
struct netfs_dirty_region *netfs_find_region(struct netfs_inode *ctx,
					     pgoff_t first, pgoff_t last)
{
	struct netfs_dirty_region *r, *prior = NULL;

	list_for_each_entry(r, &ctx->dirty_regions, dirty_link) {
		if (r->first > last)
			return prior ?: r; /* Beyond */
		if (r->last >= first)
			return r; /* Overlaps */
		prior = r;
	}
	return prior;
}

/*
 * Return true if two dirty regions are compatible such that b can be merged
 * onto the end of a.
 */
bool netfs_are_regions_mergeable(struct netfs_inode *ctx,
				 const struct netfs_dirty_region *a,
				 const struct netfs_dirty_region *b)
{
	if (a->type == NETFS_COPY_TO_CACHE ||
	    b->type == NETFS_COPY_TO_CACHE)
		return false;
	if (b->from > a->to &&
	    b->from < ctx->zero_point)
		return false;
	if (b->group != a->group) {
		kdebug("different groups %px %px", b->group, a->group);
		return false;
	}
	if (ctx->ops->are_regions_mergeable)
		return ctx->ops->are_regions_mergeable(ctx, a, b);
	return true;
}

static bool netfs_can_merge(struct netfs_inode *ctx,
			    const struct netfs_dirty_region *onto,
			    const struct netfs_dirty_region *x,
			    struct file *file)
{
	return netfs_are_regions_mergeable(ctx, onto, x);
}

static void netfs_region_absorbed(struct netfs_inode *ctx,
				  struct netfs_dirty_region *into,
				  struct netfs_dirty_region *absorbed,
				  struct list_head *discards,
				  enum netfs_dirty_trace why)
{
	absorbed->absorbed_by =
		netfs_get_dirty_region(ctx, into, netfs_region_trace_get_absorbed_by);
	list_del_init(&absorbed->flush_link);
	list_move(&absorbed->dirty_link, discards);
	trace_netfs_dirty(ctx, into, absorbed, why);
}

/*
 * See if the extended target region bridges to the next region.  Returns true.
 */
static bool netfs_try_bridge_next(struct netfs_inode *ctx,
				  struct netfs_dirty_region *target,
				  struct list_head *discards)
{
	struct netfs_dirty_region *next;

again:
	next = netfs_next_region(ctx, target);
	if (!next)
		goto out;

	if (target->last + 1 != next->first)
		goto out;

	/* If the regions can simply be merged, do so. */
	if (netfs_are_regions_mergeable(ctx, target, next)) {
		target->to = next->to;
		target->last = next->last;
		netfs_region_absorbed(ctx, target, next, discards,
				      netfs_dirty_trace_bridged);
		goto out;
	}

	/* If the next region is copy-to-cache only, we may need to slide the
	 * divider over and supersede part or all of it.
	 */
	if (next->type != NETFS_COPY_TO_CACHE ||
	    target->last < next->first)
		goto out;

	if (target->last >= next->last) {
		/* Next entry is superseded in its entirety. */
		netfs_region_absorbed(ctx, target, next, discards,
				      netfs_dirty_trace_supersede_all);
		if (target->last > next->last)
			goto again;
		goto out;
	}

	next->from  = target->to;
	next->first = target->last + 1;
	trace_netfs_dirty(ctx, target, next, netfs_dirty_trace_superseded);
out:
	return true; /* Return true for tail-callers */
}

/*
 * Try to continue the modification of a preceding region.  The regions must
 * overlap, touch or be bridgeable.
 */
static bool netfs_continue_modification(struct netfs_inode *ctx,
					const struct netfs_dirty_region *proposal,
					struct netfs_dirty_region *target,
					struct list_head *discards)
{
	if (proposal->from != target->to ||
	    proposal->type != target->type ||
	    proposal->group != target->group)
		return false;
	if (proposal->type != NETFS_COPY_TO_CACHE &&
	    ctx->ops->are_regions_mergeable &&
	    !ctx->ops->are_regions_mergeable(ctx, proposal, target))
		return false;

	target->to   = proposal->to;
	target->last = proposal->last;
	trace_netfs_dirty(ctx, target, NULL, netfs_dirty_trace_continue);

	return netfs_try_bridge_next(ctx, target, discards);
}

/*
 * Try to merge the modifications with an existing target region that starts
 * at or before the proposed.
 */
static bool netfs_merge_with_previous(struct netfs_inode *ctx,
				      const struct netfs_dirty_region *proposal,
				      struct netfs_dirty_region *target,
				      struct list_head *discards)
{
	if (netfs_bounds_dont_touch(target, proposal) ||
	    !netfs_are_regions_mergeable(ctx, target, proposal))
		return false;

	target->to   = max(target->to,   proposal->to);
	target->last = max(target->last, proposal->last);
	trace_netfs_dirty(ctx, target, NULL, netfs_dirty_trace_merged_prev);

	return netfs_try_bridge_next(ctx, target, discards);
}

/*
 * Try to merge the modifications with an existing target region that starts
 * after the proposed.
 */
static bool netfs_merge_with_next(struct netfs_inode *ctx,
				  const struct netfs_dirty_region *proposal,
				  struct netfs_dirty_region *target,
				  struct list_head *discards)
{
	if (netfs_bounds_dont_touch(proposal, target) ||
	    !netfs_are_regions_mergeable(ctx, proposal, target))
		return false;

	target->from  = min(target->from,  proposal->from);
	target->first = min(target->first, proposal->first);
	trace_netfs_dirty(ctx, target, NULL, netfs_dirty_trace_merged_next);
	return true;
}

/*
 * Set the flush group on a dirty region.
 */
static void netfs_set_flush_group(struct netfs_inode *ctx,
				  struct netfs_dirty_region *insertion,
				  struct netfs_dirty_region *insert_point,
				  enum netfs_dirty_trace how)
{
	struct netfs_dirty_region *r;
	struct netfs_flush_group *group;
	struct list_head *p;

	if (list_empty(&ctx->flush_groups)) {
		insertion->group = NULL;
		return;
	}

	group = list_last_entry(&ctx->flush_groups,
				struct netfs_flush_group, group_link);

	insertion->group = netfs_get_flush_group(group);
	atomic_inc(&group->nr_regions);

	switch (how) {
	case netfs_dirty_trace_insert_only:
		smp_mb();
		list_add_tail(&insertion->flush_link, &group->region_list);
		return;

	case netfs_dirty_trace_insert_before:
	case netfs_dirty_trace_supersede_front:
		smp_mb();
		if (group == insert_point->group) {
			list_add_tail(&insertion->flush_link,
				      &insert_point->flush_link);
			return;
		}
		break;

	case netfs_dirty_trace_insert_after:
	case netfs_dirty_trace_supersede_back:
		smp_mb();
		if (group == insert_point->group) {
			list_add(&insertion->flush_link,
				 &insert_point->flush_link);
			return;
		}
		break;

	default:
		BUG_ON(1);
	}

	/* We need to search through the flush group's region list and
	 * insert into the right place.
	 */
	list_for_each(p, &group->region_list) {
		r = list_entry(p, struct netfs_dirty_region, flush_link);
		if (r->from > insertion->from)
			break;
	}

	list_add_tail(&insertion->flush_link, p);
}

/*
 * Insert a new region at the specified point, initialising it from the
 * proposed region.
 */
static void netfs_insert_new(struct netfs_inode *ctx,
			     struct netfs_dirty_region *insertion,
			     const struct netfs_dirty_region *proposal,
			     struct file *file,
			     struct netfs_dirty_region *insert_point,
			     enum netfs_dirty_trace how)
{
	insertion->first = proposal->first;
	insertion->last  = proposal->last;
	insertion->from  = proposal->from;
	insertion->to    = proposal->to;
	insertion->type  = proposal->type;
	netfs_init_dirty_region(ctx, insertion, file);
	netfs_set_flush_group(ctx, insertion, insert_point, how);

	switch (how) {
	case netfs_dirty_trace_insert_only:
		list_add_tail(&insertion->dirty_link, &ctx->dirty_regions);
		break;
	case netfs_dirty_trace_insert_before:
	case netfs_dirty_trace_supersede_front:
		list_add_tail(&insertion->dirty_link, &insert_point->dirty_link);
		break;
	case netfs_dirty_trace_insert_after:
	case netfs_dirty_trace_supersede_back:
		list_add(&insertion->dirty_link, &insert_point->dirty_link);
		break;
	default:
		BUG_ON(1);
	}
	trace_netfs_dirty(ctx, insertion, insert_point, how);
}

/*
 * Split the front off of the dirty region at the specified point into the new
 * supplied front region, where the point indicates the last page in the front
 * region.
 */
void netfs_split_off_front(struct netfs_inode *ctx,
			   struct netfs_dirty_region *front,
			   struct netfs_dirty_region *back,
			   pgoff_t front_last,
			   enum netfs_dirty_trace why)
{
	if (WARN_ON(back->first > front_last) ||
	    WARN_ON(back->last < front_last)) {
		spin_unlock(&ctx->dirty_lock);
		BUG();
	}

	front->debug_id = atomic_inc_return(&netfs_region_debug_ids);
	front->type	= back->type;
	front->group	= netfs_get_flush_group(back->group);
	front->first	= back->first;
	front->last	= front_last;
	back->first	= front->last + 1;
	front->from	= back->from;
	back->from	= back->first * PAGE_SIZE;
	front->to	= back->from;

	if (front->type != NETFS_COPY_TO_CACHE &&
	    ctx->ops->split_dirty_region)
		ctx->ops->split_dirty_region(front, back);

	list_move_tail(&front->dirty_link, &back->dirty_link);
	list_add(&front->proc_link,  &back->proc_link);
	if (front->group) {
		atomic_inc(&front->group->nr_regions);
		list_add_tail(&front->flush_link, &back->flush_link);
	}

	trace_netfs_dirty(ctx, front, back, why);
}

/*
 * Supersede some data that's marked copy-to-cache only.  We may need to make
 * up to two splits in the region and we may need to merge with the adjacent
 * regions.
 */
static void netfs_supersede_cache_copy(struct netfs_inode *ctx,
				       const struct netfs_dirty_region *proposal,
				       struct netfs_dirty_region *target,
				       struct list_head *discards,
				       struct file *file)
{
	struct netfs_dirty_region *prev = netfs_prev_region(ctx, target);
	struct netfs_dirty_region *next = netfs_next_region(ctx, target);
	struct netfs_dirty_region *insertion, *front;

	_enter("D=%u", target->debug_id);

	/* Get the case where they're the same size out of the way first. */
	if (target->first == proposal->first &&
	    target->last  == proposal->last)  {
		bool merge_prev = netfs_can_merge(ctx, prev, proposal, file);
		bool merge_next = netfs_can_merge(ctx, proposal, next, file);

		if (merge_prev && !merge_next) {
			prev->to   = proposal->from;
			prev->last = proposal->last;
			netfs_region_absorbed(ctx, prev, target, discards,
					      netfs_dirty_trace_merged_prev_super);
		} else if (merge_next && !merge_prev) {
			next->from  = proposal->from;
			next->first = proposal->first;
			netfs_region_absorbed(ctx, next, target, discards,
					      netfs_dirty_trace_merged_next_super);
		} else if (merge_next && merge_prev) {
			prev->to   = next->to;
			prev->last = next->last;
			netfs_region_absorbed(ctx, prev, target, discards,
					      netfs_dirty_trace_merged_next_super);
			netfs_region_absorbed(ctx, prev, next, discards,
					      netfs_dirty_trace_merged_next);
		} else if (!merge_prev && !merge_next) {
			target->from = proposal->from;
			target->to   = proposal->to;
			target->type = NETFS_MODIFIED_REGION;
			if (ctx->ops->init_dirty_region)
				ctx->ops->init_dirty_region(target, file);
			trace_netfs_dirty(ctx, target, NULL, netfs_dirty_trace_superseded);
		}
		return;
	}

	/* If they start in the same place, insert the proposed region before
	 * and shrink the copy-to-cache region.
	 */
	if (target->first == proposal->first) {
		bool merge_prev = netfs_can_merge(ctx, prev, proposal, file);

		if (merge_prev) {
			prev->to      = proposal->from;
			prev->last    = proposal->last;
			target->first = proposal->last + 1;
			target->from  = target->first * PAGE_SIZE;
			trace_netfs_dirty(ctx, prev, target,
					  netfs_dirty_trace_merged_prev_super);
		} else {
			insertion = netfs_alloc_dirty_region(GFP_ATOMIC);
			if (!insertion) {
				pr_err("OOM");
				BUG();
			}
			netfs_insert_new(ctx, insertion, proposal, file, target,
					 netfs_dirty_trace_supersede_front);
			target->first = insertion->last + 1;
			target->to    = target->first * PAGE_SIZE;
			trace_netfs_dirty(ctx, insertion, target,
					  netfs_dirty_trace_superseded);
		}
		return;
	}

	/* If they end in the same place, insert the proposed region after and
	 * cut the end of the copy-to-cache region.
	 */
	if (target->last == proposal->last) {
		bool merge_next = netfs_can_merge(ctx, proposal, next, file);

		if (merge_next) {
			next->from   = proposal->from;
			next->first  = proposal->first;
			target->last = proposal->first - 1;
			target->to   = proposal->first * PAGE_SIZE;
			trace_netfs_dirty(ctx, next, target,
					  netfs_dirty_trace_merged_next_super);
		} else {
			insertion = netfs_alloc_dirty_region(GFP_ATOMIC);
			if (!insertion) {
				pr_err("OOM");
				BUG();
			}
			netfs_insert_new(ctx, insertion, proposal, file, target,
					 netfs_dirty_trace_supersede_back);
			target->first = proposal->last + 1;
			target->from  = target->first * PAGE_SIZE;
			trace_netfs_dirty(ctx, target, insertion,
					  netfs_dirty_trace_superseded);
		}
		return;
	}

	/* Otherwise we have to split the copy-to-cache region and insert the
	 * proposed region between.
	 */
	insertion = netfs_alloc_dirty_region(GFP_ATOMIC);
	if (!insertion) {
		pr_err("OOM");
		BUG();
	}
	front = netfs_alloc_dirty_region(GFP_ATOMIC);
	if (!front) {
		pr_err("OOM");
		BUG();
	}

	netfs_split_off_front(ctx, front, target, proposal->first - 1,
			      netfs_dirty_trace_split_c2c);

	netfs_insert_new(ctx, insertion, proposal, file, target,
			 netfs_dirty_trace_supersede_front);

	target->from  = min(target->from,  insertion->from);
	target->first = min(target->first, insertion->first);
	trace_netfs_dirty(ctx, target, NULL, netfs_dirty_trace_superseded);
	return;
}

/*
 * Commit the changes to a region.
 */
static void netfs_commit_region(struct netfs_inode *ctx, struct file *file,
				struct netfs_dirty_region *proposal)
{
	struct netfs_dirty_region *target, *insertion, *next;
	unsigned long long i_size;
	size_t balign = 1UL << ctx->min_bshift;
	LIST_HEAD(discards);

	i_size	= i_size_read(&ctx->inode);
	proposal->from = round_down(proposal->from, balign);
	if (proposal->to < i_size)
		proposal->to = min(round_up(proposal->to, balign), i_size);
	// TODO: clear round the expanded region if necessary

	_enter("%llx-%llx", proposal->from, proposal->to);

	spin_lock(&ctx->dirty_lock);

	if (!list_empty(&ctx->flush_groups))
		proposal->group = list_last_entry(&ctx->flush_groups,
						  struct netfs_flush_group, group_link);
	target = netfs_find_region(ctx, proposal->first, proposal->last);

	/* If there aren't any other regions, just insert and be done. */
	if (!target) {
		insertion = netfs_alloc_dirty_region(GFP_ATOMIC);
		if (!insertion) {
			pr_err("OOM\n");
			BUG();
		}
		netfs_insert_new(ctx, insertion, proposal, file, NULL,
				 netfs_dirty_trace_insert_only);
		goto done;
	}

	/* See if we can continue the previous region.  Simply appending more
	 * data is probably the most common modification operation.
	 */
	if (likely(proposal->from == target->to) &&
	    netfs_continue_modification(ctx, proposal, target, &discards))
		goto done;

	/* We may need to supersede part of a copy-to-cache region. */
	if (target->type  == NETFS_COPY_TO_CACHE &&
	    target->first <= proposal->last &&
	    target->last  >= proposal->first) {
		if (WARN_ON(proposal->type == NETFS_COPY_TO_CACHE))
			goto just_merge; /* Re-read?! */
		netfs_supersede_cache_copy(ctx, proposal, target, &discards,
					   file);
		goto done;
	}

just_merge:
	/* Try to merge with the preceding region. */
	if (target->from <= proposal->from) {
		if (netfs_merge_with_previous(ctx, proposal, target, &discards))
			goto done;
		next = netfs_next_region(ctx, target);
		if (!next) {
			/* No next region - insert at the tail. */
			insertion = netfs_alloc_dirty_region(GFP_ATOMIC);
			if (!insertion) {
				pr_err("OOM\n");
				BUG();
			}
			netfs_insert_new(ctx, insertion, proposal, file, target,
					 netfs_dirty_trace_insert_after);
			goto done;
		}
		target = next;
	}

	/* Try to merge with the next region */
	if (netfs_merge_with_next(ctx, proposal, target, &discards))
		goto done;

	/* Insert before the next region. */
	insertion = netfs_alloc_dirty_region(GFP_ATOMIC);
	if (!insertion) {
		pr_err("OOM\n");
		BUG();
	}
	netfs_insert_new(ctx, insertion, proposal, file, target,
			 netfs_dirty_trace_insert_before);

done:
	spin_unlock(&ctx->dirty_lock);
	netfs_discard_regions(ctx, &discards, netfs_region_trace_put_merged);
}

enum netfs_handle_nonuptodate {
	NETFS_FOLIO_IS_UPTODATE,	/* Folio is uptodate already */
	NETFS_JUST_PREFETCH,		/* We have to read the folio anyway */
	NETFS_WHOLE_FOLIO_MODIFY,	/* We're going to overwrite the whole folio */
	NETFS_MODIFY_AND_CLEAR,		/* We can assume there is no data to be downloaded. */
};

/*
 * Decide how we should handle a non-uptodate folio that we want to modify.  We
 * might be attempting to do write-streaming, in which case we don't want to a
 * local RMW cycle if we can avoid it.  If we're doing local caching or content
 * crypto, we award that priority over avoiding RMW.  If the file is open
 * readably, then we also assume that we may want to written what we wrote.
 */
static enum netfs_handle_nonuptodate netfs_handle_nonuptodate_folio(struct netfs_inode *ctx,
								    struct file *file,
								    struct folio *folio,
								    size_t offset,
								    size_t len,
								    bool always_fill)
{
	size_t min_bsize = 1UL << ctx->min_bshift;
	loff_t pos = folio_file_pos(folio);

	_enter("f=%lx,z=%llx", ctx->flags, ctx->zero_point);

	if (folio_test_uptodate(folio))
		return NETFS_FOLIO_IS_UPTODATE;

	if (pos >= ctx->zero_point)
		return NETFS_MODIFY_AND_CLEAR;

	if (always_fill)
		return NETFS_JUST_PREFETCH;

	if (offset == 0 &&
	    len >= folio_size(folio) &&
	    len >= min_bsize)
		return NETFS_WHOLE_FOLIO_MODIFY;

	if (file->f_mode & FMODE_READ ||
	    test_bit(NETFS_ICTX_ENCRYPTED, &ctx->flags) ||
	    test_bit(NETFS_ICTX_DO_RMW, &ctx->flags))
		return NETFS_JUST_PREFETCH;

	if (netfs_i_cookie(ctx) ||
	    min_bsize > 0)
		return NETFS_JUST_PREFETCH;

	/* TODO: Handle streaming writes where we avoid doing client-side RMW
	 * by not bringing pages fully uptodate.
	 *
	 * TODO: Consider doing a streaming write if we're about to completely
	 * overwrite a number of blocks.  Could also do a streaming write if
	 * we're willing to do one or more reads to fill up the edges of a
	 * partially modified block prior to writing it back.
	 */
	return NETFS_JUST_PREFETCH;
}

/*
 * Grab a folio for writing.  We don't lock it at this point as we have yet to
 * preemptively trigger a fault-in - but we need to know how large the folio
 * will be before we try that.
 */
static struct folio *netfs_grab_folio_for_write(struct address_space *mapping,
						pgoff_t index, size_t len_remaining)
{
	return __filemap_get_folio(mapping, index,
				   FGP_LOCK | FGP_WRITE | FGP_CREAT | FGP_STABLE,
				   mapping_gfp_mask(mapping));
}

void netfs_discard_regions(struct netfs_inode *ctx,
			   struct list_head *discards, enum netfs_region_trace why)
{
	struct netfs_dirty_region *p;

	while ((p = list_first_entry_or_null(discards,
					     struct netfs_dirty_region, dirty_link))) {
		list_del(&p->dirty_link);
		BUG_ON(!list_empty(&p->flush_link));
		netfs_put_dirty_region(ctx, p, why);
	}
}

/*
 * Write data into a prereserved region of the pagecache attached to a netfs
 * inode.
 */
static ssize_t netfs_perform_write(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct netfs_inode *ctx = netfs_inode(inode);
	struct netfs_dirty_region proposal = { .debug_id = 0xaa55 };
	struct folio *folio;
	enum netfs_handle_nonuptodate nupt;
	ssize_t written = 0, ret;
	loff_t i_size, pos = iocb->ki_pos;
	bool always_fill = false;
	bool locked = false;

	ret = ctx->ops->validate_for_write(inode, file);
	if (ret < 0)
		return ret;

	do {
		size_t plen;
		size_t offset;	/* Offset into pagecache folio */
		size_t bytes;	/* Bytes to write to folio */
		size_t copied;	/* Bytes copied from user */

		folio = netfs_grab_folio_for_write(file->f_mapping,
						   pos / PAGE_SIZE,
						   iov_iter_count(iter));
		if (!folio) {
			ret = -ENOMEM;
			goto out;
		}

		plen = folio_size(folio);
		offset = pos - folio_file_pos(folio);
		bytes = min_t(size_t, plen - offset, iov_iter_count(iter));
		locked = true;

		if (!folio_test_uptodate(folio)) {
			folio_unlock(folio); /* Avoid deadlocking fault-in */
			locked = false;
		}

		/* Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the same
		 * page as we're writing to, without it being marked
		 * up-to-date.
		 *
		 * Not only is this an optimisation, but it is also required to
		 * check that the address is actually valid, when atomic
		 * usercopies are used, below.
		 */
		if (unlikely(fault_in_iov_iter_readable(iter, bytes))) {
			ret = -EFAULT;
			goto error_folio;
		}

		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto error_folio;
		}

		if (!locked) {
			ret = folio_lock_killable(folio);
			if (ret < 0)
				goto error_folio;
		}

redo_prefetch:
		/* See if we need to prefetch the area we're going to modify.
		 * We need to do this before we get a lock on the folio in case
		 * there's more than one writer competing for the same cache
		 * block.
		 */
		nupt = netfs_handle_nonuptodate_folio(ctx, file, folio,
						      offset, bytes, always_fill);
		_debug("nupt %u", nupt);
		switch (nupt) {
		case NETFS_JUST_PREFETCH:
			ret = netfs_prefetch_for_write(file, folio, bytes);
			if (ret < 0) {
				_debug("prefetch = %zd", ret);
				goto error_folio;
			}
			nupt = NETFS_FOLIO_IS_UPTODATE;
			fallthrough;
		case NETFS_FOLIO_IS_UPTODATE:
			break;
		case NETFS_MODIFY_AND_CLEAR:
			zero_user_segment(&folio->page, 0, offset);
			break;
		case NETFS_WHOLE_FOLIO_MODIFY:
			break;
		}

		if (mapping_writably_mapped(folio_file_mapping(folio)))
			flush_dcache_folio(folio);
		copied = copy_folio_from_iter_atomic(folio, offset, bytes, iter);
		flush_dcache_folio(folio);

		/*  Deal with a (partially) failed copy */
		if (!folio_test_uptodate(folio)) {
			if (copied == 0) {
				ret = -EFAULT;
				goto error_folio;
			}
			if (copied < bytes) {
				iov_iter_revert(iter, copied);
				always_fill = true;
				goto redo_prefetch;
			}
			switch (nupt) {
			case NETFS_JUST_PREFETCH:
			case NETFS_FOLIO_IS_UPTODATE:
				/* We have the folio locked, so it really ought
				 * to be uptodate.
				 */
				WARN(true, "Locked folio %lx became non-uptodate\n",
				     folio_index(folio));
				ret = -EIO;
				goto error_folio;
			case NETFS_MODIFY_AND_CLEAR:
				zero_user_segment(&folio->page, offset + copied, plen);
				fallthrough;
			case NETFS_WHOLE_FOLIO_MODIFY:
				folio_mark_uptodate(folio);
				break;
			}
		}

		/* Update the inode size if we moved the EOF marker */
		pos += copied;
		i_size = i_size_read(inode);
		if (pos > i_size) {
			if (ctx->ops->update_i_size) {
				ctx->ops->update_i_size(inode, pos);
			} else {
				i_size_write(inode, pos);
#if IS_ENABLED(CONFIG_FSCACHE)
				fscache_update_cookie(ctx->cache, NULL, &pos);
#endif
			}
		}

		proposal.from	= pos - copied;
		proposal.to	= pos;
		proposal.first	= folio->index;
		proposal.last	= folio->index + folio_nr_pages(folio) - 1;
		proposal.type	= NETFS_MODIFIED_REGION;
		netfs_commit_region(ctx, file, &proposal);
		netfs_check_dirty_list('D', &ctx->dirty_regions, NULL);

		folio_mark_dirty(folio);
		folio_unlock(folio);
		folio_put(folio);
		folio = NULL;

		cond_resched();

		written += copied;

		balance_dirty_pages_ratelimited(file->f_mapping);
	} while (iov_iter_count(iter));

out:
	if (likely(written)) {
		iocb->ki_pos += written;

#if 0
		/* Flush and wait for a write that requires immediate synchronisation. */
		if (iocb->ki_flags & (IOCB_DSYNC | IOCB_SYNC)) {
			_debug("dsync");
			spin_lock(&ctx->dirty_lock);
			netfs_flush_region(ctx, region, netfs_dirty_trace_flush_dsync);
			spin_unlock(&ctx->dirty_lock);

			ret = wait_on_region(region, NETFS_REGION_IS_COMPLETE);
			if (ret < 0)
				written = ret;
		}
#endif
	}

	return written ? written : ret;

error_folio:
	if (locked)
		folio_unlock(folio);
	folio_put(folio);
	goto out;
}

/**
 * netfs_file_write_iter_locked - write data to a file
 * @iocb:	IO state structure
 * @from:	iov_iter with data to write
 *
 * This is a wrapper around __generic_file_write_iter() to be used by most
 * filesystems that want to deal with the locking themselves. It takes care
 * of syncing the file in case of O_SYNC.
 * Return:
 * * negative error code if no data has been written at all of
 *   vfs_fsync_range() failed for a synchronous write
 * * number of bytes written, even for truncated writes
 */
ssize_t netfs_file_write_iter_locked(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct netfs_inode *ctx = netfs_inode(inode);
	ssize_t ret;

	_enter("%llx,%zx,%llx", iocb->ki_pos, iov_iter_count(from), i_size_read(inode));

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		return ret;

	trace_netfs_write_iter(iocb, from);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	ret = file_remove_privs(file);
	if (ret)
		goto error;

	ret = file_update_time(file);
	if (ret)
		goto error;

	{
#warning TRIGGER NEW FLUSH GROUP FOR TESTING
		static atomic_t jump;
		ret = netfs_require_flush_group(inode, (atomic_inc_return(&jump) & 3) == 3);
		if (ret < 0)
			goto error;
	}

	ret = netfs_flush_conflicting_writes(ctx, file, iocb->ki_pos,
					     iov_iter_count(from), NULL);
	if (ret < 0 && ret != -EAGAIN)
		goto error;

	if (iocb->ki_flags & IOCB_DIRECT)
		ret = netfs_direct_write_iter(iocb, from);
	else
		ret = netfs_perform_write(iocb, from);

error:
	/* TODO: Wait for DSYNC region here. */
	current->backing_dev_info = NULL;
	return ret;
}
EXPORT_SYMBOL(netfs_file_write_iter_locked);

/**
 * netfs_file_write_iter - write data to a file
 * @iocb:	IO state structure
 * @from:	iov_iter with data to write
 *
 * This is a wrapper around __generic_file_write_iter() to be used by most
 * filesystems. It takes care of syncing the file in case of O_SYNC file and
 * acquires i_mutex as needed.
 * Return:
 * * negative error code if no data has been written at all of
 *   vfs_fsync_range() failed for a synchronous write
 * * number of bytes written, even for truncated writes
 */
ssize_t netfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	bool direct = (iocb->ki_flags & (IOCB_DIRECT | IOCB_APPEND)) == IOCB_DIRECT;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (direct)
		netfs_start_io_direct(inode);
	else
		netfs_start_io_write(inode);

	ret = netfs_file_write_iter_locked(iocb, from);

	if (direct)
		netfs_end_io_direct(inode);
	else
		netfs_end_io_write(inode);

	return ret;
}
EXPORT_SYMBOL(netfs_file_write_iter);

/*
 * Notification that a previously read-only page is about to become writable.
 * Note that the caller indicates a single page of a multipage folio.
 */
vm_fault_t netfs_page_mkwrite(struct vm_fault *vmf)
{
	struct netfs_dirty_region proposal;
	struct folio *folio = page_folio(vmf->page);
	struct file *file = vmf->vma->vm_file;
	struct inode *inode = file_inode(file);
	struct netfs_inode *ctx = netfs_inode(inode);
	vm_fault_t ret = VM_FAULT_RETRY;
	int err;

	_enter("%lx", folio->index);

	if (ctx->ops->validate_for_write(inode, file) < 0)
		return VM_FAULT_SIGBUS;

	sb_start_pagefault(inode->i_sb);

	if (folio_wait_writeback_killable(folio))
		goto out;

	if (folio_lock_killable(folio) < 0)
		goto out;

	err = netfs_flush_conflicting_writes(ctx, file, folio_pos(folio),
					     folio_size(folio), folio);
	switch (err) {
	case 0:
		break;
	case -EAGAIN:
		ret = VM_FAULT_RETRY;
		goto out;
	case -ENOMEM:
		ret = VM_FAULT_OOM;
		goto out;
	default:
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	proposal.from	= folio_pos(folio);
	proposal.to	= proposal.from + folio_size(folio);
	proposal.first	= folio->index;
	proposal.last	= folio->index + folio_nr_pages(folio) - 1;
	netfs_commit_region(ctx, file, &proposal);
	file_update_time(file);

	ret = VM_FAULT_LOCKED;
out:
	sb_end_pagefault(inode->i_sb);
	return ret;
}
EXPORT_SYMBOL(netfs_page_mkwrite);

/*
 * Try to note in the dirty region list that a range of pages needs writing to
 * the cache.  These are then written back by writepages.
 */
static void netfs_copy_to_cache(struct netfs_io_request *rreq,
				loff_t start, size_t len)
{
	struct netfs_dirty_region proposal;
	struct netfs_inode *ctx = netfs_inode(rreq->inode);

	proposal.from	= start;
	proposal.to	= start + len;
	proposal.first	= start / PAGE_SIZE;
	proposal.last	= (start + len - 1) / PAGE_SIZE;
	proposal.type	= NETFS_COPY_TO_CACHE;
	netfs_commit_region(ctx, NULL, &proposal);
}

/*
 * If we downloaded some data and it now needs writing to the cache, we add it
 * to the dirty region list and let that flush it.  This way it can get merged
 * with writes.
 *
 * We inherit a ref from the caller.
 */
void netfs_rreq_do_write_to_cache(struct netfs_io_request *rreq)
{
	struct netfs_io_subrequest *subreq, *next, *p;
	struct netfs_io_chain *chain = &rreq->chain[0];

	trace_netfs_rreq(rreq, netfs_rreq_trace_copy_mark);

	list_for_each_entry_safe(subreq, p, &chain->subrequests, chain_link) {
		if (!test_bit(NETFS_SREQ_COPY_TO_CACHE, &subreq->flags)) {
			list_del_init(&subreq->chain_link);
			netfs_put_subrequest(subreq, false,
					     netfs_sreq_trace_put_no_copy);
		}
	}

	list_for_each_entry(subreq, &chain->subrequests, chain_link) {
		loff_t start = subreq->start;
		size_t len = subreq->len;

		/* Amalgamate adjacent writes */
		while (!list_is_last(&subreq->chain_link, &chain->subrequests)) {
			next = list_next_entry(subreq, chain_link);
			if (next->start != start + len)
				break;
			len += next->len;
			list_del_init(&next->chain_link);
			netfs_put_subrequest(next, false,
					     netfs_sreq_trace_put_merged);
		}

		netfs_copy_to_cache(rreq, start, len);
	}

	netfs_rreq_completed(rreq, false);
}
