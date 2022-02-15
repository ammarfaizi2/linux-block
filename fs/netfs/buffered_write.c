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
#include "internal.h"

/* Round up the last page of a region where the range is inclusive.  */
#define round_up_incl(x, to) (round_up((x) + 1, (to)) - 1)

static size_t copy_folio_from_iter_atomic(struct folio *folio,
					  unsigned int offset, size_t size,
					  struct iov_iter *i)
{
	size_t copied = 0, n;

	do {
		unsigned int index   = offset / PAGE_SIZE;
		unsigned int poffset = offset % PAGE_SIZE;
		unsigned int psize   = min(PAGE_SIZE - offset, size);

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
static void netfs_init_dirty_region(struct netfs_i_context *ctx,
				    struct netfs_dirty_region *region,
				    struct file *file,
				    loff_t start, size_t len)
{
	region->from		= start;
	region->to		= start + len;
	region->debug_id	= atomic_inc_return(&netfs_region_debug_ids);

	if (file && ctx->ops->init_dirty_region)
		ctx->ops->init_dirty_region(region, file);

	trace_netfs_ref_region(region->debug_id, refcount_read(&region->ref),
			       netfs_region_trace_new);
}

/*
 * Return true if two dirty regions are compatible such that b can be merged
 * onto the end of a.
 */
bool netfs_are_regions_mergeable(struct netfs_i_context *ctx,
				 struct netfs_dirty_region *a,
				 struct netfs_dirty_region *b)
{
	if (!netfs_mas_is_valid(a) || !netfs_mas_is_valid(b))
		return a == b;
	if (b->waiting_on_wb != a->waiting_on_wb)
		return false;
	if (b->from != a->to &&
	    b->from < ctx->zero_point)
		return false;
	if (ctx->ops->are_regions_mergeable)
		return ctx->ops->are_regions_mergeable(ctx, a, b);
	return true;
}

/*
 * Subsume the modifications into an existing target region.  Returns true if
 * we need to update the dirty_regions tree.
 */
static bool netfs_subsume_into_existing(struct netfs_i_context *ctx,
					struct folio *folio,
					struct ma_state *mas,
					struct netfs_dirty_region **_target,
					struct netfs_dirty_region **_to_put,
					pgoff_t *_first, pgoff_t *_last,
					size_t offset, size_t len)
{
	struct netfs_dirty_region *target = *_target, *prev;

	target->from  = min(target->from, folio_pos(folio) + offset);
	target->to    = max(target->to,   folio_pos(folio) + offset + len);
	trace_netfs_dirty(ctx, target, NULL, *_first, *_last,
			  netfs_dirty_trace_modified);

	/* We might have bridged to the previous region also. */
	prev = mas_prev(mas, *_first - 1);
	if (!netfs_mas_is_valid(prev))
		return false;

	if (prev->to != target->from ||
	    prev->waiting_on_wb != target->waiting_on_wb)
		return false;

	*_first = mas->index;
	prev->to = target->to;
	*_to_put = target;
	trace_netfs_dirty(ctx, prev, NULL, *_first, *_last,
			  netfs_dirty_trace_merged_prev);
	return true;
}

/*
 * Try to continue modification of a preceding region.  The target region must
 * not be covered by a non-flushing dirty region.
 */
static bool netfs_continue_modification(struct netfs_i_context *ctx,
					struct folio *folio,
					struct ma_state *mas,
					struct netfs_dirty_region **_target,
					struct netfs_dirty_region **_to_put,
					pgoff_t *_first, pgoff_t *_last,
					size_t offset, size_t len)
{
	struct netfs_dirty_region *prev, *target = *_target;
	pgoff_t first = *_first, last = *_last;
	unsigned long long from = first * PAGE_SIZE + offset;
	unsigned long long to   = from + len;
	enum netfs_dirty_trace why;

	if (first == 0)
		return false;

	mas_set(mas, first - 1);
	prev = mas_walk(mas);
	if (!netfs_mas_is_valid(prev)) {
		_debug("noncont %lx-%lx %lx", mas->index, mas->last, first);
		return false;
	}

	_debug("cont [D=%x] %lx-%lx %lx", prev->debug_id, mas->index, mas->last, first - 1);

	/* The regions touch.  The previous region and the target region can
	 * only be combined if they have the same writeback overlay state.
	 */
	if (prev->waiting_on_wb) {
		if (!netfs_mas_is_valid(target) ||
		    (prev->waiting_on_wb != target->waiting_on_wb &&
		     prev->waiting_on_wb != target))
			return false;
	}

	/* The regions must also overlap, touch or be bridgeable. */
	if (from > prev->to &&
	    prev->to < ctx->zero_point)
		return false;

	first = mas->index;
	if (netfs_mas_is_flushing(prev)) {
		_debug("overlay");
		prev->to = to;
		target = NULL;
		why = netfs_dirty_trace_overlay_flush;
	} else if (target) {
		_debug("bridged");
		*_to_put = target;
		prev->to = max(target->to, to);
		why = netfs_dirty_trace_bridged;
	} else {
		_debug("no conflict");
		prev->to = to;
		target = NULL;
		why = netfs_dirty_trace_continue;
	}

	*_target = prev;
	*_first = first;
	*_last = last;
	trace_netfs_dirty(ctx, prev, target, first, last, why);
	return true;
}

/*
 * Insert a new region.  The space it occupies may be blank, being flushed or
 * require superseding.
 */
static void netfs_add_new_region(struct netfs_i_context *ctx,
				 struct folio *folio,
				 struct ma_state *mas,
				 struct netfs_dirty_region *target,
				 struct netfs_dirty_region *old,
				 struct netfs_dirty_region **_to_put,
				 pgoff_t first, pgoff_t last,
				 size_t offset, size_t len)
{
	_debug("insert %lx-%lx,%zx,%zx", first, last, offset, len);

	/* See if there's anything occupying the region we're moving into. */
	if (old) {
		//pgoff_t align = 1 << old->align_order;

		//_debug("old [D=%x] %lx-%lx", (old&~1)->debug_id, first, last);

		/* If the region we're superseding is being written out at the
		 * moment, then mark this one as being unflushable for the
		 * moment and non-mergeable with regions that aren't overlying
		 * flushes.
		 */
		if (netfs_mas_is_flushing(old)) {
			target->waiting_on_wb = old;
		} else {
			kdebug("*** OLD %px", old);
			WARN_ON(1);
		}
	} else {
		trace_netfs_dirty(ctx, target, NULL, first, last,
				  netfs_dirty_trace_insert);
	}
}

/*
 * Commit the changes to a folio.  The internal structure of the dirty_regions
 * tree must have been preallocated before any changes were made as we must not
 * fail.
 */
static void netfs_commit_folio(struct netfs_i_context *ctx,
			       struct file *file,
			       struct netfs_dirty_region **_spare_region,
			       struct ma_state *mas,
			       struct folio *folio,
			       size_t offset,
			       size_t len)
{
	struct netfs_dirty_region *old, *target, *to_put = NULL;
	unsigned long long i_size, end, up;
	pgoff_t first, last;
	size_t balign = 1UL << ctx->min_bshift;
	size_t tmp;
	bool re_store = false;

	i_size	= i_size_read(netfs_inode(ctx));
	end	= folio_pos(folio) + offset + len;
	tmp	= offset;
	offset	= round_down(offset, balign);
	len	+= tmp - offset;
	if (end < i_size) {
		up = min(round_up(end, balign), i_size);
		len += up - end;
	}

	_enter("e=%llx o=%lx l=%lx", end, offset, len);

	mtree_lock(&ctx->dirty_regions);

	/* First thing to check is whether there's a region covering the area
	 * of interest.  If so, we may be able to simply subsume into it.
	 */
	mas_set(mas, folio->index);
	target = mas_walk(mas);
	first = mas->index;
	last = mas->last;
	if (!target) {
		first = folio->index;
		last  = folio_next_index(folio) - 1;
		mas_set_range(mas, first, last);
	}

	if (netfs_mas_is_valid(target)) {
		re_store = netfs_subsume_into_existing(ctx, folio, mas, &target, &to_put,
						       &first, &last, offset, len);
		goto done;
	}

	/* See if we can continue the previous region. */
	if (netfs_continue_modification(ctx, folio, mas, &target, &to_put,
					&first, &last, offset, len)) {
		re_store = true;
		goto done;
	}

	old = target;
	first = folio->index;
	last  = folio_next_index(folio) - 1;
	target = *_spare_region;
	*_spare_region = NULL;
	netfs_init_dirty_region(ctx, target, file, first * PAGE_SIZE + offset, len);
	netfs_add_new_region(ctx, folio, mas, target, old, &to_put,
			     first, last, offset, len);
	re_store = true;

done:
	if (re_store) {
		_debug("store [D=%x] %lx-%lx", target->debug_id, first, last);
		mas_set_range(mas, first, last);
		mas_store(mas, target);
	}
	mtree_unlock(&ctx->dirty_regions);
	netfs_put_dirty_region(ctx, to_put, netfs_region_trace_put_merged);
}

/*
 * See if we can merge the regions we just added with their neighbours at the
 * end of the write.
 */
static void netfs_commit_region(struct netfs_i_context *ctx, struct ma_state *mas,
				loff_t start, size_t len)
{
	struct netfs_dirty_region *region, *prev, *next, *put[2] = {};
	pgoff_t first = start / PAGE_SIZE;
	pgoff_t last  = (start + len - 1) / PAGE_SIZE;

	_enter("%lx-%lx", first, last);

	if (mas_expected_entries(mas, 1) < 0)
		return;

	mtree_lock(&ctx->dirty_regions);

	/* See if we can merge the front with the previous region. */
	mas_set(mas, first);
	if (first > 0 &&
	    (region = mas_walk(mas)) &&
	    netfs_mas_is_valid(region) &&
	    (first = mas->index) &&
	    (last = mas->last) &&
	    (prev = mas_prev(mas, mas->index - 1)) &&
	    netfs_mas_is_valid(prev)
	    ) {
		_debug("prev [D=%x] %lx-%lx [D=%x] %lx-%lx",
		       prev->debug_id, mas->index, mas->last,
		       region->debug_id, first, last);

		if (netfs_are_regions_mergeable(ctx, prev, region)) {
			_debug("- merge");
			first		= mas->index;
			prev->to	= region->to;
			trace_netfs_dirty(ctx, prev, region, first, last,
					  netfs_dirty_trace_merged_prev);
			mas_set_range(mas, first, last);
			mas_store(mas, prev);
			put[0] = region;
		}
	}

	mtree_unlock(&ctx->dirty_regions);

	if (mas_expected_entries(mas, 1) < 0)
		return;

	mtree_lock(&ctx->dirty_regions);

	/* See if we can merge the end with the next region. */
	mas_set_range(mas, last, last);
	if (last != ULONG_MAX &&
	    (region = mas_walk(mas)) &&
	    netfs_mas_is_valid(region) &&
	    (first = mas->index, true) &&
	    (last = mas->last) != ULONG_MAX &&
	    (next = mas_next(mas, mas->last + 1)) &&
	    netfs_mas_is_valid(next)
	    ) {
		_debug("next [D=%x] %lx-%lx [D=%x] %lx-%lx",
		       region->debug_id, first, last,
		       next->debug_id, mas->index, mas->last);

		if (!region->waiting_on_wb &&
		    netfs_are_regions_mergeable(ctx, region, next)) {
			_debug("- annex next");
			last		= mas->last;
			region->to	= next->to;
			trace_netfs_dirty(ctx, region, next, first, last,
					  netfs_dirty_trace_merged_next);
			mas_set_range(mas, first, last);
			mas_store(mas, region);
			put[1] = next;
		}
	}

	mtree_unlock(&ctx->dirty_regions);

	netfs_put_dirty_region(ctx, put[0], netfs_region_trace_put_merged);
	netfs_put_dirty_region(ctx, put[1], netfs_region_trace_put_merged);
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
static enum netfs_handle_nonuptodate netfs_handle_nonuptodate_folio(struct netfs_i_context *ctx,
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

	if (netfs_i_cookie(file_inode(file)) ||
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

/*
 * Write data into a prereserved region of the pagecache attached to a netfs
 * inode.
 */
static ssize_t netfs_perform_write(struct kiocb *iocb, struct iov_iter *iter)
{
	struct netfs_dirty_region *spare_region = NULL;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct netfs_i_context *ctx = netfs_i_context(inode);
	struct folio *folio;
	enum netfs_handle_nonuptodate nupt;
	ssize_t written = 0, ret;
	loff_t i_size, pos = iocb->ki_pos;
	bool always_fill = false;
	bool locked = false;

	MA_STATE(mas, &ctx->dirty_regions, pos / PAGE_SIZE,
		 (pos + iov_iter_count(iter) - 1) / PAGE_SIZE);

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

		/* Preallocate the space we need in the dirty region list. */
		ret = mas_expected_entries(&mas, 1);
		if (ret < 0)
			goto error_folio;

		if (!spare_region) {
			spare_region = netfs_alloc_dirty_region();
			if (IS_ERR(spare_region)) {
				ret = PTR_ERR(spare_region);
				spare_region = NULL;
				goto error_folio;
			}
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
				fscache_update_cookie(ctx->cache, NULL, &pos);
			}
		}

		netfs_commit_folio(ctx, file, &spare_region, &mas,
				   folio, offset, copied);

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
		netfs_commit_region(ctx, &mas, iocb->ki_pos, written);

		iocb->ki_pos += written;

#if 0
		/* Flush and wait for a write that requires immediate synchronisation. */
		if (iocb->ki_flags & (IOCB_DSYNC | IOCB_SYNC)) {
			_debug("dsync");
			mtree_lock(&ctx->dirty_regions);
			netfs_flush_region(ctx, region, netfs_dirty_trace_flush_dsync);
			mtree_unlock(&ctx->dirty_regions);

			ret = wait_on_region(region, NETFS_REGION_IS_COMPLETE);
			if (ret < 0)
				written = ret;
		}
#endif
	}

	mas_destroy(&mas);
	return written ? written : ret;

error_folio:
	if (locked)
		folio_unlock(folio);
	folio_put(folio);
	goto out;
}

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
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct netfs_i_context *ctx = netfs_i_context(inode);
	ssize_t ret;

	_enter("%llx,%zx,%llx", iocb->ki_pos, iov_iter_count(from), i_size_read(inode));

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto error_unlock;

	trace_netfs_write_iter(iocb, from);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	ret = file_remove_privs(file);
	if (ret)
		goto error;

	ret = file_update_time(file);
	if (ret)
		goto error;

	ret = netfs_flush_conflicting_writes(ctx, file, iocb->ki_pos,
					     iov_iter_count(from), NULL);
	if (ret < 0 && ret != -EAGAIN)
		goto error;

	if (iocb->ki_flags & IOCB_DIRECT)
		ret = netfs_direct_write_iter(iocb, from);
	else
		ret = netfs_perform_write(iocb, from);

error:
	inode_unlock(inode);
	/* TODO: Wait for DSYNC region here. */
	current->backing_dev_info = NULL;
	return ret;
error_unlock:
	inode_unlock(inode);
	return ret;
}
EXPORT_SYMBOL(netfs_file_write_iter);

/*
 * Notification that a previously read-only page is about to become writable.
 * Note that the caller indicates a single page of a multipage folio.
 */
vm_fault_t netfs_page_mkwrite(struct vm_fault *vmf)
{
	struct netfs_dirty_region *spare_region;
	struct folio *folio = page_folio(vmf->page);
	struct file *file = vmf->vma->vm_file;
	struct inode *inode = file_inode(file);
	struct netfs_i_context *ctx = netfs_i_context(inode);
	vm_fault_t ret = VM_FAULT_RETRY;
	int err;

	MA_STATE(mas, &ctx->dirty_regions, vmf->page->index, PAGE_SIZE);

	_enter("%lx", folio->index);

	if (ctx->ops->validate_for_write(inode, file) < 0)
		return VM_FAULT_SIGBUS;

	sb_start_pagefault(inode->i_sb);

	if (folio_wait_writeback_killable(folio))
		goto out;

	if (folio_lock_killable(folio) < 0)
		goto out;

	if (mas_expected_entries(&mas, 2) < 0) {
		ret = VM_FAULT_OOM;
		goto out;
	}

	spare_region = netfs_alloc_dirty_region();
	if (IS_ERR(spare_region)) {
		ret = VM_FAULT_OOM;
		goto out;
	}

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

	netfs_commit_folio(ctx, file, &spare_region, &mas,
			   folio, 0, folio_size(folio));
	netfs_commit_region(ctx, &mas, folio_pos(folio), folio_size(folio));
	file_update_time(file);

	ret = VM_FAULT_LOCKED;
out:
	sb_end_pagefault(inode->i_sb);
	mas_destroy(&mas);
	netfs_put_dirty_region(ctx, spare_region, netfs_region_trace_put_discard);
	return ret;
}
