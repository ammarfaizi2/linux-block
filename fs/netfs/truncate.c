// SPDX-License-Identifier: GPL-2.0-only
/* Handle truncation on a netfs file.
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

static struct netfs_io_request *netfs_alloc_truncation(struct netfs_inode *ctx,
						       struct iattr *attr)
{
	return netfs_alloc_request(ctx->inode.i_mapping,
				   attr->ia_valid & ATTR_FILE ? attr->ia_file : NULL,
				   attr->ia_size, 0, NETFS_TRUNCATE);
}

/*
 * Assess the type of modification we're going to need to perform.
 *
 * If we're going to expand or punch a hole in a file that has content
 * encryption, then we need to inject encrypted cleared blocks.  The simplest
 * way to do this may be by writing zeroes into the pagecache and letting the
 * writeback code do the actual work.  We would have to deal with EDQUOT or
 * ENOSPC occurring.
 *
 * We can be lazy in a number of ways:
 *
 * (1) If a page of blocks or a block of pages is entirely scrubbed, we don't
 *     need to read it from the server/cache and can just splice in zeroed
 *     pages where we don't have anything yet.
 *
 * (2) We could be lazy about updating the EOF marker on the server - and hope
 *     we don't hit EDQUOT or ENOSPC later.
 *
 * (3) We may be able to record sparseness on the server.  Ceph, for instance,
 *     can do this.
 */
static void netfs_assess_truncation(struct netfs_inode *ctx,
				    struct netfs_io_request *treq)
{
	unsigned long min_bsize = 1UL << ctx->min_bshift;
	loff_t remote_i_size = ctx->remote_i_size;
	loff_t cur_i_size = treq->i_size;
	loff_t new_i_size = treq->start;

	_enter("%llx,%llx,%llx,%lx", cur_i_size, new_i_size, remote_i_size, min_bsize);

	if (new_i_size > cur_i_size) {
		/* Simplest case: The increase in file size fits in the same
		 * encryption block/page as the current EOF.
		 */
		if (new_i_size <= round_up(cur_i_size, PAGE_SIZE)) {
			treq->trunc_type = NETFS_TRUNC_GROW_LOCALLY;
			return;
		}

		/* Next case: The file is just increasing in size and there's
		 * no content encryption.
		 */
		if (!test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &treq->flags)) {
			treq->trunc_type = NETFS_TRUNC_GROW_NOENC;
			return;
		}

		/* Next case: the file is being grown to a logical block
		 * boundary.  We don't need to worry about encryption in this
		 * case.
		 */
		if ((new_i_size & (min_bsize - 1)) == 0) {
			treq->trunc_type = NETFS_TRUNC_SHRINK_TO_ENC_BLOCK;
			return;
		}

		/* Otherwise: the file is being grown to mid-block.  We have to
		 * be very careful when altering the partial block to not
		 * corrupt the file.  We need to make sure there's a dirty
		 * region to cover the modified block.
		 */
		treq->trunc_type = NETFS_TRUNC_SHRINK_MID_ENC_BLOCK;
		return;
	}

	if (new_i_size < cur_i_size) {
		/* Simplest case: the file is being truncated to nothing. */
		if (new_i_size == 0) {
			treq->trunc_type = NETFS_TRUNC_SHRINK_TO_ZERO;
			return;
		}

		/* Next case: the file is being shrunk, but the data being
		 * discarded is only stored locally and is all above the remote
		 * EOF position.
		 */
		if (new_i_size > remote_i_size) {
			treq->trunc_type = NETFS_TRUNC_SHRINK_LOCALLY;
			return;
		}

		/* Next case: We're going to have to discard part of the file,
		 * but we don't have any encryption to worry about.
		 */
		if (!test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &treq->flags)) {
			treq->trunc_type = NETFS_TRUNC_SHRINK_NOENC;
			return;
		}

		/* Next case: the file is being shrunk to a logical block
		 * boundary.  We don't need to worry about encryption in this
		 * case.
		 */
		if ((new_i_size & (min_bsize - 1)) == 0) {
			treq->trunc_type = NETFS_TRUNC_SHRINK_TO_ENC_BLOCK;
			return;
		}

		/* Otherwise: the file is being shrunk to mid-block.  We have
		 * to be very careful when altering the partial block to not
		 * corrupt the file.  We need to make sure there's a dirty
		 * region to cover the modified block.
		 */
		treq->trunc_type = NETFS_TRUNC_SHRINK_MID_ENC_BLOCK;
		return;
	}

	treq->trunc_type = NETFS_TRUNC_NO_CHANGE;
}

/*
 * Set up a pair of buffers with which we can perform an RMW cycle to
 * reconstitute the block containing the EOF marker.  One buffer will hold the
 * proposed modification in unencrypted form, the other will hold the
 * encrypted/compressed data.
 *
 * We don't want to make our proposed changes to the pagecache yet as we would
 * have to back them out if an error occurs.
 */
static int netfs_prepare_trunc_buffers(struct netfs_io_request *treq)
{
	struct netfs_inode *ctx = netfs_inode(treq->inode);
	struct iov_iter iter;
	struct folio *folio;
	unsigned long long base;
	pgoff_t from, to, fto;
	size_t offset, seg;
	size_t bsize = max_t(size_t, 1UL << ctx->min_bshift, PAGE_SIZE);
	int ret;

	/* We want to hold the entire replacement block, but we round that out
	 * to a multiple of pages.
	 */
	base = round_down(treq->trunc_i_size, bsize);
	treq->start	= base;
	treq->len	= bsize;
	treq->first	= base / PAGE_SIZE;
	treq->last	= (base + bsize + 1) / PAGE_SIZE;

	ret = netfs_add_folios_to_buffer(&treq->buffer, treq->first, treq->last,
					 GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = netfs_add_folios_to_buffer(&treq->bounce, treq->first, treq->last,
					 GFP_KERNEL);
	if (ret < 0)
		return ret;

	/* We need to fill the buffer. */
	iov_iter_xarray(&iter, READ, &treq->buffer, base, base + bsize);
	do {
		folio = read_mapping_folio(treq->mapping, from, NULL);
		if (IS_ERR(folio))
			return PTR_ERR(folio);
		if (folio->index > from ||
		    folio->index + folio_nr_pages(folio) <= folio->index) {
			folio_put(folio);
			kleave("-EIO [unexpected folio %lx != %lx]", folio->index, from);
			return -EIO;
		}

		offset = (from - folio->index);
		fto = folio->index + folio_nr_pages(folio) - 1;
		seg = min(to, fto);
		seg = (seg - from) + 1;
		kdebug("buf=%lx-%lx fol=%lx-%lx s=%lx@%lx",
		       from, to, folio->index, fto, seg, offset);
		if (copy_folio_to_iter(folio, offset * PAGE_SIZE, seg * PAGE_SIZE, &iter)) {
			folio_put(folio);
			kleave(" = -EIO [copy failure]");
			return -EIO;
		}

		/* We keep the refs to discard later - we don't want read
		 * interfering with what we're up to.
		 */
		from = fto;
	} while (from < to);

	/* Lock the folios and clear the uptodate flag.  Read must wait. */

	/* Clear the region after the new EOF */
	iov_iter_xarray(&iter, READ, &treq->buffer, base, base + bsize);
	iov_iter_advance(&iter, treq->trunc_i_size - treq->start);
	iov_iter_zero(iov_iter_count(&iter), &iter);
	return 0;
}

/*
 * Flush all outstanding writes prior to rearranging file.
 */
static void netfs_truncate_preflush(struct netfs_inode *ctx)
{
	filemap_write_and_wait(ctx->inode.i_mapping);
}

/**
 * netfs_prepare_to_truncate - Prepare to truncate a file
 * @dentry: The file to be modified.
 * @attr: The attribute set from truncate
 *
 * Prepare to change the size of a file.  This may mean trimming the dirty
 * region list, altering an encrypted block, updating the server or even fully
 * flushing the data.
 *
 * The caller holds an exclusive lock on the inode.
 */
struct netfs_io_request *netfs_prepare_to_truncate(struct dentry *dentry,
						   struct iattr *attr)
{
	struct netfs_io_request *treq;
	struct netfs_inode *ctx = netfs_inode(d_inode(dentry));
	loff_t i_size;
	bool need_flush;
	int ret;

	if (!S_ISREG(ctx->inode.i_mode))
		return (attr->ia_valid & ATTR_SIZE) ? ERR_PTR(-EISDIR) : NULL;

	/* Flush any dirty data outstanding on a regular file */
	need_flush = attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID);
	if (!(attr->ia_valid & ATTR_SIZE))
		goto no_size_change;

	i_size = i_size_read(&ctx->inode);
	if (attr->ia_size == i_size)
		goto no_change_in_size;

	ret = inode_newsize_ok(&ctx->inode, attr->ia_size);
	if (ret)
		return ERR_PTR(ret);

	/* Flush all outstanding older flush groups to get them out of the way
	 * before we start rearranging the file contents.
	 */
	// TODO

	/* Set up a truncation record to track what we need to do. */
	treq = netfs_alloc_truncation(ctx, attr);
	if (IS_ERR(treq))
		return ERR_CAST(treq);

	treq->trunc_i_size = attr->ia_size;
	netfs_assess_truncation(ctx, treq);

	/* Invalidate any PTEs applying to folios in the region. */
	//unmap_mapping_pages(treq->mapping, attr->ia_size / PAGE_SIZE, 0, false);

	/* If we're doing encryption, we may need to create a separate buffer
	 * with a copy of the data in it, truncated appropriately, so that we
	 * can encrypt it and try writing it without changing what's in the
	 * pagecache in case we have to revert.
	 */
	switch (treq->trunc_type) {
	case NETFS_TRUNC_GROW_MID_ENC_BLOCK:
	case NETFS_TRUNC_SHRINK_MID_ENC_BLOCK:
		ret = netfs_prepare_trunc_buffers(treq);
		if (ret < 0)
			goto failed;
		break;
	default:
		treq->start	= treq->trunc_i_size;
		treq->len	= 0;
		break;
	}

	return treq;

failed:
	netfs_put_request(treq, false, netfs_rreq_trace_put_discard);
	return ERR_PTR(ret);

no_change_in_size:
	attr->ia_valid &= ~ATTR_SIZE;
no_size_change:
	if (need_flush)
		netfs_truncate_preflush(ctx);
	return NULL;
}
EXPORT_SYMBOL(netfs_prepare_to_truncate);

/**
 * netfs_truncate - Apply truncation to a file
 * @treq: The truncation operation to be applied
 *
 * Apply a change of size to a file after it has been created on the server.
 * This may mean trimming the dirty region list, altering an encrypted block,
 * updating the server or even fully flushing the data.
 *
 * The caller must cache the original i_size and supply it here as it may have
 * already changed inode->i_size so that stat() reports correctly.
 *
 * The caller must hold an exclusive lock on the inode.
 */
void netfs_truncate(struct netfs_io_request *treq)
{
	struct netfs_dirty_region *r, *p;
	struct netfs_inode *ctx = netfs_inode(treq->inode);
	LIST_HEAD(graveyard);
	//unsigned int min_bsize = 1U << ctx->min_bshift;
	loff_t cur_i_size = treq->i_size;
	loff_t new_i_size = treq->trunc_i_size;

	_enter("%llx,%llx", cur_i_size, new_i_size);

	trace_netfs_truncate(treq, cur_i_size, new_i_size);

	switch (treq->trunc_type) {
	case NETFS_TRUNC_NO_CHANGE:
		return;

	case NETFS_TRUNC_GROW_LOCALLY:
	case NETFS_TRUNC_GROW_NOENC:
		pagecache_isize_extended(treq->inode, cur_i_size, new_i_size);
		return;

	case NETFS_TRUNC_GROW_TO_ENC_BLOCK:
	case NETFS_TRUNC_SHRINK_TO_ZERO:
		goto just_trim_dirty_list;
	case NETFS_TRUNC_SHRINK_LOCALLY:
		goto just_trim_dirty_list;
	case NETFS_TRUNC_SHRINK_NOENC:
	case NETFS_TRUNC_SHRINK_TO_ENC_BLOCK:
		goto just_trim_dirty_list;
	case NETFS_TRUNC_SHRINK_MID_ENC_BLOCK:
	case NETFS_TRUNC_GROW_MID_ENC_BLOCK:
		BUG();
	}




just_trim_dirty_list:
	spin_lock(&ctx->dirty_lock);
	list_for_each_entry_safe_reverse(r, p, &ctx->dirty_regions, dirty_link) {
		if (r->to <= new_i_size)
			break;
		if (r->from < new_i_size) {
			/* This region straddles the new EOF. */
			r->from = new_i_size;
			trace_netfs_dirty(ctx, r, NULL, netfs_dirty_trace_truncated);
			break;
		}

		list_move_tail(&r->dirty_link, &graveyard);
		trace_netfs_dirty(ctx, r, NULL, netfs_dirty_trace_cancel);
	}
	spin_unlock(&ctx->dirty_lock);

	while ((r = list_first_entry_or_null(&graveyard,
					     struct netfs_dirty_region,
					     dirty_link))) {
		list_del_init(&r->dirty_link);
		netfs_put_dirty_region(ctx, r, netfs_region_trace_put_truncated);
	}

	truncate_pagecache(treq->inode, new_i_size);
	netfs_resize_file(ctx, new_i_size);
	fscache_resize_cookie(netfs_i_cookie(ctx), new_i_size);
}
EXPORT_SYMBOL(netfs_truncate);
