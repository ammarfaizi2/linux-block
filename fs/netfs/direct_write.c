// SPDX-License-Identifier: GPL-2.0-or-later
/* Direct write support.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/uio.h>
#include "internal.h"

static void netfs_cleanup_dio_write(struct netfs_io_request *wreq)
{
	struct inode *inode = wreq->inode;
	unsigned long long end = wreq->start + wreq->len;

	if (!wreq->error &&
	    i_size_read(inode) < end) {
		if (wreq->netfs_ops->update_i_size)
			wreq->netfs_ops->update_i_size(inode, end);
		else
			i_size_write(inode, end);
	}
}

/*
 * Copy all of the data from the source iterator into folios in the destination
 * xarray.  We cannot step through and kmap the source iterator if it's an
 * iovec, so we have to step through the xarray and drop the RCU lock each
 * time.
 */
static int netfs_copy_iter_to_xarray(struct iov_iter *src, struct xarray *xa,
				     unsigned long long start)
{
	struct folio *folio;
	void *base;
	pgoff_t index = start / PAGE_SIZE;
	size_t len, copied, count = iov_iter_count(src);

	XA_STATE(xas, xa, index);

	_enter("%zx", count);

	if (!count)
		return -EIO;

	len = PAGE_SIZE - offset_in_page(start);
	rcu_read_lock();
	xas_for_each(&xas, folio, ULONG_MAX) {
		size_t offset;

		if (xas_retry(&xas, folio))
			continue;

		/* There shouldn't be a need to call xas_pause() as no one else
		 * can see the xarray we're iterating over.
		 */
		rcu_read_unlock();

		offset = offset_in_folio(folio, start);
		_debug("folio %lx +%zx [%llx]", folio->index, offset, start);

		while (offset < folio_size(folio)) {
			len = min(count, len);

			base = kmap_local_folio(folio, offset);
			copied = copy_from_iter(base, len, src);
			kunmap_local(base);
			if (copied != len)
				goto out;
			count -= len;
			if (count == 0)
				goto out;

			start += len;
			offset += len;
			len = PAGE_SIZE;
		}

		rcu_read_lock();
	}

	rcu_read_unlock();
out:
	_leave(" = %zx", count);
	return count ? -EIO : 0;
}

/*
 * Perform a direct I/O write.
 */
ssize_t netfs_direct_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct netfs_dirty_region *region;
	struct netfs_io_request *wreq;
	struct netfs_inode *ctx = netfs_inode(file_inode(iocb->ki_filp));
	unsigned long long start, end, i_size = i_size_read(&ctx->inode);
	ssize_t ret, n;
	size_t min_bsize = 1UL << ctx->min_bshift;

	_enter("");

	/* Work out what we're actually going to write. */
	start = round_down(iocb->ki_pos, min_bsize);
	end = iocb->ki_pos + iov_iter_count(iter);
	if (end < i_size)
		end = min(round_up(end, min_bsize), i_size);
	_debug("wb %llx-%llx", start, end);

	wreq = netfs_alloc_request(iocb->ki_filp->f_mapping, iocb->ki_filp,
				   start, end - start, NETFS_DIO_WRITE);
	if (IS_ERR(wreq))
		return PTR_ERR(wreq);

	ret = -ENOMEM;
	region = netfs_alloc_dirty_region();
	if (!region)
		goto out;
	region->from = start;
	region->to   = end;
	region->first = start / PAGE_SIZE;
	region->last  = (end - 1) / PAGE_SIZE;

	if (ctx->ops->init_dirty_region)
		ctx->ops->init_dirty_region(region, iocb->ki_filp);
	list_add(&region->dirty_link, &wreq->regions);

	ret = netfs_wait_for_credit(NULL);
	if (ret < 0)
		goto out;
	netfs_deduct_write_credit(region, iov_iter_count(iter));

	if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags)) {
		if (!netfs_is_crypto_aligned(wreq, iter))
			wreq->buffering = NETFS_COPY_ENC_BOUNCE;
		else
			wreq->buffering = NETFS_ENC_DIRECT_TO_BOUNCE;
	} else if (iov_iter_count(iter) <= PAGE_SIZE) {
		/* If the amount of data is small, just buffer it anyway. */
		wreq->buffering = NETFS_BOUNCE;
	} else if (is_sync_kiocb(iocb) && !iter_is_iovec(iter)) {
		wreq->buffering = NETFS_DIRECT;
	} else {
		wreq->buffering = NETFS_DIRECT_BV;
	}

	/* If this is an async op and we're not using a bounce buffer, we have
	 * to save the source buffer as the iterator is only good until we
	 * return.  In such a case, extract an iterator to represent as much of
	 * the the output buffer as we can manage.  Note that the extraction
	 * might not be able to allocate a sufficiently large bvec array and
	 * may shorten the request.
	 */
	switch (wreq->buffering) {
	case NETFS_DIRECT:
	case NETFS_BOUNCE:
	case NETFS_ENC_DIRECT_TO_BOUNCE:
	case NETFS_COPY_ENC_BOUNCE:
		wreq->direct_iter = *iter;
		wreq->len = iov_iter_count(&wreq->direct_iter);
		break;
	case NETFS_DIRECT_BV:
		n = extract_iter_to_iter(iter, wreq->len,
					 &wreq->direct_iter, &wreq->direct_bv);
		if (n < 0) {
			ret = n;
			goto out;
		}
		wreq->direct_bv_count = n;
		wreq->len = iov_iter_count(&wreq->direct_iter);
		break;
	default:
		BUG();
	}

	/* If we're going to use a bounce buffer, we need to set it up.  We
	 * will then need to pad the request out to the minimum block size.
	 */
	switch (wreq->buffering) {
	case NETFS_BOUNCE:
	case NETFS_ENC_DIRECT_TO_BOUNCE:
	case NETFS_COPY_ENC_BOUNCE:
		wreq->first = start / PAGE_SIZE;
		wreq->last  = (end - 1) / PAGE_SIZE;
		_debug("bounce %llx-%llx %lx-%lx",
		       start, end, wreq->first, wreq->last);

		ret = netfs_alloc_buffer(&wreq->bounce, wreq->first,
					 wreq->last - wreq->first + 1);
		if (ret < 0)
			goto out;

		/* Encrypt/copy the data into the bounce buffer and clear any
		 * padding on either end.
		 */
		switch (wreq->buffering) {
		case NETFS_BOUNCE:
		case NETFS_COPY_ENC_BOUNCE:
			_debug("copy");
			iov_iter_xarray(&wreq->direct_iter, READ, &wreq->bounce,
					start, end - start);
			if (wreq->start < iocb->ki_pos) {
				_debug("zero pre");
				iov_iter_zero(iocb->ki_pos - wreq->start,
					      &wreq->direct_iter);
			}
			ret = netfs_copy_iter_to_xarray(iter, &wreq->bounce,
							iocb->ki_pos);
			if (ret < 0) {
				_debug("bad copy");
				goto out;
			}
			iov_iter_advance(&wreq->direct_iter, end - start);
			if (iov_iter_count(&wreq->direct_iter) > 0) {
				_debug("zero post %zx", iov_iter_count(&wreq->direct_iter));
				iov_iter_zero(iov_iter_count(&wreq->direct_iter),
					      &wreq->direct_iter);
			}

			_debug("iter %llx %llx", wreq->start, end - start);
			iov_iter_xarray(&wreq->direct_iter, WRITE, &wreq->bounce,
					wreq->start, end - start);
			wreq->len = end - start;
			break;
		case NETFS_ENC_DIRECT_TO_BOUNCE:
			_debug("direct");
			wreq->direct_iter = *iter;
			break;
		default:
			BUG();
		}

		break;
	default:
		break;
	}

	netfs_get_request(wreq, netfs_rreq_trace_get_hold);
	__set_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags);
	wreq->cleanup = netfs_cleanup_dio_write;
	ret = netfs_begin_write(wreq, is_sync_kiocb(iocb));
	if (ret < 0) {
		_debug("begin = %zd", ret);
		goto out;
	}

	if (is_sync_kiocb(iocb)) {
		trace_netfs_rreq(wreq, netfs_rreq_trace_wait_ip);
		wait_on_bit(&wreq->flags, NETFS_RREQ_IN_PROGRESS,
			    TASK_UNINTERRUPTIBLE);

		ret = wreq->error;
		_debug("waited = %zd", ret);
		if (ret == 0) {
			ret = wreq->transferred;
			iocb->ki_pos += ret;
		}
	} else {
		ret = -EIOCBQUEUED;
	}

out:
	netfs_put_request(wreq, false, netfs_rreq_trace_put_hold);
	return ret;
}
