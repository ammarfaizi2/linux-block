// SPDX-License-Identifier: GPL-2.0-or-later
/* Direct I/O support.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/sched/mm.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/netfs.h>
#include "internal.h"

/*
 * Work out the size of the next subrequest and slice off a chunk of the source
 * buffer.
 */
static bool netfs_dio_rreq_prepare_read(struct netfs_read_request *rreq,
					struct netfs_read_subrequest *subreq,
					struct iov_iter *iter)
{
	struct netfs_i_context *ctx = netfs_i_context(rreq->inode);
	ssize_t n;
	bool ret = false;

	_enter("%llx-%llx,%llx", subreq->start, subreq->start + subreq->len, rreq->i_size);

	/* Call out to the netfs to let it shrink the request to fit its own
	 * I/O sizes and boundaries.  If it shinks it here, it will be called
	 * again to make simultaneous calls; if it wants to make serial calls,
	 * it can indicate a short read and then we will call it again.
	 */
	if (subreq->len > rreq->i_size - subreq->start)
		subreq->len = rreq->i_size - subreq->start;
	if (ctx->rsize && subreq->len > ctx->rsize)
		subreq->len = ctx->rsize;

	if (rreq->netfs_ops->clamp_length) {
		if (!rreq->netfs_ops->clamp_length(subreq))
			goto out;
	}

	if (WARN_ON(subreq->len == 0))
		goto out;

	/* Extract an iterator to represent a segment of the output buffer.
	 * Note that the extraction might not be able to allocate a
	 * sufficiently large bv array and may shorten the request.
	 */
	n = extract_iter_to_iter(iter, subreq->len, &subreq->iter, &subreq->bv);
	if (n < 0) {
		subreq->error = n;
		goto out;
	}

	subreq->bv_count = n;
	subreq->len = iov_iter_count(&subreq->iter);
	ret = true;
out:
	trace_netfs_sreq(subreq, netfs_sreq_trace_prepare);
	return ret;
}

/*
 * Ask the netfs to issue a read request to the server for us.
 *
 * The netfs is expected to read from subreq->pos + subreq->transferred to
 * subreq->pos + subreq->len - 1.  It may not backtrack and write data into the
 * buffer prior to the transferred point as it might clobber dirty data
 * obtained from the cache.
 *
 * Alternatively, the netfs is allowed to indicate one of two things:
 *
 * - NETFS_SREQ_SHORT_READ: A short read - it will get called again to try and
 *   make progress.
 *
 * - NETFS_SREQ_CLEAR_TAIL: A short read - the rest of the buffer will be
 *   cleared.
 */
static void netfs_dio_read_from_server(struct netfs_read_request *rreq,
				       struct netfs_read_subrequest *subreq)
{
	netfs_stat(&netfs_n_rh_download);
	rreq->netfs_ops->issue_op(subreq);
}

/*
 * Slice off a piece of a DIO read request and submit an I/O request for it.
 */
static bool netfs_dio_rreq_submit_slice(struct netfs_read_request *rreq,
					struct iov_iter *iter,
					unsigned int *_debug_index)
{
	struct netfs_read_subrequest *subreq;

	subreq = netfs_alloc_subrequest(rreq);
	if (!subreq)
		return false;

	subreq->debug_index	= (*_debug_index)++;
	subreq->start		= rreq->start + rreq->submitted;
	subreq->len		= rreq->len   - rreq->submitted;
	subreq->source		= NETFS_DOWNLOAD_FROM_SERVER;

	_debug("slice %llx,%zx,%zx", subreq->start, subreq->len, rreq->submitted);
	list_add_tail(&subreq->rreq_link, &rreq->subrequests);

	if (!netfs_dio_rreq_prepare_read(rreq, subreq, iter))
		goto subreq_failed;

	atomic_inc(&rreq->nr_rd_ops);

	rreq->submitted += subreq->len;

	trace_netfs_sreq(subreq, netfs_sreq_trace_submit);
	netfs_dio_read_from_server(rreq, subreq);
	return true;

subreq_failed:
	subreq->source = NETFS_INVALID_READ;
	rreq->error = subreq->error;
	netfs_put_subrequest(subreq, false);
	return false;
}

/**
 * netfs_direct_read_iter - Perform a direct I/O read
 * @iocb: The I/O control descriptor describing the read
 * @iter: The output buffer (also specifies read length)
 */
ssize_t netfs_direct_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct netfs_read_request *rreq;
	unsigned int debug_index = 0;
	ssize_t ret;

	_enter("");

	rreq = netfs_alloc_read_request(iocb->ki_filp->f_mapping,
					iocb->ki_filp,
					iocb->ki_pos, iov_iter_count(iter),
					NETFS_DIO_READ);
	if (IS_ERR(rreq))
		return PTR_ERR(rreq);

	netfs_stat(&netfs_n_rh_readahead);
	trace_netfs_read(rreq, rreq->start, rreq->len, netfs_read_trace_dio_read);

	netfs_get_read_request(rreq);
	atomic_set(&rreq->nr_rd_ops, 1);
	do {
		if (rreq->start + rreq->submitted >= rreq->i_size)
			break;
		if (!netfs_dio_rreq_submit_slice(rreq, iter, &debug_index))
			break;

	} while (rreq->submitted < rreq->len);

	if (is_sync_kiocb(iocb)) {
		/* Synchronous I/O.  Keep nr_rd_ops incremented so that the ref
		 * always belongs to us and the service code isn't punted off
		 * to a random thread pool to process.
		 */
		for (;;) {
			wait_var_event(&rreq->nr_rd_ops, atomic_read(&rreq->nr_rd_ops) == 1);
			netfs_rreq_assess(rreq, false);
			if (!test_bit(NETFS_RREQ_IN_PROGRESS, &rreq->flags))
				break;
			cond_resched();
		}

		ret = rreq->error;
		if (ret == 0 && rreq->submitted < rreq->len) {
			trace_netfs_failure(rreq, NULL, ret, netfs_fail_short_write_begin);
			ret = -EIO;
		}
		if (ret == 0) {
			ret = rreq->len;
			iocb->ki_pos += ret;
		}
	} else {
		/* Asynchronous I/O. */
		rreq->iocb = iocb;
		ret = -EIOCBQUEUED;

		/* If we decrement nr_rd_ops to 0, the ref belongs to us. */
		if (atomic_dec_and_test(&rreq->nr_rd_ops))
			netfs_rreq_assess(rreq, false);
	}


	netfs_put_read_request(rreq, false);
	return ret;
}
EXPORT_SYMBOL(netfs_direct_read_iter);
