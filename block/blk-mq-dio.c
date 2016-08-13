/*
 * Block multiqueue DIO code
 *
 * Copyright (C) 2016 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/smp.h>
#include <linux/uio.h>
#include <linux/task_io_accounting_ops.h>

#include <linux/blk-mq.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-tag.h"

static enum hrtimer_restart blk_mq_poll_timer(struct hrtimer *timer)
{
	struct request *rq = container_of(timer, struct request, hrtimer);

	smp_rmb();
	if (rq->end_io_data)
		wake_up_process(rq->end_io_data);

	return HRTIMER_NORESTART;
}

static bool blk_mq_poll(struct request_queue *q, struct blk_mq_hw_ctx *hctx,
			struct request *rq)
{
	long state;

	/*
	 * This will be replaced with the stats tracking code, using
	 * 'avg_completion_time / 2' as the pre-sleep target. The
	 * timer will also be moved out of struct request.
	 */
	if (q->poll_nsec && !test_bit(REQ_ATOM_POLL_SLEPT, &rq->atomic_flags)) {
		ktime_t kt = ktime_set(0, q->poll_nsec);

		set_bit(REQ_ATOM_POLL_SLEPT, &rq->atomic_flags);
		rq->hrtimer.function = blk_mq_poll_timer;
		hrtimer_start(&rq->hrtimer, kt, HRTIMER_MODE_REL);
		return false;
	}

	state = current->state;
	while (!need_resched()) {
		int ret;

		hctx->poll_invoked++;

		if (test_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags)) {
			set_current_state(TASK_RUNNING);
			return true;
		}

		ret = q->mq_ops->poll(hctx, rq->tag);
		if (ret > 0) {
			hctx->poll_success++;
			set_current_state(TASK_RUNNING);
			return true;
		}

		if (signal_pending_state(state, current))
			set_current_state(TASK_RUNNING);

		if (current->state == TASK_RUNNING)
			return true;
		if (ret < 0)
			break;
		cpu_relax();
	}

	return true;
}

bool blk_poll(struct request_queue *q, blk_qc_t cookie)
{
	struct blk_mq_hw_ctx *hctx;
	struct request *rq;

	if (!q->mq_ops || !q->mq_ops->poll || !blk_qc_t_valid(cookie) ||
	    !test_bit(QUEUE_FLAG_POLL, &q->queue_flags))
		return false;

	hctx = q->queue_hw_ctx[blk_qc_t_to_queue_num(cookie)];
	rq = blk_mq_tag_to_rq(hctx->tags, blk_qc_t_to_tag(cookie));

	return blk_mq_poll(q, hctx, rq);
}
EXPORT_SYMBOL_GPL(blk_poll);

static void dio_rq_end_io(struct request *rq, int error)
{
	smp_rmb();
	if (rq->end_io_data)
		wake_up_process(rq->end_io_data);
}

struct rq_aio_data {
	struct kiocb *iocb;
	unsigned int size;
};

static void dio_rq_end_aio(struct request *rq, int error)
{
	struct rq_aio_data *rad = rq->end_io_data;

	if (!error)
		rad->iocb->ki_complete(rad->iocb, rad->size, 0);
	else
		rad->iocb->ki_complete(rad->iocb, error, 0);

	kfree(rad);
	blk_mq_free_request(rq);
}

static void dio_bio_end_io(struct bio *bio)
{
	if (bio_op(bio) == REQ_OP_READ)
		bio_check_pages_dirty(bio);
	else
		bio_put(bio);
}

/*
 * Sleep/poll until IO completes
 */
static void wait_for_sync_rq(struct request_queue *q, struct request *rq,
			     blk_qc_t cookie, struct blk_map_ctx *bmc)
{
	while (!test_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags)) {
		if ((rq->cmd_flags & REQ_POLL) && blk_poll(q, cookie))
			continue;

		rq->end_io_data = current;
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (test_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags)) {
			set_current_state(TASK_RUNNING);
			break;
		}

		io_schedule();
	}

	if (test_bit(REQ_ATOM_POLL_SLEPT, &rq->atomic_flags))
		clear_bit(REQ_ATOM_POLL_SLEPT, &rq->atomic_flags);

	hrtimer_cancel(&rq->hrtimer);
	blk_mq_free_hctx_request(bmc->hctx, rq);
}

static ssize_t bio_direct_IO(struct request_queue *q, struct bio *bio,
			     struct kiocb *iocb)
{
	const bool is_async = !is_sync_kiocb(iocb);
	ssize_t ret = bio->bi_iter.bi_size;
	struct blk_map_ctx bmc;
	struct bio_vec *bv;
	blk_qc_t cookie;
	struct request *rq;
	int i;

	rq = blk_mq_map_request(q, bio, &bmc);
	if (unlikely(!rq)) {
		ret = -ENOMEM;
		goto error;
	}

	blk_mq_bio_to_request(rq, bio);
	if (!is_async)
		rq->end_io = dio_rq_end_io;
	else {
		struct rq_aio_data *rad;

		rad = kmalloc(sizeof(*rad), GFP_KERNEL);
		if (!rad) {
			blk_mq_free_request(rq);
			ret = -ENOMEM;
			goto error;
		}
		rad->iocb = iocb;
		rad->size = bio->bi_iter.bi_size;
		rq->end_io = dio_rq_end_aio;
		rq->end_io_data = rad;
		bio->bi_end_io = dio_bio_end_io;

		if (bio_op(bio) == REQ_OP_READ)
			bio_set_pages_dirty(bio);
	}

	blk_mq_put_ctx(bmc.ctx);

	cookie = blk_tag_to_qc_t(rq->tag, bmc.hctx->queue_num);

	/*
	 * if async, insert request and run queue. if sync, issue direct
	 */
	if (is_async || blk_mq_direct_issue_request(rq, &cookie))
		blk_mq_insert_request(rq, false, true, false);

	if (is_async)
		return -EIOCBQUEUED;

	wait_for_sync_rq(q, rq, cookie, &bmc);

error:
	/*
	 * Dirty any pages we've DMA'ed into, and free the page
	 */
	bio_for_each_segment_all(bv, bio, i) {
		if (!bv->bv_page)
			continue;
		if (!ret && bio_op(bio) == REQ_OP_READ &&
		    !PageCompound(bv->bv_page))
			set_page_dirty_lock(bv->bv_page);

		put_page(bv->bv_page);
	}

	if (bio->bi_error)
		ret = -EIO;

	bio_put(bio);
	return ret;
}

/*
 * Can fit on the stack, and larger than this the overhead of the old
 * dio code isn't as much of an issue.
 */
#define BLK_DIO_MAX_PAGES	8
#define BLK_DIO_MAX_SZ		(8 * PAGE_SIZE)

static void put_unused_pages(struct page *pages, size_t left, size_t this)
{
	while (left) {
		put_page(pages);
		left -= this;
		this = PAGE_SIZE;
		if (this > left)
			this = left;
		pages++;
	}
}

/*
 * TODO:
 *
 *	- Add support for polled async O_DIRECT
 */
ssize_t blk_direct_IO(struct kiocb *iocb, struct inode *inode,
		      struct iov_iter *iter)
{
	struct block_device *bdev = I_BDEV(inode);
	struct request_queue *q = bdev_get_queue(bdev);
	unsigned blkbits = blksize_bits(bdev_logical_block_size(bdev));
	size_t count = iov_iter_count(iter);
	struct page *pages[BLK_DIO_MAX_PAGES];
	size_t pgoff, this_len, total_len;
	loff_t offset = iocb->ki_pos;
	int i, op, op_flags;
	struct bio *bio;
	ssize_t ret;

	if (!q->mq_ops || test_bit(QUEUE_FLAG_OLDDIO, &q->queue_flags))
		return -EINVAL;
	if ((count > BLK_DIO_MAX_SZ) || count & ((1 << blkbits) - 1))
		return -EINVAL;
	if ((offset | iov_iter_alignment(iter)) & ((1 << blkbits) - 1))
		return -EINVAL;

	ret = iov_iter_get_pages(iter, pages, LONG_MAX,
					BLK_DIO_MAX_PAGES, &pgoff);
	if (ret <= 0)
		return -EFAULT;

	bio = bio_alloc(GFP_KERNEL, (ret + pgoff + PAGE_SIZE - 1) >> PAGE_SHIFT);
	bio->bi_bdev = bdev;
	bio->bi_iter.bi_sector = offset >> blkbits;
	blk_partition_remap(bio);

	total_len = ret;
	i = ret = 0;
	while (total_len) {
		this_len = PAGE_SIZE - pgoff;
		if (this_len > total_len)
			this_len = total_len;

		if (!bio_add_page(bio, pages[i], this_len, pgoff)) {
			put_unused_pages(pages[i], total_len, this_len);
			break;
		}

		total_len -= this_len;
		ret += this_len;
		pgoff = 0;
		i++;
	}

	if (iov_iter_rw(iter) == WRITE) {
		op = REQ_OP_WRITE;
		op_flags = WRITE_ODIRECT;
		count_vm_events(PGPGOUT, ret >> blkbits);
	} else {
		op = REQ_OP_READ;
		op_flags = REQ_SYNC;
		task_io_account_read(ret);
		count_vm_events(PGPGIN, ret >> blkbits);
	}
	if (iocb->ki_flags & IOCB_HIPRI)
		op_flags |= REQ_POLL;

	bio_set_op_attrs(bio, op, op_flags);

	iov_iter_advance(iter, ret);

	return bio_direct_IO(q, bio, iocb);
}
