/*
 * buffered writeback throttling
 *
 * Copyright (C) 2016 Jens Axboe
 *
 * Things that need changing:
 *
 *	- Auto-detection of most of this, no tunables. Cache type we can get,
 *	  and most other settings we can tweak/gather based on time.
 *	- Better solution for rwb->bdp_wait?
 *	- Higher depth for WB_SYNC_ALL?
 *
 */
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

#include "blk.h"
#include "blk-wb.h"

void __blk_buffered_writeback_done(struct rq_wb *rwb)
{
	int inflight;

	inflight = atomic_dec_return(&rwb->inflight);
	if (inflight >= rwb->limit)
		return;

	/*
	 * If the device does caching, we can still flood it with IO
	 * even at a low depth. If caching is on, delay a bit before
	 * submitting the next, if we're still purely background
	 * activity.
	 */
	if (test_bit(QUEUE_FLAG_WC, &rwb->q->queue_flags) && !*rwb->bdp_wait &&
	    time_before(jiffies, rwb->last_comp + rwb->cache_delay)) {
		if (!timer_pending(&rwb->timer))
			mod_timer(&rwb->timer, jiffies + rwb->cache_delay);
		return;
	}

	if (waitqueue_active(&rwb->wait)) {
		int diff = rwb->limit - inflight;

		if (diff >= rwb->batch)
			wake_up_nr(&rwb->wait, 1);
	}
}

/*
 * Called on completion of a request. Note that it's also called when
 * a request is merged, when the request gets freed.
 */
void blk_buffered_writeback_done(struct rq_wb *rwb, struct request *rq)
{
	if (!(rq->cmd_flags & REQ_BUF_INFLIGHT)) {
		const unsigned long cur = jiffies;

		if (rwb->limit && cur != rwb->last_comp)
			rwb->last_comp = cur;
	} else
		__blk_buffered_writeback_done(rwb);
}

/*
 * Increment 'v', if 'v' is below 'below'. Returns true if we succeeded,
 * false if 'v' + 1 would be bigger than 'below'.
 */
static bool atomic_inc_below(atomic_t *v, int below)
{
	int cur = atomic_read(v);

	for (;;) {
		int old;

		if (cur >= below)
			return false;
		old = atomic_cmpxchg(v, cur, cur + 1);
		if (old == cur)
			break;
		cur = old;
	}

	return true;
}

/*
 * Block if we will exceed our limit, or if we are currently waiting for
 * the timer to kick off queuing again.
 */
static void __blk_buffered_writeback_wait(struct rq_wb *rwb, unsigned int limit,
					  spinlock_t *lock)
{
	DEFINE_WAIT(wait);

	if (!timer_pending(&rwb->timer) &&
	    atomic_inc_below(&rwb->inflight, limit))
		return;

	do {
		prepare_to_wait_exclusive(&rwb->wait, &wait,
						TASK_UNINTERRUPTIBLE);

		if (!timer_pending(&rwb->timer) &&
		    atomic_inc_below(&rwb->inflight, limit))
			break;

		if (lock)
			spin_unlock_irq(lock);

		io_schedule();

		if (lock)
			spin_lock_irq(lock);
	} while (1);

	finish_wait(&rwb->wait, &wait);
}

/*
 * Returns true if the IO request should be accounted, false if not.
 * May sleep, if we have exceeded the writeback limits. Caller can pass
 * in an irq held spinlock, if it holds one when calling this function.
 * If we do sleep, we'll release and re-grab it.
 */
bool blk_buffered_writeback_wait(struct rq_wb *rwb, struct bio *bio,
				 spinlock_t *lock)
{
	unsigned int limit;

	/*
	 * If disabled, or not a WRITE (or a discard), do nothing
	 */
	if (!rwb->limit || !(bio->bi_rw & REQ_WRITE) ||
	    (bio->bi_rw & REQ_DISCARD))
		return false;

	/*
	 * Don't throttle WRITE_ODIRECT
	 */
	if ((bio->bi_rw & (REQ_SYNC | REQ_NOIDLE)) == REQ_SYNC)
		return false;

	/*
	 * At this point we know it's a buffered write. If REQ_SYNC is
	 * set, then it's WB_SYNC_ALL writeback. Bump the limit 4x for
	 * those, since someone is (or will be) waiting on that.
	 */
	limit = rwb->limit;
	if (bio->bi_rw & REQ_SYNC)
		limit <<= 2;
	else if (limit != 1) {
		/*
		 * If less than 100ms since we completed unrelated IO,
		 * limit us to a depth of 1 for background writeback.
		 */
		if (time_before(jiffies, rwb->last_comp + HZ / 10))
			limit = 1;
		else if (!*rwb->bdp_wait)
			limit >>= 1;
	}

	__blk_buffered_writeback_wait(rwb, limit, lock);
	return true;
}

void blk_update_wb_limit(struct rq_wb *rwb, unsigned int limit)
{
	rwb->limit = limit;
	rwb->batch = rwb->limit / 2;
	if (!rwb->batch && rwb->limit)
		rwb->batch = 1;
	else if (rwb->batch > 4)
		rwb->batch = 4;

	wake_up_all(&rwb->wait);
}

static void blk_buffered_writeback_timer(unsigned long data)
{
	struct rq_wb *rwb = (struct rq_wb *) data;

	if (waitqueue_active(&rwb->wait))
		wake_up_nr(&rwb->wait, 1);
}

#define DEF_WB_LIMIT		4
#define DEF_WB_CACHE_DELAY	10000

int blk_buffered_writeback_init(struct request_queue *q)
{
	struct rq_wb *rwb;

	rwb = kzalloc(sizeof(*rwb), GFP_KERNEL);
	if (!rwb)
		return -ENOMEM;

	atomic_set(&rwb->inflight, 0);
	init_waitqueue_head(&rwb->wait);
	rwb->last_comp = jiffies;
	rwb->bdp_wait = &q->backing_dev_info.wb.dirty_sleeping;
	setup_timer(&rwb->timer, blk_buffered_writeback_timer,
			(unsigned long) rwb);
	rwb->cache_delay_usecs = DEF_WB_CACHE_DELAY;
	rwb->cache_delay = usecs_to_jiffies(rwb->cache_delay);
	rwb->q = q;
	blk_update_wb_limit(rwb, DEF_WB_LIMIT);
	q->rq_wb = rwb;
	return 0;
}

void blk_buffered_writeback_exit(struct request_queue *q)
{
	if (q->rq_wb)
		del_timer_sync(&q->rq_wb->timer);

	kfree(q->rq_wb);
	q->rq_wb = NULL;
}
