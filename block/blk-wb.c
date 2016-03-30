/*
 * buffered writeback throttling
 *
 * Copyright (C) 2016 Jens Axboe
 *
 * Things that need changing:
 *
 *	- Auto-detection of optimal wb_percent setting. A lower setting
 *	  is appropriate on rotating storage (wb_percent=15 gives good
 *	  separation, while still getting full bandwidth with wb cache).
 *
 */
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

#include "blk.h"
#include "blk-wb.h"

static inline bool rwb_enabled(struct rq_wb *rwb)
{
	return rwb->wb_normal != 0;
}

void __blk_wb_done(struct rq_wb *rwb)
{
	int inflight, limit = rwb->wb_normal;

	inflight = atomic_dec_return(&rwb->inflight);
	if (inflight >= limit)
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
		int diff = limit - inflight;

		if (diff >= rwb->wb_idle / 2)
			wake_up_nr(&rwb->wait, 1);
	}
}

/*
 * Called on completion of a request. Note that it's also called when
 * a request is merged, when the request gets freed.
 */
void blk_wb_done(struct rq_wb *rwb, struct request *rq)
{
	if (!(rq->cmd_flags & REQ_BUF_INFLIGHT)) {
		if (rwb_enabled(rwb)) {
			const unsigned long cur = jiffies;

			if (cur != rwb->last_comp)
				rwb->last_comp = cur;
		}
	} else
		__blk_wb_done(rwb);
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

static inline unsigned int get_limit(struct rq_wb *rwb, unsigned int rw)
{
	unsigned int limit;

	/*
	 * At this point we know it's a buffered write. If REQ_SYNC is
	 * set, then it's WB_SYNC_ALL writeback. Bump the limit 4x for
	 * those, since someone is (or will be) waiting on that.
	 */
	if ((rw & REQ_SYNC) || *rwb->bdp_wait)
		limit = rwb->wb_max;
	else if (time_before(jiffies, rwb->last_comp + HZ / 10)) {
		/*
		 * If less than 100ms since we completed unrelated IO,
		 * limit us to half the depth for background writeback.
		 */
		limit = rwb->wb_idle;
	} else
		limit = rwb->wb_normal;

	return limit;
}

/*
 * Block if we will exceed our limit, or if we are currently waiting for
 * the timer to kick off queuing again.
 */
static void __blk_wb_wait(struct rq_wb *rwb, unsigned int rw, spinlock_t *lock)
{
	DEFINE_WAIT(wait);

	if (!timer_pending(&rwb->timer) &&
	    atomic_inc_below(&rwb->inflight, get_limit(rwb, rw)))
		return;

	do {
		prepare_to_wait_exclusive(&rwb->wait, &wait,
						TASK_UNINTERRUPTIBLE);

		if (!timer_pending(&rwb->timer) &&
		    atomic_inc_below(&rwb->inflight, get_limit(rwb, rw)))
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
bool blk_wb_wait(struct rq_wb *rwb, struct bio *bio, spinlock_t *lock)
{
	/*
	 * If disabled, or not a WRITE (or a discard), do nothing
	 */
	if (!rwb_enabled(rwb) || !(bio->bi_rw & REQ_WRITE) ||
	    (bio->bi_rw & REQ_DISCARD))
		return false;

	/*
	 * Don't throttle WRITE_ODIRECT
	 */
	if ((bio->bi_rw & (REQ_SYNC | REQ_NOIDLE)) == REQ_SYNC)
		return false;

	__blk_wb_wait(rwb, bio->bi_rw, lock);
	return true;
}

static void calc_wb_limits(struct rq_wb *rwb, unsigned int depth,
			   unsigned int perc)
{
	/*
	 * We'll use depth==64 as a reasonable max limit that should be able
	 * to achieve full device bandwidth anywhere.
	 */
	depth = min(64U, depth);

	/*
	 * Full perf writes are max 'perc' percentage of the depth
	 */
	rwb->wb_max = (perc * depth + 1) / 100;
	if (!rwb->wb_max && perc)
		rwb->wb_max = 1;
	rwb->wb_normal = (rwb->wb_max + 1) / 2;
	rwb->wb_idle = (rwb->wb_max + 3) / 4;
}

void blk_wb_update_limits(struct rq_wb *rwb, unsigned int depth)
{
	calc_wb_limits(rwb, depth, rwb->perc);
	wake_up_all(&rwb->wait);
}

static void blk_wb_timer(unsigned long data)
{
	struct rq_wb *rwb = (struct rq_wb *) data;

	if (waitqueue_active(&rwb->wait))
		wake_up_nr(&rwb->wait, 1);
}

#define DEF_WB_PERC		50
#define DEF_WB_CACHE_DELAY	10000

int blk_wb_init(struct request_queue *q)
{
	struct rq_wb *rwb;

	rwb = kzalloc(sizeof(*rwb), GFP_KERNEL);
	if (!rwb)
		return -ENOMEM;

	atomic_set(&rwb->inflight, 0);
	init_waitqueue_head(&rwb->wait);
	rwb->last_comp = jiffies;
	rwb->bdp_wait = &q->backing_dev_info.wb.dirty_sleeping;
	setup_timer(&rwb->timer, blk_wb_timer, (unsigned long) rwb);
	rwb->perc = DEF_WB_PERC;
	rwb->cache_delay_usecs = DEF_WB_CACHE_DELAY;
	rwb->cache_delay = usecs_to_jiffies(rwb->cache_delay);
	rwb->q = q;
	blk_wb_update_limits(rwb, blk_queue_depth(q));
	q->rq_wb = rwb;
	return 0;
}

void blk_wb_exit(struct request_queue *q)
{
	if (q->rq_wb)
		del_timer_sync(&q->rq_wb->timer);

	kfree(q->rq_wb);
	q->rq_wb = NULL;
}
