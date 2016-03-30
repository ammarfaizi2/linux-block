#ifndef BLK_WB_H
#define BLK_WB_H

#include <linux/atomic.h>
#include <linux/wait.h>

struct rq_wb {
	/*
	 * Settings that govern how we throttle
	 */
	unsigned int perc;			/* INPUT */
	unsigned int wb_idle;			/* idle writeback */
	unsigned int wb_normal;			/* normal writeback */
	unsigned int wb_max;			/* max throughput writeback */

	unsigned int cache_delay;
	unsigned int cache_delay_usecs;
	unsigned long last_comp;
	unsigned int *bdp_wait;
	struct request_queue *q;
	atomic_t inflight;
	wait_queue_head_t wait;
	struct timer_list timer;
};

void __blk_wb_done(struct rq_wb *);
void blk_wb_done(struct rq_wb *, struct request *);
bool blk_wb_wait(struct rq_wb *, struct bio *, spinlock_t *);
int blk_wb_init(struct request_queue *);
void blk_wb_exit(struct request_queue *);
void blk_wb_update_limits(struct rq_wb *, unsigned int);

#endif
