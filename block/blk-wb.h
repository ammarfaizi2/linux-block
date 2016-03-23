#ifndef BLK_WB_H
#define BLK_WB_H

#include <linux/atomic.h>
#include <linux/wait.h>

struct rq_wb {
	unsigned int limit;
	unsigned int batch;
	unsigned int cache_delay;
	unsigned int cache_delay_usecs;
	unsigned long last_comp;
	unsigned int *bdp_wait;
	struct request_queue *q;
	atomic_t inflight;
	wait_queue_head_t wait;
	struct timer_list timer;
};

void __blk_buffered_writeback_done(struct rq_wb *);
void blk_buffered_writeback_done(struct rq_wb *, struct request *);
bool blk_buffered_writeback_wait(struct rq_wb *, struct bio *, spinlock_t *);
int blk_buffered_writeback_init(struct request_queue *);
void blk_buffered_writeback_exit(struct request_queue *);
void blk_update_wb_limit(struct rq_wb *, unsigned int);

#endif
