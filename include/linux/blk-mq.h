#ifndef BLK_MQ_H
#define BLK_MQ_H

#include <linux/blkdev.h>

struct request_list {
	/*
	 * count[], starved[], and wait[] are indexed by
	 * BLK_RW_SYNC/BLK_RW_ASYNC
	 */
	int count[2];
	int starved[2];
	int elvpriv;
	wait_queue_head_t wait[2];
};

struct blk_queue_ctx {
	spinlock_t		lock;
	struct elevator_queue	*elevator;
	void			*elevator_data;
	struct request_queue	*queue;
	struct hlist_head	*hash;

	struct request		*last_merge;

	/*
	 * the queue request freelist, one for reads and one for writes
	 */
	struct request_list	rl;

	unsigned int		nr_sorted;
	unsigned int		in_flight[2];

	struct list_head	timeout_list;
};


/*
 * For this initial patch, the mapping will be 1:1 between the queue
 * and the context queues
 */
static inline struct request_queue *blk_ctx_to_queue(struct blk_queue_ctx *ctx)
{
	return ctx->queue;
}

/*
 * Elevator per-context data. Again, this will map to the proper queue
 * when we do support more than 1 context per queue
 */
static inline struct blk_queue_ctx *blk_get_ctx(struct request_queue *q, int nr)
{
	if (nr < q->nr_queues)
		return &q->queue_ctx[nr];

	BUG();
}

#define queue_for_each_ctx(q, ctx, i)					\
	for (i = 0, ctx = &(q)->queue_ctx[0];				\
		i < (q)->nr_queues; i++, ctx++)				\

static inline int __queue_in_flight(struct request_queue *q, int index)
{
	struct blk_queue_ctx *ctx;
	int i, ret;

	ret = 0;
	queue_for_each_ctx(q, ctx, i)
		ret += ctx->in_flight[index];

	return ret;
}

static inline int queue_in_flight(struct request_queue *q)
{
	struct blk_queue_ctx *ctx;
	int i, ret;

	ret = 0;
	queue_for_each_ctx(q, ctx, i)
		ret += ctx->in_flight[0] + ctx->in_flight[1];

	return ret;
}

#endif
