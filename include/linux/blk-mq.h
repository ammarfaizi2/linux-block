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


static inline struct blk_queue_ctx *blk_get_ctx(struct request_queue *q, int nr)
{
	BUG_ON(nr >= q->nr_queues);

	return &q->queue_ctx[nr];
}

#define queue_for_each_ctx(q, ctx, i)					\
	for (i = 0, ctx = &(q)->queue_ctx[0];				\
		i < (q)->nr_queues; i++, ctx++)				\

#define blk_ctx_sum(q, sum)						\
({									\
	struct blk_queue_ctx *__ctx;					\
	unsigned int __ret = 0, __i;					\
									\
	queue_for_each_ctx((q), __ctx, __i)				\
		__ret += sum;						\
	__ret;								\
})

static inline int __queue_in_flight(struct request_queue *q, int index)
{
	return blk_ctx_sum(q, __ctx->in_flight[index]);
}

static inline int queue_in_flight(struct request_queue *q)
{
	return blk_ctx_sum(q, __ctx->in_flight[0] + __ctx->in_flight[1]);
}

static inline int queue_rq_queued(struct request_queue *q)
{
	return blk_ctx_sum(q, __ctx->rl.count[0] + __ctx->rl.count[1]);
}

static inline int queue_rq_starved(struct request_queue *q)
{
	return blk_ctx_sum(q, __ctx->rl.starved[0] + __ctx->rl.starved[1]);
}

static inline int queue_elvpriv(struct request_queue *q)
{
	return blk_ctx_sum(q, __ctx->rl.elvpriv);
}

static inline void queue_ctx_lock_queue(struct request_queue *q,
					struct blk_queue_ctx *ctx)
{
	spin_unlock(&ctx->lock);
	spin_lock(q->queue_lock);
}

static inline void queue_ctx_unlock_queue(struct request_queue *q,
					  struct blk_queue_ctx *ctx)
{
	spin_unlock(q->queue_lock);
	spin_lock(&ctx->lock);
}

#endif
