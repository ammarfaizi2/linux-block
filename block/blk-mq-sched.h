#ifndef BLK_MQ_SCHED_H
#define BLK_MQ_SCHED_H

#include "blk-mq.h"

struct blk_mq_hw_ctx;
struct blk_mq_ctx;
struct request_queue;

struct blk_mq_tags *blk_mq_sched_alloc_requests(unsigned int depth, unsigned int numa_node);
void blk_mq_sched_free_requests(struct blk_mq_tags *tags);

int blk_mq_sched_init_hctx_data(struct request_queue *q, size_t size,
				void (*init)(struct blk_mq_hw_ctx *));
void blk_mq_sched_free_hctx_data(struct request_queue *q,
				 void (*exit)(struct blk_mq_hw_ctx *));

void blk_mq_sched_free_shadow_request(struct blk_mq_tags *tags,
				      struct request *rq);
struct request *blk_mq_sched_alloc_shadow_request(struct request_queue *q,
						  struct blk_mq_alloc_data *data,
						  struct blk_mq_tags *tags,
						  atomic_t *wait_index);
struct request *
blk_mq_sched_request_from_shadow(struct blk_mq_hw_ctx *hctx,
				 struct request *(*get_sched_rq)(struct blk_mq_hw_ctx *));


struct blk_mq_alloc_data {
	/* input parameter */
	struct request_queue *q;
	unsigned int flags;

	/* input & output parameter */
	struct blk_mq_ctx *ctx;
	struct blk_mq_hw_ctx *hctx;
};

static inline void blk_mq_set_alloc_data(struct blk_mq_alloc_data *data,
		struct request_queue *q, unsigned int flags,
		struct blk_mq_ctx *ctx, struct blk_mq_hw_ctx *hctx)
{
	data->q = q;
	data->flags = flags;
	data->ctx = ctx;
	data->hctx = hctx;
}

void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx);

static inline bool
blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (blk_queue_nomerges(q) || !bio_mergeable(bio))
		return false;

	if (e) {
		struct blk_mq_ctx *ctx = blk_mq_get_ctx(q);
		struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

		blk_mq_put_ctx(ctx);
		return e->type->mq_ops.bio_merge(hctx, bio);
	}

	return false;
}

static inline struct request *
blk_mq_sched_get_request(struct request_queue *q, struct bio *bio,
			 struct blk_mq_alloc_data *data)
{
	struct elevator_queue *e = q->elevator;
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	struct request *rq;

	blk_queue_enter_live(q);
	ctx = blk_mq_get_ctx(q);
	hctx = blk_mq_map_queue(q, ctx->cpu);

	blk_mq_set_alloc_data(data, q, 0, ctx, hctx);

	if (e)
		rq = e->type->mq_ops.get_request(q, bio, data);
	else
		rq = __blk_mq_alloc_request(data, bio->bi_opf);

	if (rq)
		data->hctx->queued++;

	return rq;

}

static inline void
blk_mq_sched_insert_request(struct request *rq, bool at_head, bool run_queue,
			    bool async)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

	if (e)
		e->type->mq_ops.insert_request(hctx, rq, at_head);
	else {
		spin_lock(&ctx->lock);
		__blk_mq_insert_request(hctx, rq, at_head);
		spin_unlock(&ctx->lock);
	}

	if (run_queue)
		blk_mq_run_hw_queue(hctx, async);
}

static inline bool
blk_mq_sched_allow_merge(struct request_queue *q, struct request *rq,
			 struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->type->mq_ops.allow_merge)
		return e->type->mq_ops.allow_merge(q, rq, bio);

	return true;
}

static inline void
blk_mq_sched_completed_request(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct elevator_queue *e = hctx->queue->elevator;

	if (e && e->type->mq_ops.completed_request)
		e->type->mq_ops.completed_request(hctx, rq);
}

static inline void blk_mq_sched_started_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (e && e->type->mq_ops.started_request)
		e->type->mq_ops.started_request(rq);
}

static inline void blk_mq_sched_requeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (e && e->type->mq_ops.requeue_request)
		e->type->mq_ops.requeue_request(rq);
}

static inline bool blk_mq_sched_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct elevator_queue *e = hctx->queue->elevator;

	if (e && e->type->mq_ops.has_work)
		return e->type->mq_ops.has_work(hctx);

	return false;
}


#endif
