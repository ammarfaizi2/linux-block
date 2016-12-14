#ifndef BLK_MQ_SCHED_H
#define BLK_MQ_SCHED_H

#include "blk-mq.h"

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

struct request *blk_mq_sched_get_request(struct request_queue *q, struct bio *bio, unsigned int op, struct blk_mq_alloc_data *data);

void __blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx);
void blk_mq_sched_request_inserted(struct request *rq);
bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio);
bool __blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio);

void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx);

static inline bool
blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (!e || blk_queue_nomerges(q) || !bio_mergeable(bio))
		return false;

	return __blk_mq_sched_bio_merge(q, bio);
}

static inline int blk_mq_sched_get_rq_priv(struct request_queue *q,
					   struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->type->ops.mq.get_rq_priv)
		return e->type->ops.mq.get_rq_priv(q, rq);

	return 0;
}

static inline void blk_mq_sched_put_rq_priv(struct request_queue *q,
					    struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->type->ops.mq.put_rq_priv)
		e->type->ops.mq.put_rq_priv(q, rq);
}

static inline void blk_mq_sched_put_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;
	bool do_free = true;

	if (rq->rq_flags & RQF_ELVPRIV) {
		blk_mq_sched_put_rq_priv(rq->q, rq);
		if (rq->elv.icq)
			put_io_context(rq->elv.icq->ioc);
	}

	if (e && e->type->ops.mq.put_request)
		do_free = !e->type->ops.mq.put_request(rq);
	if (do_free)
		blk_mq_free_request(rq);
}

static inline void
blk_mq_sched_insert_request(struct request *rq, bool at_head, bool run_queue,
			    bool async)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

	if (e && e->type->ops.mq.insert_requests) {
		LIST_HEAD(list);

		list_add(&rq->queuelist, &list);
		e->type->ops.mq.insert_requests(hctx, &list, at_head);
	} else {
		spin_lock(&ctx->lock);
		__blk_mq_insert_request(hctx, rq, at_head);
		spin_unlock(&ctx->lock);
	}

	if (run_queue)
		blk_mq_run_hw_queue(hctx, async);
}

static inline void
blk_mq_sched_insert_requests(struct request_queue *q, struct blk_mq_ctx *ctx,
			     struct list_head *list, bool run_queue_async)
{
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);
	struct elevator_queue *e = hctx->queue->elevator;

	if (e && e->type->ops.mq.insert_requests)
		e->type->ops.mq.insert_requests(hctx, list, false);
	else
		blk_mq_insert_requests(hctx, ctx, list);

	blk_mq_run_hw_queue(hctx, run_queue_async);
}

static inline void
blk_mq_sched_dispatch_shadow_requests(struct blk_mq_hw_ctx *hctx,
				      struct list_head *rq_list,
				      struct request *(*get_sched_rq)(struct blk_mq_hw_ctx *))
{
	do {
		struct request *rq;

		rq = blk_mq_sched_request_from_shadow(hctx, get_sched_rq);
		if (!rq)
			break;

		list_add_tail(&rq->queuelist, rq_list);
	} while (1);
}

static inline bool
blk_mq_sched_allow_merge(struct request_queue *q, struct request *rq,
			 struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->type->ops.mq.allow_merge)
		return e->type->ops.mq.allow_merge(q, rq, bio);

	return true;
}

static inline void
blk_mq_sched_completed_request(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct elevator_queue *e = hctx->queue->elevator;

	if (e && e->type->ops.mq.completed_request)
		e->type->ops.mq.completed_request(hctx, rq);

	if (test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state)) {
		clear_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);
		blk_mq_run_hw_queue(hctx, true);
	}
}

static inline void blk_mq_sched_started_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (e && e->type->ops.mq.started_request)
		e->type->ops.mq.started_request(rq);
}

static inline void blk_mq_sched_requeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (e && e->type->ops.mq.requeue_request)
		e->type->ops.mq.requeue_request(rq);
}

static inline bool blk_mq_sched_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct elevator_queue *e = hctx->queue->elevator;

	if (e && e->type->ops.mq.has_work)
		return e->type->ops.mq.has_work(hctx);

	return false;
}
#endif
