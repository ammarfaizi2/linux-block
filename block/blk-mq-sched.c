/*
 * blk-mq scheduling framework
 *
 * Copyright (C) 2016 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blk-mq.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"
#include "blk-wbt.h"

void blk_mq_sched_free_hctx_data(struct request_queue *q,
				 void (*exit)(struct blk_mq_hw_ctx *))
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (exit)
			exit(hctx);
		kfree(hctx->sched_data);
		hctx->sched_data = NULL;
	}
}
EXPORT_SYMBOL_GPL(blk_mq_sched_free_hctx_data);

int blk_mq_sched_init_hctx_data(struct request_queue *q, size_t size,
				int (*init)(struct blk_mq_hw_ctx *),
				void (*exit)(struct blk_mq_hw_ctx *))
{
	struct blk_mq_hw_ctx *hctx;
	int ret;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		hctx->sched_data = kmalloc_node(size, GFP_KERNEL, hctx->numa_node);
		if (!hctx->sched_data) {
			ret = -ENOMEM;
			goto error;
		}

		if (init) {
			ret = init(hctx);
			if (ret) {
				/*
				 * We don't want to give exit() a partially
				 * initialized sched_data. init() must clean up
				 * if it fails.
				 */
				kfree(hctx->sched_data);
				hctx->sched_data = NULL;
				goto error;
			}
		}
	}

	return 0;
error:
	blk_mq_sched_free_hctx_data(q, exit);
	return ret;
}
EXPORT_SYMBOL_GPL(blk_mq_sched_init_hctx_data);

static void __blk_mq_sched_assign_ioc(struct request_queue *q,
				      struct request *rq, struct io_context *ioc)
{
	struct io_cq *icq;

	spin_lock_irq(q->queue_lock);
	icq = ioc_lookup_icq(ioc, q);
	spin_unlock_irq(q->queue_lock);

	if (!icq) {
		icq = ioc_create_icq(ioc, q, GFP_ATOMIC);
		if (!icq)
			return;
	}

	rq->elv.icq = icq;
	if (!blk_mq_sched_get_rq_priv(q, rq)) {
		get_io_context(icq->ioc);
		return;
	}

	rq->elv.icq = NULL;
}

static void blk_mq_sched_assign_ioc(struct request_queue *q,
				    struct request *rq, struct bio *bio)
{
	struct io_context *ioc;

	ioc = rq_ioc(bio);
	if (ioc)
		__blk_mq_sched_assign_ioc(q, rq, ioc);
}

struct request *blk_mq_sched_get_request(struct request_queue *q,
					 struct bio *bio,
					 unsigned int op,
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

	if (e) {
		data->flags |= BLK_MQ_REQ_INTERNAL;
		if (e->type->ops.mq.get_request)
			rq = e->type->ops.mq.get_request(q, op, data);
		else
			rq = __blk_mq_alloc_request(data, op);
	} else {
		rq = __blk_mq_alloc_request(data, op);
		if (rq) {
			rq->tag = rq->internal_tag;
			rq->internal_tag = -1;
		}
	}

	if (rq) {
		rq->elv.icq = NULL;
		if (e && e->type->icq_cache)
			blk_mq_sched_assign_ioc(q, rq, bio);
		data->hctx->queued++;
		return rq;
	}

	blk_queue_exit(q);
	return NULL;
}

void blk_mq_sched_put_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;

	if (rq->rq_flags & RQF_ELVPRIV) {
		blk_mq_sched_put_rq_priv(rq->q, rq);
		if (rq->elv.icq) {
			put_io_context(rq->elv.icq->ioc);
			rq->elv.icq = NULL;
		}
	}

	if (e && e->type->ops.mq.put_request)
		e->type->ops.mq.put_request(rq);
	else
		blk_mq_finish_request(rq);
}

void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
	struct elevator_queue *e = hctx->queue->elevator;
	LIST_HEAD(rq_list);

	if (unlikely(blk_mq_hctx_stopped(hctx)))
		return;

	hctx->run++;

	/*
	 * If we have previous entries on our dispatch list, grab them first for
	 * more fair dispatch.
	 */
	if (!list_empty_careful(&hctx->dispatch)) {
		spin_lock(&hctx->lock);
		if (!list_empty(&hctx->dispatch))
			list_splice_init(&hctx->dispatch, &rq_list);
		spin_unlock(&hctx->lock);
	}

	/*
	 * Only ask the scheduler for requests, if we didn't have residual
	 * requests from the dispatch list. This is to avoid the case where
	 * we only ever dispatch a fraction of the requests available because
	 * of low device queue depth. Once we pull requests out of the IO
	 * scheduler, we can no longer merge or sort them. So it's best to
	 * leave them there for as long as we can. Mark the hw queue as
	 * needing a restart in that case.
	 */
	if (list_empty(&rq_list)) {
		if (e && e->type->ops.mq.dispatch_requests)
			e->type->ops.mq.dispatch_requests(hctx, &rq_list);
		else
			blk_mq_flush_busy_ctxs(hctx, &rq_list);
	} else if (!test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
		set_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);

	blk_mq_dispatch_rq_list(hctx, &rq_list);
}

bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio)
{
	struct request *rq;
	int ret;

	ret = elv_merge(q, &rq, bio);
	if (ret == ELEVATOR_BACK_MERGE) {
		if (bio_attempt_back_merge(q, rq, bio)) {
			if (!attempt_back_merge(q, rq))
				elv_merged_request(q, rq, ret);
			return true;
		}
	} else if (ret == ELEVATOR_FRONT_MERGE) {
		if (bio_attempt_front_merge(q, rq, bio)) {
			if (!attempt_front_merge(q, rq))
				elv_merged_request(q, rq, ret);
			return true;
		}
	}

	return false;
}
EXPORT_SYMBOL_GPL(blk_mq_sched_try_merge);

bool __blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (e->type->ops.mq.bio_merge) {
		struct blk_mq_ctx *ctx = blk_mq_get_ctx(q);
		struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

		blk_mq_put_ctx(ctx);
		return e->type->ops.mq.bio_merge(hctx, bio);
	}

	return false;
}

bool blk_mq_sched_try_insert_merge(struct request_queue *q, struct request *rq)
{
	return rq_mergeable(rq) && elv_attempt_insert_merge(q, rq);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_try_insert_merge);

void blk_mq_sched_request_inserted(struct request *rq)
{
	trace_block_rq_insert(rq->q, rq);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_request_inserted);

int blk_mq_sched_setup(struct request_queue *q)
{
	struct blk_mq_tag_set *set = q->tag_set;
	struct blk_mq_hw_ctx *hctx;
	int ret, i;

	/*
	 * Default to 256, since we don't split into sync/async like the
	 * old code did. Additionally, this is a per-hw queue depth.
	 */
	q->nr_requests = 2 * BLKDEV_MAX_RQ;

	/*
	 * We're switching to using an IO scheduler, so setup the hctx
	 * scheduler tags and switch the request map from the regular
	 * tags to scheduler tags. First allocate what we need, so we
	 * can safely fail and fallback, if needed.
	 */
	ret = 0;
	queue_for_each_hw_ctx(q, hctx, i) {
		hctx->sched_tags = blk_mq_alloc_rq_map(set, i, q->nr_requests, 0);
		if (!hctx->sched_tags) {
			ret = -ENOMEM;
			break;
		}
		ret = blk_mq_alloc_rqs(set, hctx->sched_tags, i, q->nr_requests);
		if (ret)
			break;
	}

	/*
	 * If we failed, free what we did allocate
	 */
	if (ret) {
		queue_for_each_hw_ctx(q, hctx, i) {
			if (!hctx->sched_tags)
				continue;
			blk_mq_free_rqs(set, hctx->sched_tags, i);
			blk_mq_free_rq_map(hctx->sched_tags);
			hctx->sched_tags = NULL;
		}

		return ret;
	}

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_free_rqs(set, hctx->tags, i);

	return 0;
}

int blk_mq_sched_teardown(struct request_queue *q)
{
	struct blk_mq_tag_set *set = q->tag_set;
	struct blk_mq_hw_ctx *hctx;
	int i, ret;

	ret = 0;
	queue_for_each_hw_ctx(q, hctx, i) {
		ret = blk_mq_alloc_rqs(set, hctx->tags, i, set->queue_depth);
		if (ret)
			break;
	}

	if (ret) {
		queue_for_each_hw_ctx(q, hctx, i)
			blk_mq_free_rqs(set, hctx->tags, i);
		return ret;
	}

	queue_for_each_hw_ctx(q, hctx, i) {
		blk_mq_free_rqs(set, hctx->sched_tags, i);
		blk_mq_free_rq_map(hctx->sched_tags);
		hctx->sched_tags = NULL;
	}

	return 0;
}

int blk_mq_sched_init(struct request_queue *q)
{
	int ret;

#if defined(CONFIG_DEFAULT_SQ_NONE)
	if (q->nr_hw_queues == 1)
		return 0;
#endif
#if defined(CONFIG_DEFAULT_MQ_NONE)
	if (q->nr_hw_queues > 1)
		return 0;
#endif

	mutex_lock(&q->sysfs_lock);
	ret = elevator_init(q, NULL);
	mutex_unlock(&q->sysfs_lock);

	return ret;
}
