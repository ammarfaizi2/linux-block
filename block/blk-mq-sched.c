#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blk-mq.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"
#include "blk-wbt.h"

/*
 * Empty set
 */
static const struct blk_mq_ops mq_sched_tag_ops = {
};

void blk_mq_sched_free_requests(struct blk_mq_tags *tags)
{
	blk_mq_free_rq_map(NULL, tags, 0);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_free_requests);

struct blk_mq_tags *blk_mq_sched_alloc_requests(unsigned int depth,
						unsigned int numa_node)
{
	struct blk_mq_tag_set set = {
		.ops		= &mq_sched_tag_ops,
		.nr_hw_queues	= 1,
		.queue_depth	= depth,
		.numa_node	= numa_node,
	};

	return blk_mq_init_rq_map(&set, 0);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_alloc_requests);

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
				void (*init)(struct blk_mq_hw_ctx *))
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		hctx->sched_data = kmalloc_node(size, GFP_KERNEL, hctx->numa_node);
		if (!hctx->sched_data)
			goto error;

		if (init)
			init(hctx);
	}

	return 0;
error:
	blk_mq_sched_free_hctx_data(q, NULL);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(blk_mq_sched_init_hctx_data);

struct request *blk_mq_sched_alloc_shadow_request(struct request_queue *q,
						  struct blk_mq_alloc_data *data,
						  struct blk_mq_tags *tags,
						  atomic_t *wait_index)
{
	struct sbq_wait_state *ws;
	DEFINE_WAIT(wait);
	struct request *rq;
	int tag;

	tag = __sbitmap_queue_get(&tags->bitmap_tags);
	if (tag != -1)
		goto done;

	if (data->flags & BLK_MQ_REQ_NOWAIT)
		return NULL;

	ws = sbq_wait_ptr(&tags->bitmap_tags, wait_index);
	do {
		prepare_to_wait(&ws->wait, &wait, TASK_UNINTERRUPTIBLE);

		tag = __sbitmap_queue_get(&tags->bitmap_tags);
		if (tag != -1)
			break;

		blk_mq_run_hw_queue(data->hctx, false);

		tag = __sbitmap_queue_get(&tags->bitmap_tags);
		if (tag != -1)
			break;

		blk_mq_put_ctx(data->ctx);
		io_schedule();

		data->ctx = blk_mq_get_ctx(data->q);
		data->hctx = blk_mq_map_queue(data->q, data->ctx->cpu);
		finish_wait(&ws->wait, &wait);
		ws = sbq_wait_ptr(&tags->bitmap_tags, wait_index);
	} while (1);

	finish_wait(&ws->wait, &wait);
done:
	rq = tags->rqs[tag];
	rq->tag = tag;
	rq->rq_flags |= RQF_ALLOCED;
	return rq;
}
EXPORT_SYMBOL_GPL(blk_mq_sched_alloc_shadow_request);

void blk_mq_sched_free_shadow_request(struct blk_mq_tags *tags,
				      struct request *rq)
{
	WARN_ON_ONCE(!(rq->rq_flags & RQF_ALLOCED));
	sbitmap_queue_clear(&tags->bitmap_tags, rq->tag, rq->mq_ctx->cpu);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_free_shadow_request);

static void rq_copy(struct request *rq, struct request *src)
{
#define FIELD_COPY(dst, src, name)	((dst)->name = (src)->name)
	FIELD_COPY(rq, src, cpu);
	FIELD_COPY(rq, src, cmd_type);
	FIELD_COPY(rq, src, cmd_flags);
	rq->rq_flags |= (src->rq_flags & (RQF_PREEMPT | RQF_QUIET | RQF_PM | RQF_DONTPREP));
	rq->rq_flags &= ~RQF_IO_STAT;
	FIELD_COPY(rq, src, __data_len);
	FIELD_COPY(rq, src, __sector);
	FIELD_COPY(rq, src, bio);
	FIELD_COPY(rq, src, biotail);
	FIELD_COPY(rq, src, rq_disk);
	FIELD_COPY(rq, src, part);
	FIELD_COPY(rq, src, issue_stat);
	src->issue_stat.time = 0;
	FIELD_COPY(rq, src, nr_phys_segments);
#if defined(CONFIG_BLK_DEV_INTEGRITY)
	FIELD_COPY(rq, src, nr_integrity_segments);
#endif
	FIELD_COPY(rq, src, ioprio);
	FIELD_COPY(rq, src, timeout);

	if (src->cmd_type == REQ_TYPE_BLOCK_PC) {
		FIELD_COPY(rq, src, cmd);
		FIELD_COPY(rq, src, cmd_len);
		FIELD_COPY(rq, src, extra_len);
		FIELD_COPY(rq, src, sense_len);
		FIELD_COPY(rq, src, resid_len);
		FIELD_COPY(rq, src, sense);
		FIELD_COPY(rq, src, retries);
	}

	src->bio = src->biotail = NULL;
}

static void sched_rq_end_io(struct request *rq, int error)
{
	struct request *sched_rq = rq->end_io_data;

	FIELD_COPY(sched_rq, rq, resid_len);
	FIELD_COPY(sched_rq, rq, extra_len);
	FIELD_COPY(sched_rq, rq, sense_len);
	FIELD_COPY(sched_rq, rq, errors);
	FIELD_COPY(sched_rq, rq, retries);

	blk_account_io_completion(sched_rq, blk_rq_bytes(sched_rq));
	blk_account_io_done(sched_rq);

	if (sched_rq->end_io)
		sched_rq->end_io(sched_rq, error);

	blk_mq_free_request(rq);
}

struct request *
blk_mq_sched_request_from_shadow(struct blk_mq_hw_ctx *hctx,
				 struct request *(*get_sched_rq)(struct blk_mq_hw_ctx *))
{
	struct blk_mq_alloc_data data;
	struct request *sched_rq, *rq;

	data.q = hctx->queue;
	data.flags = BLK_MQ_REQ_NOWAIT;
	data.ctx = blk_mq_get_ctx(hctx->queue);
	data.hctx = hctx;

	rq = __blk_mq_alloc_request(&data, 0);
	blk_mq_put_ctx(data.ctx);

	if (!rq) {
		blk_mq_stop_hw_queue(hctx);
		return NULL;
	}

	sched_rq = get_sched_rq(hctx);

	if (!sched_rq) {
		blk_queue_enter_live(hctx->queue);
		__blk_mq_free_request(hctx, data.ctx, rq);
		return NULL;
	}

	WARN_ON_ONCE(!(sched_rq->rq_flags & RQF_ALLOCED));
	rq_copy(rq, sched_rq);
	rq->end_io = sched_rq_end_io;
	rq->end_io_data = sched_rq;

	return rq;
}
EXPORT_SYMBOL_GPL(blk_mq_sched_request_from_shadow);

static void blk_mq_sched_assign_ioc(struct request_queue *q,
				    struct request *rq, struct bio *bio)
{
	struct io_context *ioc = rq_ioc(bio);
	struct io_cq *icq;

	if (!ioc)
		return;

	spin_lock_irq(q->queue_lock);
	icq = ioc_lookup_icq(ioc, q);
	spin_unlock_irq(q->queue_lock);

	if (!icq) {
		if (ioc)
			icq = ioc_create_icq(ioc, q, GFP_ATOMIC);
		if (!icq) {
fail:
			printk_ratelimited("failed icq alloc\n");
			return;
		}
	}

	rq->elv.icq = icq;
	if (blk_mq_sched_get_rq_priv(q, rq))
		goto fail;

	if (icq)
		get_io_context(icq->ioc);
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

	if (e && e->type->ops.mq.get_request)
		rq = e->type->ops.mq.get_request(q, op, data);
	else
		rq = __blk_mq_alloc_request(data, op);

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
	} else
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
			goto done;
		}
		ret = ELEVATOR_NO_MERGE;
	} else if (ret == ELEVATOR_FRONT_MERGE) {
		if (bio_attempt_front_merge(q, rq, bio)) {
			if (!attempt_front_merge(q, rq))
				elv_merged_request(q, rq, ret);
			goto done;
		}
		ret = ELEVATOR_NO_MERGE;
	}
done:
	return ret != ELEVATOR_NO_MERGE;
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

void blk_mq_sched_request_inserted(struct request *rq)
{
	trace_block_rq_insert(rq->q, rq);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_request_inserted);

int blk_mq_sched_init(struct request_queue *q)
{
	int ret;

#if defined(CONFIG_DEFAULT_MQ_NONE)
	return 0;
#endif
#if defined(CONFIG_MQ_IOSCHED_ONLY_SQ)
	if (q->nr_hw_queues > 1)
		return 0;
#endif

	mutex_lock(&q->sysfs_lock);
	ret = elevator_init(q, NULL);
	mutex_unlock(&q->sysfs_lock);

	return ret;
}
