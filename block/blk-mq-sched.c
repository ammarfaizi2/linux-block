#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/blk-mq.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"
#include "blk-wbt.h"

/*
 * Empty set
 */
static struct blk_mq_ops mq_sched_tag_ops = {
	.queue_rq	= NULL,
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

	wbt_done(sched_rq->q->rq_wb, &sched_rq->issue_stat);

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

void __blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
	struct elevator_queue *e = hctx->queue->elevator;
	struct request *rq;
	LIST_HEAD(rq_list);

	if (unlikely(blk_mq_hctx_stopped(hctx)))
		return;

	hctx->run++;

	if (!list_empty(&hctx->dispatch)) {
		spin_lock(&hctx->lock);
		if (!list_empty(&hctx->dispatch))
			list_splice_init(&hctx->dispatch, &rq_list);
		spin_unlock(&hctx->lock);
	}

	while ((rq = e->type->mq_ops.dispatch_request(hctx)) != NULL)
		list_add_tail(&rq->queuelist, &rq_list);

	blk_mq_dispatch_rq_list(hctx, &rq_list);
}
