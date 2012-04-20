/*
 * elevator noop
 */
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>

struct noop_data {
	struct list_head queue;
};

static void noop_merged_requests(struct blk_queue_ctx *ctx, struct request *rq,
				 struct request *next)
{
	lockdep_assert_held(&ctx->lock);
	list_del_init(&next->queuelist);
}

static int noop_dispatch(struct request_queue *q, int force)
{
	struct blk_queue_ctx *ctx;
	struct noop_data *nd;
	unsigned int i, dispatched = 0;

	/*
	 * This obviously needs to me made more clever...
	 */
	queue_for_each_ctx(q, ctx, i) {
		struct request *rq;

		nd = ctx->elevator_data;
		if (list_empty(&nd->queue))
			continue;

		spin_lock(&ctx->lock);
		rq = list_entry(nd->queue.next, struct request, queuelist);
		list_del_init(&rq->queuelist);
		BUG_ON(rq->queue_ctx != ctx);
		elv_dispatch_sort(q, ctx, rq);
		spin_unlock(&ctx->lock);
		dispatched++;
	}

	return dispatched;
}

static void noop_add_request(struct blk_queue_ctx *ctx, struct request *rq)
{
	struct noop_data *nd = ctx->elevator_data;

	lockdep_assert_held(&ctx->lock);
	list_add_tail(&rq->queuelist, &nd->queue);
}

static struct request *
noop_former_request(struct blk_queue_ctx *ctx, struct request *rq)
{
	struct noop_data *nd = ctx->elevator_data;

	if (rq->queuelist.prev == &nd->queue)
		return NULL;
	return list_entry(rq->queuelist.prev, struct request, queuelist);
}

static struct request *
noop_latter_request(struct blk_queue_ctx *ctx, struct request *rq)
{
	struct noop_data *nd = ctx->elevator_data;

	if (rq->queuelist.next == &nd->queue)
		return NULL;
	return list_entry(rq->queuelist.next, struct request, queuelist);
}

static int noop_init_queue(struct request_queue *q, unsigned int nr_queues)
{
	struct noop_data *nd;
	unsigned int i;

	for (i = 0; i < nr_queues; i++) {
		nd = kmalloc_node(sizeof(*nd), GFP_KERNEL, q->node);
		if (!nd)
			goto cleanup;

		INIT_LIST_HEAD(&nd->queue);
		blk_get_ctx(q, i)->elevator_data = nd;
	}

	return 0;

cleanup:
	while (i--)
		kfree(blk_get_ctx(q, i)->elevator_data);

	return -ENOMEM;
}

static void noop_exit_queue(struct request_queue *q, struct elevator_queue *e)
{
	struct blk_queue_ctx *ctx;
	unsigned int i;

	queue_for_each_ctx(q, ctx, i) {
		struct noop_data *nd = ctx->elevator_data;

		BUG_ON(!list_empty(&nd->queue));
		kfree(nd);
	}
}

static struct elevator_type elevator_noop = {
	.ops = {
		.elevator_merge_req_fn		= noop_merged_requests,
		.elevator_dispatch_fn		= noop_dispatch,
		.elevator_add_req_fn		= noop_add_request,
		.elevator_former_req_fn		= noop_former_request,
		.elevator_latter_req_fn		= noop_latter_request,
		.elevator_init_fn		= noop_init_queue,
		.elevator_exit_fn		= noop_exit_queue,
	},
	.elevator_name = "noop",
	.elevator_owner = THIS_MODULE,
};

static int __init noop_init(void)
{
	return elv_register(&elevator_noop);
}

static void __exit noop_exit(void)
{
	elv_unregister(&elevator_noop);
}

module_init(noop_init);
module_exit(noop_exit);


MODULE_AUTHOR("Jens Axboe");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("No-op IO scheduler");
