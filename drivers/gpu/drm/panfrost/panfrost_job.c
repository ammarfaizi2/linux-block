// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 Linaro, Ltd, Rob Herring <robh@kernel.org> */
/* Copyright 2019 Collabora ltd. */
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/reservation.h>
#include <drm/gpu_scheduler.h>
#include <drm/panfrost_drm.h>

#include "panfrost_device.h"
#include "panfrost_job.h"
#include "panfrost_features.h"
#include "panfrost_issues.h"
#include "panfrost_gem.h"
#include "panfrost_regs.h"

#define job_write(dev, reg, data) writel(data, dev->iomem + (reg))
#define job_read(dev, reg) readl(dev->iomem + (reg))

struct panfrost_queue_state {
	struct drm_gpu_scheduler sched;

	u64 fence_context;
	u64 emit_seqno;
};

struct panfrost_job_slot {
	struct panfrost_queue_state queue[NUM_JOB_SLOTS];
	spinlock_t job_lock;
};

static struct panfrost_job *
to_panfrost_job(struct drm_sched_job *sched_job)
{
	return container_of(sched_job, struct panfrost_job, base);
}

struct panfrost_fence {
	struct dma_fence base;
	struct drm_device *dev;
	/* panfrost seqno for signaled() test */
	u64 seqno;
	int queue;
};

static inline struct panfrost_fence *
to_panfrost_fence(struct dma_fence *fence)
{
	return (struct panfrost_fence *)fence;
}

static const char *panfrost_fence_get_driver_name(struct dma_fence *fence)
{
	return "panfrost";
}

static const char *panfrost_fence_get_timeline_name(struct dma_fence *fence)
{
	struct panfrost_fence *f = to_panfrost_fence(fence);

	switch (f->queue) {
	case 0:
		return "panfrost-js-0";
	case 1:
		return "panfrost-js-1";
	case 2:
		return "panfrost-js-2";
	default:
		return NULL;
	}
}

static const struct dma_fence_ops panfrost_fence_ops = {
	.get_driver_name = panfrost_fence_get_driver_name,
	.get_timeline_name = panfrost_fence_get_timeline_name,
};

static struct dma_fence *panfrost_fence_create(struct panfrost_device *pfdev, int js_num)
{
	struct panfrost_fence *fence;
	struct panfrost_job_slot *js = pfdev->js;

	fence = kzalloc(sizeof(*fence), GFP_KERNEL);
	if (!fence)
		return ERR_PTR(-ENOMEM);

	fence->dev = pfdev->ddev;
	fence->queue = js_num;
	fence->seqno = ++js->queue[js_num].emit_seqno;
	dma_fence_init(&fence->base, &panfrost_fence_ops, &js->job_lock,
		       js->queue[js_num].fence_context, fence->seqno);

	return &fence->base;
}

static int panfrost_job_get_slot(struct panfrost_job *job)
{
	/* JS0: fragment jobs.
	 * JS1: vertex/tiler jobs
	 * JS2: compute jobs
	 */
	if (job->requirements & PANFROST_JD_REQ_FS)
		return 0;

/* Not exposed to userspace yet */
#if 0
	if (job->requirements & PANFROST_JD_REQ_ONLY_COMPUTE) {
		if ((job->requirements & PANFROST_JD_REQ_CORE_GRP_MASK) &&
		    (job->pfdev->features.nr_core_groups == 2))
			return 2;
		if (panfrost_has_hw_issue(job->pfdev, HW_ISSUE_8987))
			return 2;
	}
#endif
	return 1;
}

static void panfrost_job_write_affinity(struct panfrost_device *pfdev,
					u32 requirements,
					int js)
{
	u64 affinity;

	/*
	 * Use all cores for now.
	 * Eventually we may need to support tiler only jobs and h/w with
	 * multiple (2) coherent core groups
	 */
	affinity = pfdev->features.shader_present;

	job_write(pfdev, JS_AFFINITY_NEXT_LO(js), affinity & 0xFFFFFFFF);
	job_write(pfdev, JS_AFFINITY_NEXT_HI(js), affinity >> 32);
}

static void panfrost_job_hw_submit(struct panfrost_job *job, int js)
{
	struct panfrost_device *pfdev = job->pfdev;
	u32 cfg;
	u64 jc_head = job->jc;

	if (WARN_ON(job_read(pfdev, JS_COMMAND_NEXT(js))))
		return;


	job_write(pfdev, JS_HEAD_NEXT_LO(js), jc_head & 0xFFFFFFFF);
	job_write(pfdev, JS_HEAD_NEXT_HI(js), jc_head >> 32);

	panfrost_job_write_affinity(pfdev, job->requirements, js);

	/* start MMU, medium priority, cache clean/flush on end, clean/flush on
	 * start */
	// TODO: different address spaces
	cfg = JS_CONFIG_THREAD_PRI(8) |
		JS_CONFIG_START_FLUSH_CLEAN_INVALIDATE |
		JS_CONFIG_END_FLUSH_CLEAN_INVALIDATE;

	if (panfrost_has_hw_feature(pfdev, HW_FEATURE_FLUSH_REDUCTION))
		cfg |= JS_CONFIG_ENABLE_FLUSH_REDUCTION;

	if (panfrost_has_hw_issue(pfdev, HW_ISSUE_10649))
		cfg |= JS_CONFIG_START_MMU;

	job_write(pfdev, JS_CONFIG_NEXT(js), cfg);

	if (panfrost_has_hw_feature(pfdev, HW_FEATURE_FLUSH_REDUCTION))
		job_write(pfdev, JS_FLUSH_ID_NEXT(js), job->flush_id);

	/* GO ! */
	dev_dbg(pfdev->dev, "JS: Submitting atom %p to js[%d] with head=0x%llx",
				job, js, jc_head);

	job_write(pfdev, JS_COMMAND_NEXT(js), JS_COMMAND_START);
}

static void panfrost_acquire_object_fences(struct drm_gem_object **bos,
					   int bo_count,
					   struct dma_fence **implicit_fences)
{
	int i;

	for (i = 0; i < bo_count; i++)
		implicit_fences[i] = reservation_object_get_excl_rcu(bos[i]->resv);
}

static void panfrost_attach_object_fences(struct drm_gem_object **bos,
					  int bo_count,
					  struct dma_fence *fence)
{
	int i;

	for (i = 0; i < bo_count; i++)
		reservation_object_add_excl_fence(bos[i]->resv, fence);
}

int panfrost_job_push(struct panfrost_job *job)
{
	struct panfrost_device *pfdev = job->pfdev;
	int slot = panfrost_job_get_slot(job);
	struct drm_sched_entity *entity = &job->file_priv->sched_entity[slot];
	struct ww_acquire_ctx acquire_ctx;
	int ret = 0;

	mutex_lock(&pfdev->sched_lock);

	ret = drm_gem_lock_reservations(job->bos, job->bo_count,
					    &acquire_ctx);
	if (ret) {
		mutex_unlock(&pfdev->sched_lock);
		return ret;
	}

	ret = drm_sched_job_init(&job->base, entity, NULL);
	if (ret) {
		mutex_unlock(&pfdev->sched_lock);
		goto unlock;
	}

	job->render_done_fence = dma_fence_get(&job->base.s_fence->finished);

	kref_get(&job->refcount); /* put by scheduler job completion */

	drm_sched_entity_push_job(&job->base, entity);

	mutex_unlock(&pfdev->sched_lock);

	panfrost_acquire_object_fences(job->bos, job->bo_count,
				       job->implicit_fences);

	panfrost_attach_object_fences(job->bos, job->bo_count,
				      job->render_done_fence);

unlock:
	drm_gem_unlock_reservations(job->bos, job->bo_count, &acquire_ctx);

	return ret;
}

static void panfrost_job_cleanup(struct kref *ref)
{
	struct panfrost_job *job = container_of(ref, struct panfrost_job,
						refcount);
	unsigned int i;

	for (i = 0; i < job->in_fence_count; i++)
		dma_fence_put(job->in_fences[i]);
	kvfree(job->in_fences);

	for (i = 0; i < job->bo_count; i++)
		dma_fence_put(job->implicit_fences[i]);
	kvfree(job->implicit_fences);

	dma_fence_put(job->done_fence);
	dma_fence_put(job->render_done_fence);

	for (i = 0; i < job->bo_count; i++)
		drm_gem_object_put_unlocked(job->bos[i]);
	kvfree(job->bos);

	kfree(job);
}

void panfrost_job_put(struct panfrost_job *job)
{
	kref_put(&job->refcount, panfrost_job_cleanup);
}

static void panfrost_job_free(struct drm_sched_job *sched_job)
{
	struct panfrost_job *job = to_panfrost_job(sched_job);

	drm_sched_job_cleanup(sched_job);

	panfrost_job_put(job);
}

static struct dma_fence *panfrost_job_dependency(struct drm_sched_job *sched_job,
						 struct drm_sched_entity *s_entity)
{
	struct panfrost_job *job = to_panfrost_job(sched_job);
	struct dma_fence *fence;
	unsigned int i;

	/* Explicit fences */
	for (i = 0; i < job->in_fence_count; i++) {
		if (job->in_fences[i]) {
			fence = job->in_fences[i];
			job->in_fences[i] = NULL;
			return fence;
		}
	}

	/* Implicit fences, max. one per BO */
	for (i = 0; i < job->bo_count; i++) {
		if (job->implicit_fences[i]) {
			fence = job->implicit_fences[i];
			job->implicit_fences[i] = NULL;
			return fence;
		}
	}

	return NULL;
}

static struct dma_fence *panfrost_job_run(struct drm_sched_job *sched_job)
{
	struct panfrost_job *job = to_panfrost_job(sched_job);
	struct panfrost_device *pfdev = job->pfdev;
	int slot = panfrost_job_get_slot(job);
	struct dma_fence *fence = NULL;

	if (unlikely(job->base.s_fence->finished.error))
		return NULL;

	pfdev->jobs[slot] = job;

	fence = panfrost_fence_create(pfdev, slot);
	if (IS_ERR(fence))
		return NULL;

	if (job->done_fence)
		dma_fence_put(job->done_fence);
	job->done_fence = dma_fence_get(fence);

	panfrost_job_hw_submit(job, slot);

	return fence;
}

static void panfrost_job_timedout(struct drm_sched_job *sched_job)
{
	struct panfrost_job *job = to_panfrost_job(sched_job);
	struct panfrost_device *pfdev = job->pfdev;
	int js = panfrost_job_get_slot(job);

	job_write(pfdev, JS_COMMAND_NEXT(js), JS_COMMAND_NOP);

	job_write(pfdev, JS_COMMAND(js), JS_COMMAND_HARD_STOP_0);
	dev_err(pfdev->dev, "gpu sched timeout, js=%d, status=0x%x, head=0x%x, tail=0x%x",
		js,
		job_read(pfdev, JS_STATUS(js)),
		job_read(pfdev, JS_HEAD_LO(js)),
		job_read(pfdev, JS_TAIL_LO(js)));

	if (job_read(pfdev, JS_STATUS(js)) == 8) {
//		dev_err(pfdev->dev, "reseting gpu");
//		panfrost_gpu_reset(pfdev);
	}

	/* For now, just say we're done. No reset and retry. */
//	job_write(pfdev, JS_COMMAND(js), JS_COMMAND_HARD_STOP);
	dma_fence_signal(job->done_fence);
}

static const struct drm_sched_backend_ops panfrost_sched_ops = {
	.dependency = panfrost_job_dependency,
	.run_job = panfrost_job_run,
	.timedout_job = panfrost_job_timedout,
	.free_job = panfrost_job_free
};

static const char *job_exception_name(u32 exception_code)
{
	switch (exception_code) {
		/* Non-Fault Status code */
	case 0x00: return "NOT_STARTED/IDLE/OK";
	case 0x01: return "DONE";
	case 0x02: return "INTERRUPTED";
	case 0x03: return "STOPPED";
	case 0x04: return "TERMINATED";
	case 0x08: return "ACTIVE";
		/* Job exceptions */
	case 0x40: return "JOB_CONFIG_FAULT";
	case 0x41: return "JOB_POWER_FAULT";
	case 0x42: return "JOB_READ_FAULT";
	case 0x43: return "JOB_WRITE_FAULT";
	case 0x44: return "JOB_AFFINITY_FAULT";
	case 0x48: return "JOB_BUS_FAULT";
	case 0x50: return "INSTR_INVALID_PC";
	case 0x51: return "INSTR_INVALID_ENC";
	case 0x52: return "INSTR_TYPE_MISMATCH";
	case 0x53: return "INSTR_OPERAND_FAULT";
	case 0x54: return "INSTR_TLS_FAULT";
	case 0x55: return "INSTR_BARRIER_FAULT";
	case 0x56: return "INSTR_ALIGN_FAULT";
	case 0x58: return "DATA_INVALID_FAULT";
	case 0x59: return "TILE_RANGE_FAULT";
	case 0x5A: return "ADDR_RANGE_FAULT";
	case 0x60: return "OUT_OF_MEMORY";
	}

	return "UNKNOWN";
}

static irqreturn_t panfrost_job_irq_handler(int irq, void *data)
{
	struct panfrost_device *pfdev = data;
	u32 status = job_read(pfdev, JOB_INT_STAT);
	int j;

	dev_dbg(pfdev->dev, "jobslot irq status=%x\n", status);

	if (!status)
		return IRQ_NONE;

	for (j = 0; status; j++) {
		u32 mask = MK_JS_MASK(j);

		if (!(status & mask))
			continue;

		job_write(pfdev, JOB_INT_CLEAR, mask);

		if (status & JOB_INT_MASK_ERR(j)) {
			job_write(pfdev, JS_COMMAND_NEXT(j), JS_COMMAND_NOP);
			job_write(pfdev, JS_COMMAND(j), JS_COMMAND_HARD_STOP_0);

			dev_err(pfdev->dev, "js fault, js=%d, status=%s, head=0x%x, tail=0x%x",
				j,
				job_exception_name(job_read(pfdev, JS_STATUS(j))),
				job_read(pfdev, JS_HEAD_LO(j)),
				job_read(pfdev, JS_TAIL_LO(j)));
		}

		if (status & JOB_INT_MASK_DONE(j)) {
			dma_fence_signal(pfdev->jobs[j]->done_fence);
		}

		status &= ~mask;
	}

	return IRQ_HANDLED;
}

int panfrost_job_init(struct panfrost_device *pfdev)
{
	struct panfrost_job_slot *js;
	int ret, j, irq;
	u32 irq_mask = 0;

	pfdev->js = js = devm_kzalloc(pfdev->dev, sizeof(*js), GFP_KERNEL);
	if (!js)
		return -ENOMEM;

	spin_lock_init(&js->job_lock);

	irq = platform_get_irq_byname(to_platform_device(pfdev->dev), "job");
	if (irq <= 0)
		return -ENODEV;

	ret = devm_request_irq(pfdev->dev, irq, panfrost_job_irq_handler,
			       IRQF_SHARED, "job", pfdev);
	if (ret) {
		dev_err(pfdev->dev, "failed to request job irq");
		return ret;
	}

	for (j = 0; j < NUM_JOB_SLOTS; j++) {
		js->queue[j].fence_context = dma_fence_context_alloc(1);

		ret = drm_sched_init(&js->queue[j].sched,
				     &panfrost_sched_ops,
				     1, 0, msecs_to_jiffies(500),
				     "pan_js");
		if (ret) {
			dev_err(pfdev->dev, "Failed to create scheduler: %d.", ret);
			goto err_sched;
		}

		irq_mask |= MK_JS_MASK(j);
	}

	job_write(pfdev, JOB_INT_CLEAR, irq_mask);
	job_write(pfdev, JOB_INT_MASK, irq_mask);

	return 0;

err_sched:
	for (j--; j >= 0; j--)
		drm_sched_fini(&js->queue[j].sched);

	return ret;
}

void panfrost_job_fini(struct panfrost_device *pfdev)
{
	struct panfrost_job_slot *js = pfdev->js;
	int j;

	job_write(pfdev, JOB_INT_MASK, 0);

	for (j = 0; j < NUM_JOB_SLOTS; j++)
		drm_sched_fini(&js->queue[j].sched);

}

int panfrost_job_open(struct panfrost_file_priv *panfrost_priv)
{
	struct panfrost_device *pfdev = panfrost_priv->pfdev;
	struct panfrost_job_slot *js = pfdev->js;
	struct drm_sched_rq *rq;
	int ret, i;

	for (i = 0; i < NUM_JOB_SLOTS; i++) {
		rq = &js->queue[i].sched.sched_rq[DRM_SCHED_PRIORITY_NORMAL];
		ret = drm_sched_entity_init(&panfrost_priv->sched_entity[i], &rq, 1, NULL);
		if (WARN_ON(ret))
			return ret;
	}
	return 0;
}

void panfrost_job_close(struct panfrost_file_priv *panfrost_priv)
{
	int i;

	for (i = 0; i < NUM_JOB_SLOTS; i++)
		drm_sched_entity_destroy(&panfrost_priv->sched_entity[i]);
}
