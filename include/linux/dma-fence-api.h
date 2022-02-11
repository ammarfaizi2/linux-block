/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Fence mechanism for dma-buf to allow for asynchronous dma access
 *
 * Copyright (C) 2012 Canonical Ltd
 * Copyright (C) 2012 Texas Instruments
 *
 * Authors:
 * Rob Clark <robdclark@gmail.com>
 * Maarten Lankhorst <maarten.lankhorst@canonical.com>
 */

#ifndef __LINUX_DMA_FENCE_API_H
#define __LINUX_DMA_FENCE_API_H

#include <linux/kref_api.h>
#include <linux/dma-fence.h>

#include <linux/err.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/ktime.h>

void dma_fence_init(struct dma_fence *fence, const struct dma_fence_ops *ops,
		    spinlock_t *lock, u64 context, u64 seqno);

void dma_fence_release(struct kref *kref);
void dma_fence_free(struct dma_fence *fence);
void dma_fence_describe(struct dma_fence *fence, struct seq_file *seq);

/**
 * dma_fence_put - decreases refcount of the fence
 * @fence: fence to reduce refcount of
 */
static inline void dma_fence_put(struct dma_fence *fence)
{
	if (fence)
		kref_put(&fence->refcount, dma_fence_release);
}

/**
 * dma_fence_get - increases refcount of the fence
 * @fence: fence to increase refcount of
 *
 * Returns the same fence, with refcount increased by 1.
 */
static inline struct dma_fence *dma_fence_get(struct dma_fence *fence)
{
	if (fence)
		kref_get(&fence->refcount);
	return fence;
}

/**
 * dma_fence_get_rcu - get a fence from a dma_resv_list with
 *                     rcu read lock
 * @fence: fence to increase refcount of
 *
 * Function returns NULL if no refcount could be obtained, or the fence.
 */
static inline struct dma_fence *dma_fence_get_rcu(struct dma_fence *fence)
{
	if (kref_get_unless_zero(&fence->refcount))
		return fence;
	else
		return NULL;
}

/**
 * dma_fence_get_rcu_safe  - acquire a reference to an RCU tracked fence
 * @fencep: pointer to fence to increase refcount of
 *
 * Function returns NULL if no refcount could be obtained, or the fence.
 * This function handles acquiring a reference to a fence that may be
 * reallocated within the RCU grace period (such as with SLAB_TYPESAFE_BY_RCU),
 * so long as the caller is using RCU on the pointer to the fence.
 *
 * An alternative mechanism is to employ a seqlock to protect a bunch of
 * fences, such as used by struct dma_resv. When using a seqlock,
 * the seqlock must be taken before and checked after a reference to the
 * fence is acquired (as shown here).
 *
 * The caller is required to hold the RCU read lock.
 */
static inline struct dma_fence *
dma_fence_get_rcu_safe(struct dma_fence __rcu **fencep)
{
	do {
		struct dma_fence *fence;

		fence = rcu_dereference(*fencep);
		if (!fence)
			return NULL;

		if (!dma_fence_get_rcu(fence))
			continue;

		/* The atomic_inc_not_zero() inside dma_fence_get_rcu()
		 * provides a full memory barrier upon success (such as now).
		 * This is paired with the write barrier from assigning
		 * to the __rcu protected fence pointer so that if that
		 * pointer still matches the current fence, we know we
		 * have successfully acquire a reference to it. If it no
		 * longer matches, we are holding a reference to some other
		 * reallocated pointer. This is possible if the allocator
		 * is using a freelist like SLAB_TYPESAFE_BY_RCU where the
		 * fence remains valid for the RCU grace period, but it
		 * may be reallocated. When using such allocators, we are
		 * responsible for ensuring the reference we get is to
		 * the right fence, as below.
		 */
		if (fence == rcu_access_pointer(*fencep))
			return rcu_pointer_handoff(fence);

		dma_fence_put(fence);
	} while (1);
}

#ifdef CONFIG_LOCKDEP
bool dma_fence_begin_signalling(void);
void dma_fence_end_signalling(bool cookie);
void __dma_fence_might_wait(void);
#else
static inline bool dma_fence_begin_signalling(void)
{
	return true;
}
static inline void dma_fence_end_signalling(bool cookie) {}
static inline void __dma_fence_might_wait(void) {}
#endif

int dma_fence_signal(struct dma_fence *fence);
int dma_fence_signal_locked(struct dma_fence *fence);
int dma_fence_signal_timestamp(struct dma_fence *fence, ktime_t timestamp);
int dma_fence_signal_timestamp_locked(struct dma_fence *fence,
				      ktime_t timestamp);
signed long dma_fence_default_wait(struct dma_fence *fence,
				   bool intr, signed long timeout);
int dma_fence_add_callback(struct dma_fence *fence,
			   struct dma_fence_cb *cb,
			   dma_fence_func_t func);
bool dma_fence_remove_callback(struct dma_fence *fence,
			       struct dma_fence_cb *cb);
void dma_fence_enable_sw_signaling(struct dma_fence *fence);

/**
 * dma_fence_is_signaled_locked - Return an indication if the fence
 *                                is signaled yet.
 * @fence: the fence to check
 *
 * Returns true if the fence was already signaled, false if not. Since this
 * function doesn't enable signaling, it is not guaranteed to ever return
 * true if dma_fence_add_callback(), dma_fence_wait() or
 * dma_fence_enable_sw_signaling() haven't been called before.
 *
 * This function requires &dma_fence.lock to be held.
 *
 * See also dma_fence_is_signaled().
 */
static inline bool
dma_fence_is_signaled_locked(struct dma_fence *fence)
{
	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags))
		return true;

	if (fence->ops->signaled && fence->ops->signaled(fence)) {
		dma_fence_signal_locked(fence);
		return true;
	}

	return false;
}

/**
 * dma_fence_is_signaled - Return an indication if the fence is signaled yet.
 * @fence: the fence to check
 *
 * Returns true if the fence was already signaled, false if not. Since this
 * function doesn't enable signaling, it is not guaranteed to ever return
 * true if dma_fence_add_callback(), dma_fence_wait() or
 * dma_fence_enable_sw_signaling() haven't been called before.
 *
 * It's recommended for seqno fences to call dma_fence_signal when the
 * operation is complete, it makes it possible to prevent issues from
 * wraparound between time of issue and time of use by checking the return
 * value of this function before calling hardware-specific wait instructions.
 *
 * See also dma_fence_is_signaled_locked().
 */
static inline bool
dma_fence_is_signaled(struct dma_fence *fence)
{
	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags))
		return true;

	if (fence->ops->signaled && fence->ops->signaled(fence)) {
		dma_fence_signal(fence);
		return true;
	}

	return false;
}

/**
 * __dma_fence_is_later - return if f1 is chronologically later than f2
 * @f1: the first fence's seqno
 * @f2: the second fence's seqno from the same context
 * @ops: dma_fence_ops associated with the seqno
 *
 * Returns true if f1 is chronologically later than f2. Both fences must be
 * from the same context, since a seqno is not common across contexts.
 */
static inline bool __dma_fence_is_later(u64 f1, u64 f2,
					const struct dma_fence_ops *ops)
{
	/* This is for backward compatibility with drivers which can only handle
	 * 32bit sequence numbers. Use a 64bit compare when the driver says to
	 * do so.
	 */
	if (ops->use_64bit_seqno)
		return f1 > f2;

	return (int)(lower_32_bits(f1) - lower_32_bits(f2)) > 0;
}

/**
 * dma_fence_is_later - return if f1 is chronologically later than f2
 * @f1: the first fence from the same context
 * @f2: the second fence from the same context
 *
 * Returns true if f1 is chronologically later than f2. Both fences must be
 * from the same context, since a seqno is not re-used across contexts.
 */
static inline bool dma_fence_is_later(struct dma_fence *f1,
				      struct dma_fence *f2)
{
	if (WARN_ON(f1->context != f2->context))
		return false;

	return __dma_fence_is_later(f1->seqno, f2->seqno, f1->ops);
}

/**
 * dma_fence_later - return the chronologically later fence
 * @f1:	the first fence from the same context
 * @f2:	the second fence from the same context
 *
 * Returns NULL if both fences are signaled, otherwise the fence that would be
 * signaled last. Both fences must be from the same context, since a seqno is
 * not re-used across contexts.
 */
static inline struct dma_fence *dma_fence_later(struct dma_fence *f1,
						struct dma_fence *f2)
{
	if (WARN_ON(f1->context != f2->context))
		return NULL;

	/*
	 * Can't check just DMA_FENCE_FLAG_SIGNALED_BIT here, it may never
	 * have been set if enable_signaling wasn't called, and enabling that
	 * here is overkill.
	 */
	if (dma_fence_is_later(f1, f2))
		return dma_fence_is_signaled(f1) ? NULL : f1;
	else
		return dma_fence_is_signaled(f2) ? NULL : f2;
}

/**
 * dma_fence_get_status_locked - returns the status upon completion
 * @fence: the dma_fence to query
 *
 * Drivers can supply an optional error status condition before they signal
 * the fence (to indicate whether the fence was completed due to an error
 * rather than success). The value of the status condition is only valid
 * if the fence has been signaled, dma_fence_get_status_locked() first checks
 * the signal state before reporting the error status.
 *
 * Returns 0 if the fence has not yet been signaled, 1 if the fence has
 * been signaled without an error condition, or a negative error code
 * if the fence has been completed in err.
 */
static inline int dma_fence_get_status_locked(struct dma_fence *fence)
{
	if (dma_fence_is_signaled_locked(fence))
		return fence->error ?: 1;
	else
		return 0;
}

int dma_fence_get_status(struct dma_fence *fence);

/**
 * dma_fence_set_error - flag an error condition on the fence
 * @fence: the dma_fence
 * @error: the error to store
 *
 * Drivers can supply an optional error status condition before they signal
 * the fence, to indicate that the fence was completed due to an error
 * rather than success. This must be set before signaling (so that the value
 * is visible before any waiters on the signal callback are woken). This
 * helper exists to help catching erroneous setting of #dma_fence.error.
 */
static inline void dma_fence_set_error(struct dma_fence *fence,
				       int error)
{
	WARN_ON(test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags));
	WARN_ON(error >= 0 || error < -MAX_ERRNO);

	fence->error = error;
}

signed long dma_fence_wait_timeout(struct dma_fence *,
				   bool intr, signed long timeout);
signed long dma_fence_wait_any_timeout(struct dma_fence **fences,
				       uint32_t count,
				       bool intr, signed long timeout,
				       uint32_t *idx);

/**
 * dma_fence_wait - sleep until the fence gets signaled
 * @fence: the fence to wait on
 * @intr: if true, do an interruptible wait
 *
 * This function will return -ERESTARTSYS if interrupted by a signal,
 * or 0 if the fence was signaled. Other error values may be
 * returned on custom implementations.
 *
 * Performs a synchronous wait on this fence. It is assumed the caller
 * directly or indirectly holds a reference to the fence, otherwise the
 * fence might be freed before return, resulting in undefined behavior.
 *
 * See also dma_fence_wait_timeout() and dma_fence_wait_any_timeout().
 */
static inline signed long dma_fence_wait(struct dma_fence *fence, bool intr)
{
	signed long ret;

	/* Since dma_fence_wait_timeout cannot timeout with
	 * MAX_SCHEDULE_TIMEOUT, only valid return values are
	 * -ERESTARTSYS and MAX_SCHEDULE_TIMEOUT.
	 */
	ret = dma_fence_wait_timeout(fence, intr, MAX_SCHEDULE_TIMEOUT);

	return ret < 0 ? ret : 0;
}

struct dma_fence *dma_fence_get_stub(void);
struct dma_fence *dma_fence_allocate_private_stub(void);
u64 dma_fence_context_alloc(unsigned num);

extern const struct dma_fence_ops dma_fence_array_ops;
extern const struct dma_fence_ops dma_fence_chain_ops;

/**
 * dma_fence_is_array - check if a fence is from the array subclass
 * @fence: the fence to test
 *
 * Return true if it is a dma_fence_array and false otherwise.
 */
static inline bool dma_fence_is_array(struct dma_fence *fence)
{
	return fence->ops == &dma_fence_array_ops;
}

/**
 * dma_fence_is_chain - check if a fence is from the chain subclass
 * @fence: the fence to test
 *
 * Return true if it is a dma_fence_chain and false otherwise.
 */
static inline bool dma_fence_is_chain(struct dma_fence *fence)
{
	return fence->ops == &dma_fence_chain_ops;
}

/**
 * dma_fence_is_container - check if a fence is a container for other fences
 * @fence: the fence to test
 *
 * Return true if this fence is a container for other fences, false otherwise.
 * This is important since we can't build up large fence structure or otherwise
 * we run into recursion during operation on those fences.
 */
static inline bool dma_fence_is_container(struct dma_fence *fence)
{
	return dma_fence_is_array(fence) || dma_fence_is_chain(fence);
}

#endif /* __LINUX_DMA_FENCE_API_H */
