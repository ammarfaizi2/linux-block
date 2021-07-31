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

#ifndef __LINUX_DMA_FENCE_H
#define __LINUX_DMA_FENCE_H

#include <linux/spinlock_types.h>
#include <linux/ktime.h>
#include <linux/err.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>

struct dma_fence;
struct dma_fence_ops;
struct dma_fence_cb;

/**
 * struct dma_fence - software synchronization primitive
 * @refcount: refcount for this fence
 * @ops: dma_fence_ops associated with this fence
 * @rcu: used for releasing fence with kfree_rcu
 * @cb_list: list of all callbacks to call
 * @lock: spin_lock_irqsave used for locking
 * @context: execution context this fence belongs to, returned by
 *           dma_fence_context_alloc()
 * @seqno: the sequence number of this fence inside the execution context,
 * can be compared to decide which fence would be signaled later.
 * @flags: A mask of DMA_FENCE_FLAG_* defined below
 * @timestamp: Timestamp when the fence was signaled.
 * @error: Optional, only valid if < 0, must be set before calling
 * dma_fence_signal, indicates that the fence has completed with an error.
 *
 * the flags member must be manipulated and read using the appropriate
 * atomic ops (bit_*), so taking the spinlock will not be needed most
 * of the time.
 *
 * DMA_FENCE_FLAG_SIGNALED_BIT - fence is already signaled
 * DMA_FENCE_FLAG_TIMESTAMP_BIT - timestamp recorded for fence signaling
 * DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT - enable_signaling might have been called
 * DMA_FENCE_FLAG_USER_BITS - start of the unused bits, can be used by the
 * implementer of the fence for its own purposes. Can be used in different
 * ways by different fence implementers, so do not rely on this.
 *
 * Since atomic bitops are used, this is not guaranteed to be the case.
 * Particularly, if the bit was set, but dma_fence_signal was called right
 * before this bit was set, it would have been able to set the
 * DMA_FENCE_FLAG_SIGNALED_BIT, before enable_signaling was called.
 * Adding a check for DMA_FENCE_FLAG_SIGNALED_BIT after setting
 * DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT closes this race, and makes sure that
 * after dma_fence_signal was called, any enable_signaling call will have either
 * been completed, or never called at all.
 */
struct dma_fence {
	spinlock_t *lock;
	const struct dma_fence_ops *ops;
	/*
	 * We clear the callback list on kref_put so that by the time we
	 * release the fence it is unused. No one should be adding to the
	 * cb_list that they don't themselves hold a reference for.
	 *
	 * The lifetime of the timestamp is similarly tied to both the
	 * rcu freelist and the cb_list. The timestamp is only set upon
	 * signaling while simultaneously notifying the cb_list. Ergo, we
	 * only use either the cb_list of timestamp. Upon destruction,
	 * neither are accessible, and so we can use the rcu. This means
	 * that the cb_list is *only* valid until the signal bit is set,
	 * and to read either you *must* hold a reference to the fence,
	 * and not just the rcu_read_lock.
	 *
	 * Listed in chronological order.
	 */
	union {
		struct list_head cb_list;
		/* @cb_list replaced by @timestamp on dma_fence_signal() */
		ktime_t timestamp;
		/* @timestamp replaced by @rcu on dma_fence_release() */
		struct rcu_head rcu;
	};
	u64 context;
	u64 seqno;
	unsigned long flags;
	struct kref refcount;
	int error;
};

enum dma_fence_flag_bits {
	DMA_FENCE_FLAG_SIGNALED_BIT,
	DMA_FENCE_FLAG_TIMESTAMP_BIT,
	DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT,
	DMA_FENCE_FLAG_USER_BITS, /* must always be last member */
};

typedef void (*dma_fence_func_t)(struct dma_fence *fence,
				 struct dma_fence_cb *cb);

/**
 * struct dma_fence_cb - callback for dma_fence_add_callback()
 * @node: used by dma_fence_add_callback() to append this struct to fence::cb_list
 * @func: dma_fence_func_t to call
 *
 * This struct will be initialized by dma_fence_add_callback(), additional
 * data can be passed along by embedding dma_fence_cb in another struct.
 */
struct dma_fence_cb {
	struct list_head node;
	dma_fence_func_t func;
};

/**
 * struct dma_fence_ops - operations implemented for fence
 *
 */
struct dma_fence_ops {
	/**
	 * @use_64bit_seqno:
	 *
	 * True if this dma_fence implementation uses 64bit seqno, false
	 * otherwise.
	 */
	bool use_64bit_seqno;

	/**
	 * @get_driver_name:
	 *
	 * Returns the driver name. This is a callback to allow drivers to
	 * compute the name at runtime, without having it to store permanently
	 * for each fence, or build a cache of some sort.
	 *
	 * This callback is mandatory.
	 */
	const char * (*get_driver_name)(struct dma_fence *fence);

	/**
	 * @get_timeline_name:
	 *
	 * Return the name of the context this fence belongs to. This is a
	 * callback to allow drivers to compute the name at runtime, without
	 * having it to store permanently for each fence, or build a cache of
	 * some sort.
	 *
	 * This callback is mandatory.
	 */
	const char * (*get_timeline_name)(struct dma_fence *fence);

	/**
	 * @enable_signaling:
	 *
	 * Enable software signaling of fence.
	 *
	 * For fence implementations that have the capability for hw->hw
	 * signaling, they can implement this op to enable the necessary
	 * interrupts, or insert commands into cmdstream, etc, to avoid these
	 * costly operations for the common case where only hw->hw
	 * synchronization is required.  This is called in the first
	 * dma_fence_wait() or dma_fence_add_callback() path to let the fence
	 * implementation know that there is another driver waiting on the
	 * signal (ie. hw->sw case).
	 *
	 * This function can be called from atomic context, but not
	 * from irq context, so normal spinlocks can be used.
	 *
	 * A return value of false indicates the fence already passed,
	 * or some failure occurred that made it impossible to enable
	 * signaling. True indicates successful enabling.
	 *
	 * &dma_fence.error may be set in enable_signaling, but only when false
	 * is returned.
	 *
	 * Since many implementations can call dma_fence_signal() even when before
	 * @enable_signaling has been called there's a race window, where the
	 * dma_fence_signal() might result in the final fence reference being
	 * released and its memory freed. To avoid this, implementations of this
	 * callback should grab their own reference using dma_fence_get(), to be
	 * released when the fence is signalled (through e.g. the interrupt
	 * handler).
	 *
	 * This callback is optional. If this callback is not present, then the
	 * driver must always have signaling enabled.
	 */
	bool (*enable_signaling)(struct dma_fence *fence);

	/**
	 * @signaled:
	 *
	 * Peek whether the fence is signaled, as a fastpath optimization for
	 * e.g. dma_fence_wait() or dma_fence_add_callback(). Note that this
	 * callback does not need to make any guarantees beyond that a fence
	 * once indicates as signalled must always return true from this
	 * callback. This callback may return false even if the fence has
	 * completed already, in this case information hasn't propogated throug
	 * the system yet. See also dma_fence_is_signaled().
	 *
	 * May set &dma_fence.error if returning true.
	 *
	 * This callback is optional.
	 */
	bool (*signaled)(struct dma_fence *fence);

	/**
	 * @wait:
	 *
	 * Custom wait implementation, defaults to dma_fence_default_wait() if
	 * not set.
	 *
	 * Deprecated and should not be used by new implementations. Only used
	 * by existing implementations which need special handling for their
	 * hardware reset procedure.
	 *
	 * Must return -ERESTARTSYS if the wait is intr = true and the wait was
	 * interrupted, and remaining jiffies if fence has signaled, or 0 if wait
	 * timed out. Can also return other error values on custom implementations,
	 * which should be treated as if the fence is signaled. For example a hardware
	 * lockup could be reported like that.
	 */
	signed long (*wait)(struct dma_fence *fence,
			    bool intr, signed long timeout);

	/**
	 * @release:
	 *
	 * Called on destruction of fence to release additional resources.
	 * Can be called from irq context.  This callback is optional. If it is
	 * NULL, then dma_fence_free() is instead called as the default
	 * implementation.
	 */
	void (*release)(struct dma_fence *fence);

	/**
	 * @fence_value_str:
	 *
	 * Callback to fill in free-form debug info specific to this fence, like
	 * the sequence number.
	 *
	 * This callback is optional.
	 */
	void (*fence_value_str)(struct dma_fence *fence, char *str, int size);

	/**
	 * @timeline_value_str:
	 *
	 * Fills in the current value of the timeline as a string, like the
	 * sequence number. Note that the specific fence passed to this function
	 * should not matter, drivers should only use it to look up the
	 * corresponding timeline structures.
	 */
	void (*timeline_value_str)(struct dma_fence *fence,
				   char *str, int size);
};

#endif /* __LINUX_DMA_FENCE_H */
