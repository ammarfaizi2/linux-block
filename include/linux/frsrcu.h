/*
 * Fast-Reader Sleepable Read-Copy Update mechanism for mutual exclusion
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can access it online at
 * http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * Copyright (C) IBM Corporation, 2006, 2015
 *
 * Author: Paul McKenney <paulmck@linux.vnet.ibm.com>
 */

#ifndef _LINUX_FRSRCU_H
#define _LINUX_FRSRCU_H

#include <linux/mutex.h>
#include <linux/rcupdate.h>

struct frsrcu_struct_array {
	int c[2];
};

struct frsrcu_struct {
	int completed;
	struct frsrcu_struct_array __percpu *per_cpu_ref;
	struct mutex mutex;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif /* #ifdef CONFIG_DEBUG_LOCK_ALLOC */
};

#ifdef CONFIG_DEBUG_LOCK_ALLOC

int __init_frsrcu_struct(struct frsrcu_struct *frsp, const char *name,
			 struct lock_class_key *key);

#define init_frsrcu_struct(frsp) \
({ \
	static struct lock_class_key __frsrcu_key; \
	\
	__init_frsrcu_struct((frsp), #frsp, &__frsrcu_key); \
})

#define __FRSRCU_DEP_MAP_INIT(frsrcu_name) .dep_map = { .name = #frsrcu_name },
#else /* #ifdef CONFIG_DEBUG_LOCK_ALLOC */

int init_frsrcu_struct(struct frsrcu_struct *frsp);

#define __FRSRCU_DEP_MAP_INIT(frsrcu_name)
#endif /* #else #ifdef CONFIG_DEBUG_LOCK_ALLOC */

#define __FRSRCU_STRUCT_INIT(name)					\
	{								\
		.completed = -300,					\
		.per_cpu_ref = &name##_frsrcu_array,			\
		.mutex = __MUTEX_INITIALIZER(name.mutex),		\
		__FRSRCU_DEP_MAP_INIT(name)				\
	}

/*
 * define and init a frsrcu struct at build time.
 * dont't call init_frsrcu_struct() nor cleanup_frsrcu_struct() on it.
 */
#define __DEFINE_FRSRCU(name, is_static)				\
	static DEFINE_PER_CPU(struct frsrcu_struct_array, name##_frsrcu_array);\
	is_static struct frsrcu_struct name = __FRSRCU_STRUCT_INIT(name)
#define DEFINE_FRSRCU(name)		__DEFINE_FRSRCU(name, /* not static */)
#define DEFINE_STATIC_FRSRCU(name)	__DEFINE_FRSRCU(name, static)

void cleanup_frsrcu_struct(struct frsrcu_struct *frsp);
int __frsrcu_read_lock(struct frsrcu_struct *frsp) __acquires(frsp);
void __frsrcu_read_unlock(struct frsrcu_struct *frsp, int idx) __releases(frsp);
void synchronize_frsrcu(struct frsrcu_struct *frsp);
void synchronize_frsrcu_expedited(struct frsrcu_struct *frsp);
long frsrcu_batches_completed(struct frsrcu_struct *frsp);

#ifdef CONFIG_DEBUG_LOCK_ALLOC

/**
 * frsrcu_read_lock_held - might we be in FRSRCU read-side critical section?
 *
 * If CONFIG_DEBUG_LOCK_ALLOC is selected, returns nonzero iff in an FRSRCU
 * read-side critical section.  In absence of CONFIG_DEBUG_LOCK_ALLOC,
 * this assumes we are in an FRSRCU read-side critical section unless it can
 * prove otherwise.
 *
 * Checks debug_lockdep_rcu_enabled() to prevent false positives during boot
 * and while lockdep is disabled.
 *
 * Note that if the CPU is in the idle loop from an RCU point of view
 * (ie: that we are in the section between rcu_idle_enter() and
 * rcu_idle_exit()) then frsrcu_read_lock_held() returns false even if
 * the CPU did an frsrcu_read_lock().  The reason for this is that RCU
 * ignores CPUs that are in such a section, considering these as in
 * extended quiescent state, so such a CPU is effectively never in an
 * RCU read-side critical section regardless of what RCU primitives it
 * invokes.  This state of affairs is required --- we need to keep an
 * RCU-free window in idle where the CPU may possibly enter into low
 * power mode. This way we can notice an extended quiescent state to
 * other CPUs that started a grace period. Otherwise we would delay any
 * grace period as long as we run in the idle task.
 *
 * Similarly, we avoid claiming an SRCU read lock held if the current
 * CPU is offline.
 */
static inline int frsrcu_read_lock_held(struct frsrcu_struct *frsp)
{
	if (!debug_lockdep_rcu_enabled())
		return 1;

	if (!rcu_is_watching())
		return 0;
	if (!rcu_lockdep_current_cpu_online())
		return 0;
	return lock_is_held(&frsp->dep_map);
}

#else /* #ifdef CONFIG_DEBUG_LOCK_ALLOC */

static inline int frsrcu_read_lock_held(struct frsrcu_struct *frsp)
{
	return 1;
}

#endif /* #else #ifdef CONFIG_DEBUG_LOCK_ALLOC */

/**
 * frsrcu_dereference_check - fetch FRSRCU-protected pointer for later deref
 * @p: the pointer to fetch and protect for later dereferencing
 * @frsp: pointer to the frsrcu_struct, which is used to check that we
 *	really are in an FRSRCU read-side critical section.
 * @c: condition to check for update-side use
 *
 * If PROVE_RCU is enabled, invoking this outside of an RCU read-side
 * critical section will result in an RCU-lockdep splat, unless @c evaluates
 * to 1.  The @c argument will normally be a logical expression containing
 * lockdep_is_held() calls.
 */
#define frsrcu_dereference_check(p, frsp, c) \
	__rcu_dereference_check((p), frsrcu_read_lock_held(frsp) || (c), __rcu)

/**
 * frsrcu_dereference - fetch FRSRCU-protected pointer for later dereferencing
 * @p: the pointer to fetch and protect for later dereferencing
 * @frsp: pointer to the frsrcu_struct, which is used to check that we
 *	really are in an FRSRCU read-side critical section.
 *
 * Makes rcu_dereference_check() do the dirty work.  If PROVE_RCU
 * is enabled, invoking this outside of an RCU read-side critical
 * section will result in an RCU-lockdep splat.
 */
#define frsrcu_dereference(p, frsp) frsrcu_dereference_check((p), (frsp), 0)

/**
 * frsrcu_read_lock - register a new reader for an FRSRCU-protected structure
 * @frsp: frsrcu_struct in which to register the new reader.
 *
 * Enter an FRSRCU read-side critical section.  Note that FRSRCU read-side
 * critical sections may be nested.  However, it is illegal to
 * call anything that waits on an FRSRCU grace period for the same
 * frsrcu_struct, whether directly or indirectly.  Please note that
 * one way to indirectly wait on an FRSRCU grace period is to acquire
 * a mutex that is held elsewhere while calling synchronize_srcu() or
 * synchronize_srcu_expedited().
 *
 * Note that frsrcu_read_lock() and the matching frsrcu_read_unlock() must
 * occur in the same context, for example, it is illegal to invoke
 * frsrcu_read_unlock() in an irq handler if the matching frsrcu_read_lock()
 * was invoked in process context.
 */
static inline int frsrcu_read_lock(struct frsrcu_struct *frsp) __acquires(frsp)
{
	int retval = __frsrcu_read_lock(frsp);

	rcu_lock_acquire(&(frsp)->dep_map);
	rcu_lockdep_assert(rcu_is_watching(),
			   "frsrcu_read_lock() used illegally while idle");
	return retval;
}

/**
 * frsrcu_read_unlock - unregister old reader from FRSRCU-protected structure
 * @frsp: frsrcu_struct in which to unregister the old reader.
 * @idx: return value from corresponding frsrcu_read_lock().
 *
 * Exit an FRSRCU read-side critical section.
 */
static inline void frsrcu_read_unlock(struct frsrcu_struct *frsp, int idx)
	__releases(frsp)
{
	rcu_lockdep_assert(rcu_is_watching(),
			   "frsrcu_read_unlock() used illegally while idle");
	rcu_lock_release(&(frsp)->dep_map);
	__frsrcu_read_unlock(frsp, idx);
}

/**
 * frsrcu_read_lock_raw - register new reader for FRSRCU-protected structure
 * @frsp: frsrcu_struct in which to register the new reader.
 *
 * Enter an FRSRCU read-side critical section.  Similar to frsrcu_read_lock(),
 * but avoids the RCU-lockdep checking.  This means that it is legal to
 * use frsrcu_read_lock_raw() in one context, for example, in an exception
 * handler, and then have the matching frsrcu_read_unlock_raw() in another
 * context, for example in the task that took the exception.
 *
 * However, the entire FRSRCU read-side critical section must reside within
 * a single task.  For example, beware of using frsrcu_read_lock_raw() in a
 * device interrupt handler and frsrcu_read_unlock() in the interrupted task:
 * This will not work if interrupts are threaded.
 */
static inline int frsrcu_read_lock_raw(struct frsrcu_struct *frsp)
{
	unsigned long flags;
	int ret;

	local_irq_save(flags);
	ret =  __frsrcu_read_lock(frsp);
	local_irq_restore(flags);
	return ret;
}

/**
 * frsrcu_read_unlock_raw - unregister reader from FRSRCU-protected structure
 * @frsp: frsrcu_struct in which to unregister the old reader.
 * @idx: return value from corresponding frsrcu_read_lock_raw().
 *
 * Exit an FRSRCU read-side critical section without lockdep-RCU checking.
 * See frsrcu_read_lock_raw() for more details.
 */
static inline void frsrcu_read_unlock_raw(struct frsrcu_struct *frsp, int idx)
{
	unsigned long flags;

	local_irq_save(flags);
	__frsrcu_read_unlock(frsp, idx);
	local_irq_restore(flags);
}

#endif
