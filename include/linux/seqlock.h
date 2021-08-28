/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SEQLOCK_H
#define __LINUX_SEQLOCK_H

/*
 * seqcount_t / seqlock_t - a reader-writer consistency mechanism with
 * lockless readers (read-only retry loops), and no writer starvation.
 *
 * See Documentation/locking/seqlock.rst
 *
 * Copyrights:
 * - Based on x86_64 vsyscall gettimeofday: Keith Owens, Andrea Arcangeli
 * - Sequence counters with associated locks, (C) 2020 Linutronix GmbH
 */

#include <linux/compiler.h>
#include <linux/kcsan-checks.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/ww_mutex.h>
#include <linux/preempt.h>
#include <linux/spinlock.h>

#include <asm/processor.h>

#if defined(CONFIG_LOCKDEP) || defined(CONFIG_PREEMPT_RT)
# include <linux/spinlock_api.h>
# include <linux/ww_mutex.h>
#endif

/*
 * The seqlock seqcount_t interface does not prescribe a precise sequence of
 * read begin/retry/end. For readers, typically there is a call to
 * read_seqcount_begin() and read_seqcount_retry(), however, there are more
 * esoteric cases which do not follow this pattern.
 *
 * As a consequence, we take the following best-effort approach for raw usage
 * via seqcount_t under KCSAN: upon beginning a seq-reader critical section,
 * pessimistically mark the next KCSAN_SEQLOCK_REGION_MAX memory accesses as
 * atomics; if there is a matching read_seqcount_retry() call, no following
 * memory operations are considered atomic. Usage of the seqlock_t interface
 * is not affected.
 */
#define KCSAN_SEQLOCK_REGION_MAX 1000

/*
 * Sequence counters (seqcount_t)
 *
 * This is the raw counting mechanism, without any writer protection.
 *
 * Write side critical sections must be serialized and non-preemptible.
 *
 * If readers can be invoked from hardirq or softirq contexts,
 * interrupts or bottom halves must also be respectively disabled before
 * entering the write section.
 *
 * This mechanism can't be used if the protected data contains pointers,
 * as the writer can invalidate a pointer that a reader is following.
 *
 * If the write serialization mechanism is one of the common kernel
 * locking primitives, use a sequence counter with associated lock
 * (seqcount_LOCKNAME_t) instead.
 *
 * If it's desired to automatically handle the sequence counter writer
 * serialization and non-preemptibility requirements, use a sequential
 * lock (seqlock_t) instead.
 *
 * See Documentation/locking/seqlock.rst
 */
typedef struct seqcount {
	unsigned sequence;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} seqcount_t;

#ifdef CONFIG_DEBUG_LOCK_ALLOC

# define SEQCOUNT_DEP_MAP_INIT(lockname)				\
		.dep_map = { .name = #lockname }

/**
 * seqcount_init() - runtime initializer for seqcount_t
 * @s: Pointer to the seqcount_t instance
 */
# define seqcount_init(s)						\
	do {								\
		static struct lock_class_key __key;			\
		__seqcount_init((s), #s, &__key);			\
	} while (0)

static inline void seqcount_lockdep_reader_access(const seqcount_t *s)
{
	seqcount_t *l = (seqcount_t *)s;
	unsigned long flags;

	local_irq_save(flags);
	seqcount_acquire_read(&l->dep_map, 0, 0, _RET_IP_);
	seqcount_release(&l->dep_map, _RET_IP_);
	local_irq_restore(flags);
}

#else
# define SEQCOUNT_DEP_MAP_INIT(lockname)
# define seqcount_init(s) __seqcount_init(s, NULL, NULL)
# define seqcount_lockdep_reader_access(x)
#endif

/**
 * SEQCNT_ZERO() - static initializer for seqcount_t
 * @name: Name of the seqcount_t instance
 */
#define SEQCNT_ZERO(name) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(name) }

/*
 * Sequence counters with associated locks (seqcount_LOCKNAME_t)
 *
 * A sequence counter which associates the lock used for writer
 * serialization at initialization time. This enables lockdep to validate
 * that the write side critical section is properly serialized.
 *
 * For associated locks which do not implicitly disable preemption,
 * preemption protection is enforced in the write side function.
 *
 * Lockdep is never used in any for the raw write variants.
 *
 * See Documentation/locking/seqlock.rst
 */

/*
 * For PREEMPT_RT, seqcount_LOCKNAME_t write side critical sections cannot
 * disable preemption. It can lead to higher latencies, and the write side
 * sections will not be able to acquire locks which become sleeping locks
 * (e.g. spinlock_t).
 *
 * To remain preemptible while avoiding a possible livelock caused by the
 * reader preempting the writer, use a different technique: let the reader
 * detect if a seqcount_LOCKNAME_t writer is in progress. If that is the
 * case, acquire then release the associated LOCKNAME writer serialization
 * lock. This will allow any possibly-preempted writer to make progress
 * until the end of its writer serialization lock critical section.
 *
 * This lock-unlock technique must be implemented for all of PREEMPT_RT
 * sleeping locks.  See Documentation/locking/locktypes.rst
 */
#if defined(CONFIG_LOCKDEP) || defined(CONFIG_PREEMPT_RT)
#define __SEQ_LOCK(expr)	expr
#else
#define __SEQ_LOCK(expr)
#endif

/*
 * typedef seqcount_LOCKNAME_t - sequence counter with LOCKNAME associated
 * @seqcount:	The real sequence counter
 * @lock:	Pointer to the associated lock
 *
 * A plain sequence counter with external writer synchronization by
 * LOCKNAME @lock. The lock is associated to the sequence counter in the
 * static initializer or init function. This enables lockdep to validate
 * that the write side critical section is properly serialized.
 *
 * LOCKNAME:	raw_spinlock, spinlock, rwlock, mutex, or ww_mutex.
 */

/*
 * seqcount_LOCKNAME_init() - runtime initializer for seqcount_LOCKNAME_t
 * @s:		Pointer to the seqcount_LOCKNAME_t instance
 * @lock:	Pointer to the associated lock
 */

#define seqcount_LOCKNAME_init(s, _lock, lockname)			\
	do {								\
		seqcount_##lockname##_t *____s = (s);			\
		seqcount_init(&____s->seqcount);			\
		__SEQ_LOCK(____s->lock = (_lock));			\
	} while (0)

#define seqcount_raw_spinlock_init(s, lock)	seqcount_LOCKNAME_init(s, lock, raw_spinlock)
#define seqcount_spinlock_init(s, lock)		seqcount_LOCKNAME_init(s, lock, spinlock)
#define seqcount_rwlock_init(s, lock)		seqcount_LOCKNAME_init(s, lock, rwlock)
#define seqcount_mutex_init(s, lock)		seqcount_LOCKNAME_init(s, lock, mutex)
#define seqcount_ww_mutex_init(s, lock)		seqcount_LOCKNAME_init(s, lock, ww_mutex)

/*
 * SEQCOUNT_LOCKNAME()	- Instantiate seqcount_LOCKNAME_t and helpers
 * seqprop_LOCKNAME_*()	- Property accessors for seqcount_LOCKNAME_t
 *
 * @lockname:		"LOCKNAME" part of seqcount_LOCKNAME_t
 * @locktype:		LOCKNAME canonical C data type
 * @preemptible:	preemptibility of above locktype
 * @lockmember:		argument for lockdep_assert_held()
 * @lockbase:		associated lock release function (prefix only)
 * @lock_acquire:	associated lock acquisition function (full call)
 */
#define SEQCOUNT_LOCKNAME(lockname, locktype, preemptible, lockmember, lockbase, lock_acquire) \
typedef struct seqcount_##lockname {					\
	seqcount_t		seqcount;				\
	__SEQ_LOCK(locktype	*lock);					\
} seqcount_##lockname##_t;						\
									\
static __always_inline seqcount_t *					\
__seqprop_##lockname##_ptr(seqcount_##lockname##_t *s)			\
{									\
	return &s->seqcount;						\
}									\
									\
static __always_inline unsigned						\
__seqprop_##lockname##_sequence(const seqcount_##lockname##_t *s)	\
{									\
	unsigned seq = READ_ONCE(s->seqcount.sequence);			\
									\
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))				\
		return seq;						\
									\
	if (preemptible && unlikely(seq & 1)) {				\
		__SEQ_LOCK(lock_acquire);				\
		__SEQ_LOCK(lockbase##_unlock(s->lock));			\
									\
		/*							\
		 * Re-read the sequence counter since the (possibly	\
		 * preempted) writer made progress.			\
		 */							\
		seq = READ_ONCE(s->seqcount.sequence);			\
	}								\
									\
	return seq;							\
}									\
									\
static __always_inline bool						\
__seqprop_##lockname##_preemptible(const seqcount_##lockname##_t *s)	\
{									\
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))				\
		return preemptible;					\
									\
	/* PREEMPT_RT relies on the above LOCK+UNLOCK */		\
	return false;							\
}									\
									\
static __always_inline void						\
__seqprop_##lockname##_assert(const seqcount_##lockname##_t *s)		\
{									\
	__SEQ_LOCK(lockdep_assert_held(lockmember));			\
}

#define __SEQ_RT	IS_ENABLED(CONFIG_PREEMPT_RT)

SEQCOUNT_LOCKNAME(raw_spinlock, raw_spinlock_t,  false,    s->lock,        raw_spin, raw_spin_lock(s->lock))
SEQCOUNT_LOCKNAME(spinlock,     spinlock_t,      __SEQ_RT, s->lock,        spin,     spin_lock(s->lock))
SEQCOUNT_LOCKNAME(rwlock,       rwlock_t,        __SEQ_RT, s->lock,        read,     read_lock(s->lock))
SEQCOUNT_LOCKNAME(mutex,        struct mutex,    true,     s->lock,        mutex,    mutex_lock(s->lock))
SEQCOUNT_LOCKNAME(ww_mutex,     struct ww_mutex, true,     &s->lock->base, ww_mutex, ww_mutex_lock(s->lock, NULL))

/*
 * SEQCNT_LOCKNAME_ZERO - static initializer for seqcount_LOCKNAME_t
 * @name:	Name of the seqcount_LOCKNAME_t instance
 * @lock:	Pointer to the associated LOCKNAME
 */

#define SEQCOUNT_LOCKNAME_ZERO(seq_name, assoc_lock) {			\
	.seqcount		= SEQCNT_ZERO(seq_name.seqcount),	\
	__SEQ_LOCK(.lock	= (assoc_lock))				\
}

#define SEQCNT_RAW_SPINLOCK_ZERO(name, lock)	SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_SPINLOCK_ZERO(name, lock)	SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_RWLOCK_ZERO(name, lock)		SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_MUTEX_ZERO(name, lock)		SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_WW_MUTEX_ZERO(name, lock) 	SEQCOUNT_LOCKNAME_ZERO(name, lock)

#define __seqprop_case(s, lockname, prop)				\
	seqcount_##lockname##_t: __seqprop_##lockname##_##prop((void *)(s))

#define __seqprop(s, prop) _Generic(*(s),				\
	seqcount_t:		__seqprop_##prop((void *)(s)),		\
	__seqprop_case((s),	raw_spinlock,	prop),			\
	__seqprop_case((s),	spinlock,	prop),			\
	__seqprop_case((s),	rwlock,		prop),			\
	__seqprop_case((s),	mutex,		prop),			\
	__seqprop_case((s),	ww_mutex,	prop))

#define seqprop_ptr(s)			__seqprop(s, ptr)
#define seqprop_sequence(s)		__seqprop(s, sequence)
#define seqprop_preemptible(s)		__seqprop(s, preemptible)
#define seqprop_assert(s)		__seqprop(s, assert)

/*
 * Sequential locks (seqlock_t)
 *
 * Sequence counters with an embedded spinlock for writer serialization
 * and non-preemptibility.
 *
 * For more info, see:
 *    - Comments on top of seqcount_t
 *    - Documentation/locking/seqlock.rst
 */
typedef struct {
	/*
	 * Make sure that readers don't starve writers on PREEMPT_RT: use
	 * seqcount_spinlock_t instead of seqcount_t. Check __SEQ_LOCK().
	 */
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

#define __SEQLOCK_UNLOCKED(lockname)					\
	{								\
		.seqcount = SEQCNT_SPINLOCK_ZERO(lockname, &(lockname).lock), \
		.lock =	__SPIN_LOCK_UNLOCKED(lockname)			\
	}

/**
 * seqlock_init() - dynamic initializer for seqlock_t
 * @sl: Pointer to the seqlock_t instance
 */
#define seqlock_init(sl)						\
	do {								\
		spin_lock_init(&(sl)->lock);				\
		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
	} while (0)

/**
 * DEFINE_SEQLOCK(sl) - Define a statically allocated seqlock_t
 * @sl: Name of the seqlock_t instance
 */
#define DEFINE_SEQLOCK(sl) \
		seqlock_t sl = __SEQLOCK_UNLOCKED(sl)

#include <linux/seqlock_api.h>

#endif /* __LINUX_SEQLOCK_H */
