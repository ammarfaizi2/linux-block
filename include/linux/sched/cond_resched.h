/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_COND_RESCHED_H
#define _LINUX_SCHED_COND_RESCHED_H

/*
 * This header contains the various conditional rescheduling APIs.
 */

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/rcupdate.h>

/*
 * cond_resched() and cond_resched_lock(): latency reduction via
 * explicit rescheduling in places that are safe. The return
 * value indicates whether a reschedule was done in fact.
 * cond_resched_lock() will drop the spinlock before scheduling,
 */
#if !defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)
extern int __cond_resched(void);

#if defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)

DECLARE_STATIC_CALL(cond_resched, __cond_resched);

static __always_inline int _cond_resched(void)
{
	return static_call_mod(cond_resched)();
}

#elif defined(CONFIG_PREEMPT_DYNAMIC) && defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)
extern int dynamic_cond_resched(void);

static __always_inline int _cond_resched(void)
{
	return dynamic_cond_resched();
}

#else

static inline int _cond_resched(void)
{
	return __cond_resched();
}

#endif /* CONFIG_PREEMPT_DYNAMIC */

#else

static inline int _cond_resched(void) { return 0; }

#endif /* !defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC) */

#define cond_resched() ({			\
	__might_resched(__FILE__, __LINE__, 0);	\
	_cond_resched();			\
})

extern int __cond_resched_lock(spinlock_t *lock);
extern int __cond_resched_rwlock_read(rwlock_t *lock);
extern int __cond_resched_rwlock_write(rwlock_t *lock);

#define MIGHT_RESCHED_RCU_SHIFT		8
#define MIGHT_RESCHED_PREEMPT_MASK	((1U << MIGHT_RESCHED_RCU_SHIFT) - 1)

#ifndef CONFIG_PREEMPT_RT
/*
 * Non RT kernels have an elevated preempt count due to the held lock,
 * but are not allowed to be inside a RCU read side critical section
 */
# define PREEMPT_LOCK_RESCHED_OFFSETS	PREEMPT_LOCK_OFFSET
#else
/*
 * spin/rw_lock() on RT implies rcu_read_lock(). The might_sleep() check in
 * cond_resched*lock() has to take that into account because it checks for
 * preempt_count() and rcu_preempt_depth().
 */
# define PREEMPT_LOCK_RESCHED_OFFSETS	\
	(PREEMPT_LOCK_OFFSET + (1U << MIGHT_RESCHED_RCU_SHIFT))
#endif

#define cond_resched_lock(lock) ({						\
	__might_resched(__FILE__, __LINE__, PREEMPT_LOCK_RESCHED_OFFSETS);	\
	__cond_resched_lock(lock);						\
})

#define cond_resched_rwlock_read(lock) ({					\
	__might_resched(__FILE__, __LINE__, PREEMPT_LOCK_RESCHED_OFFSETS);	\
	__cond_resched_rwlock_read(lock);					\
})

#define cond_resched_rwlock_write(lock) ({					\
	__might_resched(__FILE__, __LINE__, PREEMPT_LOCK_RESCHED_OFFSETS);	\
	__cond_resched_rwlock_write(lock);					\
})

extern void __cond_resched_rcu(void);

static inline void cond_resched_rcu(void)
{
#if defined(CONFIG_DEBUG_ATOMIC_SLEEP) || !defined(CONFIG_PREEMPT_RCU)
	__cond_resched_rcu();
#endif
}

/*
 * Does a critical section need to be broken due to another
 * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
 * but a general need for low latency)
 */
static inline int spin_needbreak(spinlock_t *lock)
{
#ifdef CONFIG_PREEMPTION
	return spin_is_contended(lock);
#else
	return 0;
#endif
}

/*
 * Check if a rwlock is contended.
 * Returns non-zero if there is another task waiting on the rwlock.
 * Returns zero if the lock is not contended or the system / underlying
 * rwlock implementation does not support contention detection.
 * Technically does not depend on CONFIG_PREEMPTION, but a general need
 * for low latency.
 */
static inline int rwlock_needbreak(rwlock_t *lock)
{
#ifdef CONFIG_PREEMPTION
	return rwlock_is_contended(lock);
#else
	return 0;
#endif
}

/*
 * In order to reduce various lock holder preemption latencies provide an
 * interface to see if a vCPU is currently running or not.
 *
 * This allows us to terminate optimistic spin loops and block, analogous to
 * the native optimistic spin heuristic of testing if the lock owner task is
 * running or not.
 */
#ifndef vcpu_is_preempted
static inline bool vcpu_is_preempted(int cpu)
{
	return false;
}
#endif

#endif /* _LINUX_SCHED_COND_RESCHED_H */
