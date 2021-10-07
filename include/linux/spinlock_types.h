#ifndef __LINUX_SPINLOCK_TYPES_H
#define __LINUX_SPINLOCK_TYPES_H

/*
 * include/linux/spinlock_types.h - generic spinlock type definitions
 *                                  and initializers
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

#include <linux/spinlock_types_raw.h>

#ifndef CONFIG_PREEMPT_RT

/* Non PREEMPT_RT kernels map spinlock to raw_spinlock */
typedef struct spinlock {
	union {
		struct raw_spinlock rlock;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
		struct {
			u8 __padding[LOCK_PADSIZE];
			struct lockdep_map dep_map;
		};
#endif
	};
} spinlock_t;

#define ___SPIN_LOCK_INITIALIZER(lockname)	\
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	SPIN_DEP_MAP_INIT(lockname) }

#define __SPIN_LOCK_INITIALIZER(lockname) \
	{ { .rlock = ___SPIN_LOCK_INITIALIZER(lockname) } }

#define __SPIN_LOCK_UNLOCKED(lockname) \
	(spinlock_t) __SPIN_LOCK_INITIALIZER(lockname)

#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)

#else /* !CONFIG_PREEMPT_RT */

/* PREEMPT_RT kernels map spinlock to rt_mutex */
#include <linux/rtmutex.h>

typedef struct spinlock {
	struct rt_mutex_base	lock;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
} spinlock_t;

#define __SPIN_LOCK_UNLOCKED(name)				\
	{							\
		.lock = __RT_MUTEX_BASE_INITIALIZER(name.lock),	\
		SPIN_DEP_MAP_INIT(name)				\
	}

#define __LOCAL_SPIN_LOCK_UNLOCKED(name)			\
	{							\
		.lock = __RT_MUTEX_BASE_INITIALIZER(name.lock),	\
		LOCAL_SPIN_DEP_MAP_INIT(name)			\
	}

#define DEFINE_SPINLOCK(name)					\
	spinlock_t name = __SPIN_LOCK_UNLOCKED(name)

#endif /* CONFIG_PREEMPT_RT */


#ifdef CONFIG_DEBUG_SPINLOCK
  extern void __raw_spin_lock_init(raw_spinlock_t *lock, const char *name,
				   struct lock_class_key *key, short inner);

# define raw_spin_lock_init(lock)					\
do {									\
	static struct lock_class_key __key;				\
									\
	__raw_spin_lock_init((lock), #lock, &__key, LD_WAIT_SPIN);	\
} while (0)

#else
# define raw_spin_lock_init(lock)				\
	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); } while (0)
#endif

static __always_inline raw_spinlock_t *spinlock_check(spinlock_t *lock)
{
	return &lock->rlock;
}

#ifdef CONFIG_DEBUG_SPINLOCK

# define spin_lock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__raw_spin_lock_init(spinlock_check(lock),		\
			     #lock, &__key, LD_WAIT_CONFIG);	\
} while (0)

#else

# define spin_lock_init(_lock)			\
do {						\
	spinlock_check(_lock);			\
	*(_lock) = __SPIN_LOCK_UNLOCKED(_lock);	\
} while (0)

#endif

#include <linux/rwlock_types.h>

#endif /* __LINUX_SPINLOCK_TYPES_H */
