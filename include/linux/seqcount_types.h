/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SEQCOUNT_TYPES_H
#define __LINUX_SEQCOUNT_TYPES_H

#include <linux/lockdep_types.h>

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

#else
# define SEQCOUNT_DEP_MAP_INIT(lockname)
#endif

/**
 * SEQCNT_ZERO() - static initializer for seqcount_t
 * @name: Name of the seqcount_t instance
 */
#define SEQCNT_ZERO(name) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(name) }

/*
 * Latch sequence counters (seqcount_latch_t)
 *
 * A sequence counter variant where the counter even/odd value is used to
 * switch between two copies of protected data. This allows the read path,
 * typically NMIs, to safely interrupt the write side critical section.
 *
 * As the write sections are fully preemptible, no special handling for
 * PREEMPT_RT is needed.
 */
typedef struct {
	seqcount_t seqcount;
} seqcount_latch_t;

/**
 * SEQCNT_LATCH_ZERO() - static initializer for seqcount_latch_t
 * @seq_name: Name of the seqcount_latch_t instance
 */
#define SEQCNT_LATCH_ZERO(seq_name) {					\
	.seqcount		= SEQCNT_ZERO(seq_name.seqcount),	\
}

#endif /* __LINUX_SEQCOUNT_TYPES_H */
