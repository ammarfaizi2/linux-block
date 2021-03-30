/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Ticket-based spinlock
 *
 * Copyright (C) 2021 Google, Inc
 *
 * Author: Palmer Dabbelt <palmerdabbelt@google.com>
 */
#ifndef __ASM_GENERIC_TSPINLOCK_H
#define __ASM_GENERIC_TSPINLOCK_H

#include <linux/atomic.h>
#include <asm/processor.h>
#include <asm-generic/tspinlock_types.h>

/*
 * These three are correct when checking the status of a lock held by the
 * current thread, but approximate when checking the status of a lock that is
 * either not held or held by another thread.
 */
static __always_inline int tspinlock_is_locked(struct tspinlock *l)
{
	u32 curr, next;

	curr = atomic_read(&l->curr);
	next = atomic_read(&l->next);

	return curr != next;
}

static __always_inline int tspinlock_is_contended(struct tspinlock *l)
{
	u32 curr, next;

	curr = atomic_read(&l->curr);
	next = atomic_read(&l->next);

	return curr + 1 != next;
}

static __always_inline int tspinlock_value_unlocked(struct tspinlock l)
{
	/*
	 * Ordering doesn't matter here, as we already have an inconsistent
	 * snapshot of the lock and there's nothing we can do about that.
	 */
	return atomic_read(&l.curr) != atomic_read(&l.next);
}

/*
 * These two are accurate and fair: lock always hands out tickets in the
 * correct order, while unlock is trivially consistent because the lock is held
 * at the time it is called.
 */
static __always_inline void tspinlock_lock(struct tspinlock *l)
{
	u32 ticket;

	ticket = atomic_inc_return(&l->next);
	while (atomic_read(&l->curr) != ticket)
		cpu_relax();
}

static __always_inline void tspinlock_unlock(struct tspinlock *l)
{
	u32 curr;

	curr = atomic_read(&l->curr);
	curr++;
	atomic_set(&l->curr, curr);
}

/*
 * This one is approximate and unfair.  It's correct (modulo overflow) when
 * taking the lock, but may spuriously indicate the lock is taken when it isn't
 * actually available.  It's never fair, with trylock always being a lower
 * precedence than lock.
 */
static __always_inline int tspinlock_trylock(struct tspinlock *l)
{
	u32 curr, next;

	curr = atomic_read(&l->curr);
	next = atomic_read(&l->next);

	/*
	 * Check to see if our snapshot of the lock indicates it was available.
	 * This snapshot itself is not consistent, so we may spuriously
	 * indicate the lock was token when it was in fact available -- if, for
	 * example an unlock occurred between the two reads above.
	 */
	if (curr != next)
		return 1;

	/*
	 * At this point we know that there was a point in time at which the
	 * lock was not taken, but we don't know whether the lock is currently
	 * taken.  In order to take the lock we must atomically check (curr ==
	 * next) and set (next = next + 1), which we can't do directly as
	 * they're two different memory locations.
	 *
	 * Instead we rely on an invariant of the lock: in order for curr to
	 * change, next must change first.  Since curr was read before next
	 * above and they were equal, we know that (modulo overflow) next and
	 * curr are still equal.
	 */
	if (atomic_cmpxchg(&l->next, next, next + 1))
		return 1;

	return 0;
}

/* Actually use the ticket lock. */
#define arch_spin_is_locked(l)		tspinlock_is_locked(l)
#define arch_spin_is_contended(l)	tspinlock_is_contended(l)
#define arch_spin_value_unlocked(l)	tspinlock_value_unlocked(l)
#define arch_spin_lock(l)		tspinlock_lock(l)
#define arch_spin_trylock(l)		tspinlock_trylock(l)
#define arch_spin_unlock(l)		tspinlock_unlock(l)

#define __ARCH_SPIN_LOCK_UNLOCKED	{ { 0 } }

#endif /* __ASM_GENERIC_TSPINLOCK_H */
