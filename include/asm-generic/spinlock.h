/* SPDX-License-Identifier: GPL-2.0 */

/*
 * 'Generic' ticket-lock implementation.
 *
 * It relies on atomic_fetch_add() having well defined forward progress
 * guarantees under contention. If your architecture cannot provide this, stick
 * to a test-and-set lock.
 *
 * It also relies on atomic_fetch_add() being safe vs smp_store_release() on a
 * sub-word of the value. This is generally true for anything LL/SC although
 * you'd be hard pressed to find anything useful in architecture specifications
 * about this. If your architecture cannot do this you might be better off with
 * a test-and-set.
 *
 * It further assumes atomic_*_release() + atomic_*_acquire() is RCpc and hence
 * uses atomic_fetch_add() which is SC to create an RCsc lock.
 *
 * The implementation uses smp_cond_load_acquire() to spin, so if the
 * architecture has WFE like instructions to sleep instead of poll for word
 * modifications be sure to implement that (see ARM64 for example).
 *
 */

#ifndef __ASM_GENERIC_TICKET_LOCK_H
#define __ASM_GENERIC_TICKET_LOCK_H

#include <linux/atomic.h>
#include <asm-generic/spinlock_types.h>

static __always_inline void arch_spin_lock(arch_spinlock_t *lock)
{
	u32 val = atomic_fetch_add(1<<16, lock); /* SC, gives us RCsc */
	u16 ticket = val >> 16;

	if (ticket == (u16)val)
		return;

	atomic_cond_read_acquire(lock, ticket == (u16)VAL);
}

static __always_inline bool arch_spin_trylock(arch_spinlock_t *lock)
{
	u32 old = atomic_read(lock);

	if ((old >> 16) != (old & 0xffff))
		return false;

	return atomic_try_cmpxchg(lock, &old, old + (1<<16)); /* SC, for RCsc */
}

static __always_inline void arch_spin_unlock(arch_spinlock_t *lock)
{
	u16 *ptr = (u16 *)lock + IS_ENABLED(CONFIG_CPU_BIG_ENDIAN);
	u32 val = atomic_read(lock);

	smp_store_release(ptr, (u16)val + 1);
}

static __always_inline int arch_spin_is_locked(arch_spinlock_t *lock)
{
	u32 val = atomic_read(lock);

	return ((val >> 16) != (val & 0xffff));
}

static __always_inline int arch_spin_is_contended(arch_spinlock_t *lock)
{
	u32 val = atomic_read(lock);

	return (s16)((val >> 16) - (val & 0xffff)) > 1;
}

static __always_inline int arch_spin_value_unlocked(arch_spinlock_t lock)
{
	return !arch_spin_is_locked(&lock);
}

#include <asm/qrwlock.h>

#endif /* __ASM_GENERIC_TICKET_LOCK_H */
