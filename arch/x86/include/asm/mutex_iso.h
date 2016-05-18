/* ISO atomics based mutex
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#ifndef _ASM_X86_MUTEX_ISO_H
#define _ASM_X86_MUTEX_ISO_H

/**
 * __mutex_fastpath_lock - decrement and call function if negative
 * @v: pointer of type atomic_t
 * @fail_fn: function to call if the result is negative
 *
 * Atomically decrements @v and calls <fail_fn> if the result is negative.
 */
static inline void __mutex_fastpath_lock(atomic_t *v,
					 void (*fail_fn)(atomic_t *))
{
	if (atomic_dec_return_acquire(v) < 0)
		fail_fn(v);
}

/**
 *  __mutex_fastpath_lock_retval - try to take the lock by moving the count
 *                                 from 1 to a 0 value
 * @v: pointer of type atomic_t
 *
 * Change the count from 1 to a value lower than 1. This function returns 0
 * if the fastpath succeeds, or -1 otherwise.
 */
static inline int __mutex_fastpath_lock_retval(atomic_t *v)
{
	return unlikely(atomic_dec_return(v) < 0) ? -1 : 0;
}

/**
 * __mutex_fastpath_unlock - increment and call function if nonpositive
 * @v: pointer of type atomic_t
 * @fail_fn: function to call if the result is nonpositive
 *
 * Atomically increments @v and calls <fail_fn> if the result is nonpositive.
 */
static inline void __mutex_fastpath_unlock(atomic_t *v,
					   void (*fail_fn)(atomic_t *))
{
	if (atomic_inc_return_release(v) <= 0)
		fail_fn(v);
}

#define __mutex_slowpath_needs_to_unlock()	1

/**
 * __mutex_fastpath_trylock - try to acquire the mutex, without waiting
 *
 *  @v: pointer of type atomic_t
 *  @fail_fn: fallback function
 *
 * Change the count from 1 to 0 and return true (success), or return false
 * (failure) if it wasn't 1 originally. [the fallback function is never used on
 * x86_64, because all x86_64 CPUs have a CMPXCHG instruction.]
 */
static inline bool __mutex_fastpath_trylock(atomic_t *v,
					    int (*fail_fn)(atomic_t *))
{
	return likely(atomic_try_cmpxchg(v, 1, 0));
}

#endif /* _ASM_X86_MUTEX_ISO_H */
