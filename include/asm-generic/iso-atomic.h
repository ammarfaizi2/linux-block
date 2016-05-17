/* Use ISO C++11 intrinsics to implement 32-bit atomic ops.
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _ASM_GENERIC_ISO_ATOMIC_H
#define _ASM_GENERIC_ISO_ATOMIC_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/cmpxchg.h>
#include <asm/barrier.h>

#define ATOMIC_INIT(i)	{ (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
static __always_inline int __atomic_read(const atomic_t *v, int memorder)
{
	return __atomic_load_n(&v->counter, memorder);
}
#define atomic_read(v)		(__atomic_read((v), __ATOMIC_RELAXED))
#define atomic_read_acquire(v)	(__atomic_read((v), __ATOMIC_ACQUIRE))

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static __always_inline void __atomic_set(atomic_t *v, int i, int memorder)
{
	__atomic_store_n(&v->counter, i, memorder);
}
#define atomic_set(v, i)	 __atomic_set((v), (i), __ATOMIC_RELAXED)
#define atomic_set_release(v, i) __atomic_set((v), (i), __ATOMIC_RELEASE)

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static __always_inline void atomic_add(int i, atomic_t *v)
{
	__atomic_add_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

#define atomic_inc(v) atomic_add(1, (v))

/**
 * atomic_sub - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static __always_inline void atomic_sub(int i, atomic_t *v)
{
	__atomic_sub_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

#define atomic_dec(v) atomic_add(-1, (v))

/**
 * atomic_add_return - add integer and return
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns @i + @v.
 */
static __always_inline int __atomic_add_return(int i, atomic_t *v, int memorder)
{
	return __atomic_add_fetch(&v->counter, i, memorder);
}

#define atomic_add_return(i, v)		(__atomic_add_return((i), (v), __ATOMIC_SEQ_CST))
#define atomic_add_negative(i, v)	(atomic_add_return((i), (v)) < 0)
#define atomic_inc_return(v)		(atomic_add_return(1, (v)))
#define atomic_inc_and_test(v)		(atomic_add_return(1, (v)) == 0)

#define atomic_add_return_relaxed(i, v)	(__atomic_add_return((i), (v), __ATOMIC_RELAXED))
#define atomic_inc_return_relaxed(v)	(atomic_add_return_relaxed(1, (v)))

#define atomic_add_return_acquire(i, v)	(__atomic_add_return((i), (v), __ATOMIC_ACQUIRE))
#define atomic_inc_return_acquire(v)	(atomic_add_return_acquire(1, (v)))

#define atomic_add_return_release(i, v)	(__atomic_add_return((i), (v), __ATOMIC_RELEASE))
#define atomic_inc_return_release(v)	(atomic_add_return_release(1, (v)))

/**
 * atomic_sub_return - subtract integer and return
 * @v: pointer of type atomic_t
 * @i: integer value to subtract
 *
 * Atomically subtracts @i from @v and returns @v - @i
 */
static __always_inline int __atomic_sub_return(int i, atomic_t *v, int memorder)
{
	return __atomic_sub_fetch(&v->counter, i, memorder);
}

#define atomic_sub_return(i, v)		(__atomic_sub_return((i), (v), __ATOMIC_SEQ_CST))
#define atomic_sub_and_test(i, v)	(atomic_sub_return((i), (v)) == 0)
#define atomic_dec_return(v)		(atomic_sub_return(1, (v)))
#define atomic_dec_and_test(v)		(atomic_dec_return((v)) == 0)

#define atomic_sub_return_relaxed(i, v)	(__atomic_sub_return((i), (v), __ATOMIC_RELAXED))
#define atomic_dec_return_relaxed(v)	(atomic_sub_return_relaxed(1, (v)))

#define atomic_sub_return_acquire(i, v)	(__atomic_sub_return((i), (v), __ATOMIC_ACQUIRE))
#define atomic_dec_return_acquire(v)	(atomic_sub_return_acquire(1, (v)))

#define atomic_sub_return_release(i, v)	(__atomic_sub_return((i), (v), __ATOMIC_RELEASE))
#define atomic_dec_return_release(v)	(atomic_sub_return_release(1, (v)))

/**
 * atomic_try_cmpxchg - Compare value to memory and exchange if same
 * @v: Pointer of type atomic_t
 * @old: The value to be replaced
 * @new: The value to replace with
 *
 * Atomically read the original value of *@v compare it against @old.  If *@v
 * == @old, write the value of @new to *@v.  If the write takes place, true is
 * returned otherwise false is returned.  The original value is discarded - if
 * that is required, use atomic_cmpxchg_return() instead.
 */
static __always_inline
bool __atomic_try_cmpxchg(atomic_t *v, int old, int new, int memorder)
{
	int cur = old;
	return __atomic_compare_exchange_n(&v->counter, &cur, new, false,
					   memorder, __ATOMIC_RELAXED);
}

#define atomic_try_cmpxchg(v, o, n) \
	(__atomic_try_cmpxchg((v), (o), (n), __ATOMIC_SEQ_CST))
#define atomic_try_cmpxchg_relaxed(v, o, n) \
	(__atomic_try_cmpxchg((v), (o), (n), __ATOMIC_RELAXED))
#define atomic_try_cmpxchg_acquire(v, o, n) \
	(__atomic_try_cmpxchg((v), (o), (n), __ATOMIC_ACQUIRE))
#define atomic_try_cmpxchg_release(v, o, n) \
	(__atomic_try_cmpxchg((v), (o), (n), __ATOMIC_RELEASE))

/**
 * atomic_cmpxchg_return - Compare value to memory and exchange if same
 * @v: Pointer of type atomic_t
 * @old: The value to be replaced
 * @new: The value to replace with
 * @_orig: Where to place the original value of *@v
 *
 * Atomically read the original value of *@v and compare it against @old.  If
 * *@v == @old, write the value of @new to *@v.  If the write takes place, true
 * is returned otherwise false is returned.  The original value of *@v is saved
 * to *@_orig.
 */
static __always_inline
bool __atomic_cmpxchg_return(atomic_t *v, int old, int new, int *_orig, int memorder)
{
	*_orig = old;
	return __atomic_compare_exchange_n(&v->counter, _orig, new, false,
					   memorder, __ATOMIC_RELAXED);
}

#define atomic_cmpxchg_return(v, o, n, _o) \
	(__atomic_cmpxchg_return((v), (o), (n), (_o), __ATOMIC_SEQ_CST))
#define atomic_cmpxchg_return_relaxed(v, o, n, _o) \
	(__atomic_cmpxchg_return((v), (o), (n), (_o), __ATOMIC_RELAXED))
#define atomic_cmpxchg_return_acquire(v, o, n, _o) \
	(__atomic_cmpxchg_return((v), (o), (n), (_o), __ATOMIC_ACQUIRE))
#define atomic_cmpxchg_return_release(v, o, n, _o) \
	(__atomic_cmpxchg_return((v), (o), (n), (_o), __ATOMIC_RELEASE))

/**
 * atomic_cmpxchg - Compare value to memory and exchange if same
 * @v: Pointer of type atomic_t
 * @old: The value to be replaced
 * @new: The value to replace with
 *
 * Atomically read the original value of *@v and compare it against @old.  If
 * *@v == @old, write the value of @new to *@v.  The original value is
 * returned.
 *
 * atomic_try_cmpxchg() and atomic_cmpxchg_return_release() are preferred to
 * this function as they can make better use of the knowledge as to whether a
 * write took place or not that is provided by some CPUs (e.g. x86's CMPXCHG
 * instruction stores this in the Z flag).
 */
static __always_inline int __atomic_cmpxchg(atomic_t *v, int old, int new,
					    int memorder)
{
	int cur = old;
	if (__atomic_compare_exchange_n(&v->counter, &cur, new, false,
					memorder, __ATOMIC_RELAXED))
		return old;
	return cur;
}

#define atomic_cmpxchg(v, o, n)		(__atomic_cmpxchg((v), (o), (n), __ATOMIC_SEQ_CST))
#define atomic_cmpxchg_relaxed(v, o, n)	(__atomic_cmpxchg((v), (o), (n), __ATOMIC_RELAXED))
#define atomic_cmpxchg_acquire(v, o, n)	(__atomic_cmpxchg((v), (o), (n), __ATOMIC_ACQUIRE))
#define atomic_cmpxchg_release(v, o, n)	(__atomic_cmpxchg((v), (o), (n), __ATOMIC_RELEASE))

static __always_inline int __atomic_xchg(atomic_t *v, int new, int memorder)
{
	return __atomic_exchange_n(&v->counter, new, memorder);
}

#define atomic_xchg(v, new)		(__atomic_xchg((v), (new), __ATOMIC_SEQ_CST))
#define atomic_xchg_relaxed(v, new)	(__atomic_xchg((v), (new), __ATOMIC_RELAXED))
#define atomic_xchg_acquire(v, new)	(__atomic_xchg((v), (new), __ATOMIC_ACQUIRE))
#define atomic_xchg_release(v, new)	(__atomic_xchg((v), (new), __ATOMIC_RELEASE))

static __always_inline void atomic_and(int i, atomic_t *v)
{
	__atomic_and_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_andnot(int i, atomic_t *v)
{
	__atomic_and_fetch(&v->counter, ~i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_or(int i, atomic_t *v)
{
	__atomic_or_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_xor(int i, atomic_t *v)
{
	__atomic_xor_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

/**
 * __atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns the old value of @v.
 */
static __always_inline int __atomic_add_unless(atomic_t *v,
					       int addend, int unless)
{
	int c = atomic_read(v);

	while (likely(c != unless)) {
		if (__atomic_compare_exchange_n(&v->counter,
						&c, c + addend,
						false,
						__ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED))
			break;
	}
	return c;
}

/**
 * atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns true if @v was not @u, and false otherwise.
 */
static __always_inline bool atomic_add_unless(atomic_t *v,
					      int addend, int unless)
{
	int c = atomic_read(v);

	while (likely(c != unless)) {
		if (__atomic_compare_exchange_n(&v->counter,
						&c, c + addend,
						false,
						__ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED))
			return true;
	}
	return false;
}

#define atomic_inc_not_zero(v)		atomic_add_unless((v), 1, 0)

/**
 * atomic_add_unless_hint - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 * @hint: probable value of the atomic before the increment
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns the old value of @v.
 */
static __always_inline int __atomic_add_unless_hint(atomic_t *v,
						    int addend, int unless,
						    int hint)
{
	int c = hint;

	while (likely(c != unless)) {
		if (__atomic_compare_exchange_n(&v->counter,
						&c, c + addend,
						false,
						__ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED))
			break;
	}
	return c;
}

#define atomic_inc_not_zero_hint(v, h)	(__atomic_add_unless_hint((v), 1, 0, (h)) != 0)

static inline bool atomic_inc_unless_negative(atomic_t *v)
{
	int c = 0;

	while (likely(c >= 0)) {
		if (__atomic_compare_exchange_n(&v->counter,
						&c, c + 1,
						false,
						__ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED))
			return true;
	}
	return false;
}

static inline bool atomic_dec_unless_positive(atomic_t *v)
{
	int c = 0;

	while (likely(c <= 0)) {
		if (__atomic_compare_exchange_n(&v->counter,
						&c, c - 1,
						false,
						__ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED))
			return true;
	}
	return false;
}

/*
 * atomic_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic_t
 *
 * The function returns the old value of *v minus 1, even if
 * the atomic variable, v, was not decremented.
 */
static inline bool atomic_dec_if_positive(atomic_t *v)
{
	int c = atomic_read(v);

	while (likely(c > 0)) {
		if (__atomic_compare_exchange_n(&v->counter,
						&c, c - 1,
						false,
						__ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED))
			return true;
	}
	return false;
}

/**
 * atomic_fetch_or - perform *v |= mask and return old value of *v
 * @v: pointer to atomic_t
 * @mask: mask to OR on the atomic_t
 */
static inline int atomic_fetch_or(atomic_t *v, int mask)
{
	return __atomic_fetch_or(&v->counter, mask, __ATOMIC_SEQ_CST);
}

/**
 * atomic_inc_short - increment of a short integer
 * @v: pointer to type int
 *
 * Atomically adds 1 to @v
 * Returns the new value of @v
 */
static __always_inline short int atomic_inc_short(short int *v)
{
	return __atomic_add_fetch(v, 1, __ATOMIC_SEQ_CST);
}

#endif /* _ASM_GENERIC_ISO_ATOMIC_H */
