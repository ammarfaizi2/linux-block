/* Use ISO C++11 intrinsics to implement atomic ops.
 *
 * This file is a template.  The #includer needs to #define the following
 * items:
 *
 *	atomic_val		- counter type (eg. int, long, long long)
 *	atomic_prefix(x)	- prefix (eg. atomic, atomic64, atomic_long)
 *	__atomic_prefix(x)	- prefix with "__" prepended
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

/**
 * atomic_read - read atomic variable
 * @v: pointer to atomic variable
 *
 * Atomically reads the value of @v.
 */
static __always_inline atomic_val atomic_prefix(_read)(const atomic_prefix(_t) *v)
{
	return __atomic_load_n(&v->counter, __ATOMIC_RELAXED);
}

static __always_inline atomic_val atomic_prefix(_read_acquire)(const atomic_prefix(_t) *v)
{
	return __atomic_load_n(&v->counter, __ATOMIC_ACQUIRE);
}

/**
 * atomic_set - set atomic variable
 * @v: pointer to atomic variable
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static __always_inline void atomic_prefix(_set)(atomic_prefix(_t) *v, atomic_val i)
{
	__atomic_store_n(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_prefix(_set_release)(atomic_prefix(_t) *v, atomic_val i)
{
	__atomic_store_n(&v->counter, i, __ATOMIC_RELEASE);
}

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer to atomic variable
 *
 * Atomically adds @i to @v.
 */
static __always_inline void atomic_prefix(_add)(atomic_val i, atomic_prefix(_t) *v)
{
	__atomic_add_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_prefix(_inc)(atomic_prefix(_t) *v)
{
	__atomic_add_fetch(&v->counter, 1, __ATOMIC_RELAXED);
}

/**
 * atomic_sub - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer to atomic variable
 *
 * Atomically subtracts @i from @v.
 */
static __always_inline void atomic_prefix(_sub)(atomic_val i, atomic_prefix(_t) *v)
{
	__atomic_sub_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_prefix(_dec)(atomic_prefix(_t) *v)
{
	__atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELAXED);
}

/**
 * atomic_add_return - add integer and return
 * @i: integer value to add
 * @v: pointer to atomic variable
 *
 * Atomically adds @i to @v and returns @i + @v.
 */
static __always_inline
atomic_val atomic_prefix(_add_return)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static __always_inline
atomic_val atomic_prefix(_inc_return)(atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static __always_inline
atomic_val atomic_prefix(_add_return_relaxed)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline
atomic_val atomic_prefix(_inc_return_relaxed)(atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, 1, __ATOMIC_RELAXED);
}

static __always_inline
atomic_val atomic_prefix(_add_return_acquire)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, i, __ATOMIC_ACQUIRE);
}

static __always_inline
atomic_val atomic_prefix(_inc_return_acquire)(atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, 1, __ATOMIC_ACQUIRE);
}

static __always_inline
atomic_val atomic_prefix(_add_return_release)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, i, __ATOMIC_RELEASE);
}

static __always_inline
atomic_val atomic_prefix(_inc_return_release)(atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, 1, __ATOMIC_RELEASE);
}

static __always_inline
bool atomic_prefix(_add_negative)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST) < 0;
}

static __always_inline
bool atomic_prefix(_inc_and_test)(atomic_prefix(_t) *v)
{
	return __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST) == 0;
}

/**
 * atomic_sub_return - subtract integer and return
 * @i: integer value to subtract
 * @v: pointer to atomic variable
 *
 * Atomically subtracts @i from @v and returns @v - @i
 */
static __always_inline
atomic_val atomic_prefix(_sub_return)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static __always_inline
atomic_val atomic_prefix(_dec_return)(atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static __always_inline
atomic_val atomic_prefix(_sub_return_relaxed)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline
atomic_val atomic_prefix(_dec_return_relaxed)(atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELAXED);
}

static __always_inline
atomic_val atomic_prefix(_sub_return_acquire)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, i, __ATOMIC_ACQUIRE);
}

static __always_inline
atomic_val atomic_prefix(_dec_return_acquire)(atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_ACQUIRE);
}

static __always_inline
atomic_val atomic_prefix(_sub_return_release)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, i, __ATOMIC_RELEASE);
}

static __always_inline
atomic_val atomic_prefix(_dec_return_release)(atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELEASE);
}

static __always_inline
bool atomic_prefix(_sub_and_test)(atomic_val i, atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST) == 0;
}

static __always_inline
bool atomic_prefix(_dec_and_test)(atomic_prefix(_t) *v)
{
	return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST) == 0;
}

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
bool atomic_prefix(_try_cmpxchg)(atomic_prefix(_t) *v, atomic_val old, atomic_val new)
{
	int cur = old;
	return __atomic_compare_exchange_n(&v->counter, &cur, new, false,
					   __ATOMIC_SEQ_CST,
					   __ATOMIC_RELAXED);
}

static __always_inline
bool atomic_prefix(_try_cmpxchg_relaxed)(atomic_prefix(_t) *v, atomic_val old, atomic_val new)
{
	int cur = old;
	return __atomic_compare_exchange_n(&v->counter, &cur, new, false,
					   __ATOMIC_RELAXED,
					   __ATOMIC_RELAXED);
}

static __always_inline
bool atomic_prefix(_try_cmpxchg_acquire)(atomic_prefix(_t) *v, atomic_val old, atomic_val new)
{
	int cur = old;
	return __atomic_compare_exchange_n(&v->counter, &cur, new, false,
					   __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
}

static __always_inline
bool atomic_prefix(_try_cmpxchg_release)(atomic_prefix(_t) *v, atomic_val old, atomic_val new)
{
	int cur = old;
	return __atomic_compare_exchange_n(&v->counter, &cur, new, false,
					   __ATOMIC_RELEASE,
					   __ATOMIC_RELAXED);
}

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
bool atomic_prefix(_cmpxchg_return)(atomic_prefix(_t) *v,
				    atomic_val old, atomic_val new, atomic_val *_orig)
{
	*_orig = old;
	return __atomic_compare_exchange_n(&v->counter, _orig, new, false,
					   __ATOMIC_SEQ_CST,
					   __ATOMIC_RELAXED);
}

static __always_inline
bool atomic_prefix(_cmpxchg_return_relaxed)(atomic_prefix(_t) *v,
					    atomic_val old, atomic_val new, atomic_val *_orig)
{
	*_orig = old;
	return __atomic_compare_exchange_n(&v->counter, _orig, new, false,
					   __ATOMIC_RELAXED,
					   __ATOMIC_RELAXED);
}

static __always_inline
bool atomic_prefix(_cmpxchg_return_acquire)(atomic_prefix(_t) *v,
					    atomic_val old, atomic_val new, atomic_val *_orig)
{
	*_orig = old;
	return __atomic_compare_exchange_n(&v->counter, _orig, new, false,
					   __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
}

static __always_inline
bool atomic_prefix(_cmpxchg_return_release)(atomic_prefix(_t) *v,
					    atomic_val old, atomic_val new, atomic_val *_orig)
{
	*_orig = old;
	return __atomic_compare_exchange_n(&v->counter, _orig, new, false,
					   __ATOMIC_RELEASE,
					   __ATOMIC_RELAXED);
}

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
static __always_inline
atomic_val atomic_prefix(_cmpxchg)(atomic_prefix(_t) *v, atomic_val old, atomic_val new)
{
	atomic_val cur = old;
	if (__atomic_compare_exchange_n(&v->counter, &cur, new, false,
					__ATOMIC_SEQ_CST,
					__ATOMIC_RELAXED))
		return old;
	return cur;
}

static __always_inline
atomic_val atomic_prefix(_cmpxchg_relaxed)(atomic_prefix(_t) *v, atomic_val old, atomic_val new)
{
	atomic_val cur = old;
	if (__atomic_compare_exchange_n(&v->counter, &cur, new, false,
					__ATOMIC_RELAXED,
					__ATOMIC_RELAXED))
		return old;
	return cur;
}

static __always_inline
atomic_val atomic_prefix(_cmpxchg_acquire)(atomic_prefix(_t) *v, atomic_val old, atomic_val new)
{
	atomic_val cur = old;
	if (__atomic_compare_exchange_n(&v->counter, &cur, new, false,
					__ATOMIC_ACQUIRE,
					__ATOMIC_RELAXED))
		return old;
	return cur;
}

static __always_inline
atomic_val atomic_prefix(_cmpxchg_release)(atomic_prefix(_t) *v, atomic_val old, atomic_val new)
{
	atomic_val cur = old;
	if (__atomic_compare_exchange_n(&v->counter, &cur, new, false,
					__ATOMIC_RELEASE,
					__ATOMIC_RELAXED))
		return old;
	return cur;
}

static __always_inline
atomic_val atomic_prefix(_xchg)(atomic_prefix(_t) *v, atomic_val new)
{
	return __atomic_exchange_n(&v->counter, new, __ATOMIC_SEQ_CST);
}

static __always_inline
atomic_val atomic_prefix(_xchg_relaxed)(atomic_prefix(_t) *v, atomic_val new)
{
	return __atomic_exchange_n(&v->counter, new, __ATOMIC_RELAXED);
}

static __always_inline
atomic_val atomic_prefix(_xchg_acquire)(atomic_prefix(_t) *v, atomic_val new)
{
	return __atomic_exchange_n(&v->counter, new, __ATOMIC_ACQUIRE);
}

static __always_inline
atomic_val atomic_prefix(_xchg_release)(atomic_prefix(_t) *v, atomic_val new)
{
	return __atomic_exchange_n(&v->counter, new, __ATOMIC_RELEASE);
}

/*
 * Bitwise atomic ops.
 */
static __always_inline void atomic_prefix(_and)(atomic_val i, atomic_prefix(_t) *v)
{
	__atomic_and_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_prefix(_andnot)(atomic_val i, atomic_prefix(_t) *v)
{
	__atomic_and_fetch(&v->counter, ~i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_prefix(_or)(atomic_val i, atomic_prefix(_t) *v)
{
	__atomic_or_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

static __always_inline void atomic_prefix(_xor)(atomic_val i, atomic_prefix(_t) *v)
{
	__atomic_xor_fetch(&v->counter, i, __ATOMIC_RELAXED);
}

/**
 * __atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_prefix(_t)
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns the old value of @v.
 */
static __always_inline
atomic_val __atomic_prefix(_add_unless)(atomic_prefix(_t) *v, atomic_val addend, atomic_val unless)
{
	atomic_val c = atomic_prefix(_read)(v);

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
 * @v: pointer of type atomic_prefix(_t)
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns true if @v was not @u, and false otherwise.
 */
static __always_inline
bool atomic_prefix(_add_unless)(atomic_prefix(_t) *v,
				atomic_val addend, atomic_val unless)
{
	atomic_val c = __atomic_load_n(&v->counter, __ATOMIC_RELAXED);

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

static __always_inline
bool atomic_prefix(_inc_not_zero)(atomic_prefix(_t) *v)
{
	atomic_val c = __atomic_load_n(&v->counter, __ATOMIC_RELAXED);

	while (likely(c != 0)) {
		if (__atomic_compare_exchange_n(&v->counter,
						&c, c + 1,
						false,
						__ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED))
			return true;
	}
	return false;
}

static __always_inline
bool atomic_prefix(_inc_not_zero_hint)(atomic_prefix(_t) *v, atomic_val hint)
{
	atomic_val c = hint;

	while (likely(c != 0)) {
		if (__atomic_compare_exchange_n(&v->counter,
						&c, c + 1,
						false,
						__ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED))
			return true;
	}
	return false;
}

static __always_inline
bool atomic_prefix(_inc_unless_negative)(atomic_prefix(_t) *v)
{
	atomic_val c = 0;

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

static __always_inline
bool atomic_prefix(_dec_unless_positive)(atomic_prefix(_t) *v)
{
	atomic_val c = 0;

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
 * @v: pointer of type atomic_prefix(_t)
 *
 * The function returns the old value of *v minus 1, even if
 * the atomic variable, v, was not decremented.
 */
static __always_inline
bool atomic_prefix(_dec_if_positive)(atomic_prefix(_t) *v)
{
	atomic_val c = __atomic_load_n(&v->counter, __ATOMIC_RELAXED);

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
 * @v: pointer to atomic_prefix(_t)
 * @mask: mask to OR on the atomic_prefix(_t)
 */
static __always_inline
atomic_val atomic_prefix(_fetch_or)(atomic_prefix(_t) *v, atomic_val mask)
{
	return __atomic_fetch_or(&v->counter, mask, __ATOMIC_SEQ_CST);
}
