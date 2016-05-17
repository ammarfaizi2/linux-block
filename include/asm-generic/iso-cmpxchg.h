/* Use ISO C++11 intrinsics to implement cmpxchg() and xchg().
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _ASM_GENERIC_ISO_CMPXCHG_H
#define _ASM_GENERIC_ISO_CMPXCHG_H

/**
 * cmpxchg_return - Check variable and replace if expected value.
 * @ptr: Pointer to target variable
 * @old: The value to check for
 * @new: The value to replace with
 * @_orig: A pointer to a variable in which to place the current value
 *
 * Atomically checks the contents of *@ptr, and if the same as @old, replaces
 * it with @new.  Return true if the exchange happened, false if it didn't.
 * The original value read from *@ptr is stored in *@_orig.
 *
 * gcc can generate better code if it gets to use the result of the intrinsic
 * to decide what to do, so this and try_cmpxchg() are preferred to cmpxchg().
 */
#define iso_cmpxchg_return(ptr, old, new, _orig, mem)			\
	({								\
		__typeof__((_orig)) __orig = (_orig);			\
		*__orig = (old);					\
		__atomic_compare_exchange_n((ptr),			\
					    __orig, (new),		\
					    false,			\
					    mem,			\
					    __ATOMIC_RELAXED);		\
	})

#define cmpxchg_return(ptr, old, new, _orig) \
	iso_cmpxchg_return((ptr), (old), (new), (_orig), __ATOMIC_SEQ_CST)

#define cmpxchg_return_relaxed(ptr, old, new, _orig) \
	iso_cmpxchg_return((ptr), (old), (new), (_orig), __ATOMIC_RELAXED)

#define cmpxchg_return_acquire(ptr, old, new, _orig) \
	iso_cmpxchg_return((ptr), (old), (new), (_orig), __ATOMIC_ACQUIRE)

#define cmpxchg_return_release(ptr, old, new, _orig) \
	iso_cmpxchg_return((ptr), (old), (new), (_orig), __ATOMIC_RELEASE)

/**
 * try_cmpxchg - Check variable and replace if expected value.
 * @ptr: Pointer to variable
 * @old: The value to check for
 * @new: The value to replace with
 *
 * Atomically checks the contents of *@ptr and, if the same as @old, replaces
 * it with @new.  Return true if the exchange happened, false if it didn't.
 * The value read from *@ptr is discarded.
 */
#define iso_try_cmpxchg(ptr, old, new, mem)				\
	({								\
		__typeof__((ptr)) __ptr = (ptr);			\
		__typeof__(*__ptr) __orig;				\
		__atomic_compare_exchange_n(__ptr,			\
					    &__orig, (new),		\
					    false,			\
					    mem,			\
					    __ATOMIC_RELAXED);		\
	})

#define try_cmpxchg(ptr, old, new) \
	iso_try_cmpxchg((ptr), (old), (new), __ATOMIC_SEQ_CST)

#define try_cmpxchg_relaxed(ptr, old, new) \
	iso_try_cmpxchg((ptr), (old), (new), __ATOMIC_RELAXED)

#define try_cmpxchg_acquire(ptr, old, new) \
	iso_try_cmpxchg((ptr), (old), (new), __ATOMIC_ACQUIRE)

#define try_cmpxchg_release(ptr, old, new) \
	iso_try_cmpxchg((ptr), (old), (new), __ATOMIC_RELEASE)

/**
 * cmpxchg - Check variable and replace if expected value.
 * @ptr: Pointer to target variable
 * @old: The value to check for
 * @new: The value to replace with
 *
 * Atomically checks the contents of *@ptr and, if the same as @old, replaces
 * it with @new.  The value read from *@ptr is returned.
 *
 * try_cmpxchg() and cmpxchg_return() are preferred to this function as they
 * can make better use of the knowledge as to whether a write took place or not
 * that is provided by some CPUs (e.g. x86's CMPXCHG instruction stores this in
 * the Z flag).
 */
static inline __deprecated void cmpxchg__use_cmpxchg_return_instead(void) { }

#define iso_cmpxchg(ptr, old, new, mem)					\
	({								\
		__typeof__((ptr)) __ptr = (ptr);			\
		__typeof__(*__ptr) __old = (old);			\
		__typeof__(*__ptr) __orig = __old;			\
		cmpxchg__use_cmpxchg_return_instead();			\
		__atomic_compare_exchange_n(__ptr,			\
					    &__orig, (new),		\
					    false,			\
					    mem,			\
					    __ATOMIC_RELAXED) ?		\
			__old : __orig;					\
	})

#define cmpxchg(ptr, old, new)		iso_cmpxchg((ptr), (old), (new), __ATOMIC_SEQ_CST)
#define cmpxchg_relaxed(ptr, old, new)	iso_cmpxchg((ptr), (old), (new), __ATOMIC_RELAXED)
#define cmpxchg_acquire(ptr, old, new)	iso_cmpxchg((ptr), (old), (new), __ATOMIC_ACQUIRE)
#define cmpxchg_release(ptr, old, new)	iso_cmpxchg((ptr), (old), (new), __ATOMIC_RELEASE)

#define cmpxchg64(ptr, old, new)	 cmpxchg((ptr), (old), (new))
#define cmpxchg64_relaxed(ptr, old, new) cmpxchg_relaxed((ptr), (old), (new))
#define cmpxchg64_acquire(ptr, old, new) cmpxchg_acquire((ptr), (old), (new))
#define cmpxchg64_release(ptr, old, new) cmpxchg_release((ptr), (old), (new))

/**
 * xchg - Exchange the contents of a variable for a new value
 * @ptr: Pointer to target variable
 * @new: The new value to place in @ptr
 *
 * Atomically read the contents of *@ptr and then replace those contents with
 * @new.  The value initially read from *@ptr is returned.
 */
#define iso_xchg(ptr, new, mem)						\
	({								\
		__atomic_exchange_n((ptr), (new), mem);			\
	})

#define xchg(ptr, new)		iso_xchg((ptr), (new), __ATOMIC_SEQ_CST)
#define xchg_relaxed(ptr, new)	iso_xchg((ptr), (new), __ATOMIC_RELAXED)
#define xchg_acquire(ptr, new)	iso_xchg((ptr), (new), __ATOMIC_ACQUIRE)
#define xchg_release(ptr, new)	iso_xchg((ptr), (new), __ATOMIC_RELEASE)

/**
 * xadd - Exchange the contents of a variable for a those contents plus a value
 * @ptr: Pointer to target variable
 * @addend: The value to add to *@ptr
 *
 * Atomically read the contents of *@ptr and then replace those contents with
 * that value plus @addend.  The value initially read from *@ptr is returned.
 */
#define iso_xadd(ptr, addend, mem)					\
	({								\
		__atomic_fetch_add((ptr), (addend), mem);		\
	})

#define xadd(ptr, new)		iso_xadd((ptr), (new), __ATOMIC_SEQ_CST)
#define xadd_relaxed(ptr, new)	iso_xadd((ptr), (new), __ATOMIC_RELAXED)
#define xadd_acquire(ptr, new)	iso_xadd((ptr), (new), __ATOMIC_ACQUIRE)
#define xadd_release(ptr, new)	iso_xadd((ptr), (new), __ATOMIC_RELEASE)

/**
 * add_smp - Atomically add a value to a variable
 * @ptr: Pointer to target variable
 * @addend: The value to add to *@ptr
 *
 * Atomically add the @addend to the contents of *@ptr.
 *
 * Note that the zeroness and sign of the result can be returned free of charge
 * on some arches by comparing against zero.
 */
#define iso_add(ptr, addend, mem)					\
	({								\
		__atomic_fetch_add((ptr), (addend), mem);		\
	})

#define __add(ptr, new)		iso_add((ptr), (new), __ATOMIC_SEQ_CST)
#define add_release(ptr, new)	iso_add((ptr), (new), __ATOMIC_RELEASE)
#define add_smp(ptr, new)	iso_add((ptr), (new), __ATOMIC_SEQ_CST)

#endif /* _ASM_GENERIC_ISO_CMPXCHG_H */
