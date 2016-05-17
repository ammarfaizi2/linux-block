/* Use ISO C++11 intrinsics to implement bitops.
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _ASM_GENERIC_ISO_BITOPS_H
#define _ASM_GENERIC_ISO_BITOPS_H

#include <linux/compiler.h>
#include <linux/types.h>

static __always_inline
bool test_bit(long bit, const volatile unsigned long *addr)
{
	const volatile unsigned int *addr32 = (const volatile unsigned int *)addr;
	unsigned int mask = 1U << (bit & (32 - 1));
	unsigned int old;

	addr32 += bit >> 5;
	old = __atomic_load_n(addr32, __ATOMIC_RELAXED);
	return old & mask;
}

/**
 * set_bit - Atomically set a bit in memory
 * @bit: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit() if you do
 * not require the atomic guarantees.
 *
 * Note: there are no guarantees that this function will not be reordered on
 * non x86 architectures, so if you are writing portable code, make sure not to
 * rely on its reordering guarantees.
 *
 * Note that @bit may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static __always_inline
void iso_set_bit(long bit, volatile unsigned long *addr, int memorder)
{
	volatile unsigned int *addr32 = (volatile unsigned int *)addr;
	unsigned int mask = 1U << (bit & (32 - 1));

	addr32 += bit >> 5;
	__atomic_fetch_or(addr32, mask, memorder);
}

#define set_bit(b, a) iso_set_bit((b), (a), __ATOMIC_ACQ_REL)

/**
 * set_bit_unlock - Sets a bit in memory with release semantics
 * @bit: Bit to set
 * @addr: Address to start counting from
 *
 * This function is atomic and implies release semantics before the memory
 * operation. It can be used for an unlock.
 */
#define set_bit_unlock(b, a) iso_set_bit((b), (a), __ATOMIC_RELEASE)

/**
 * clear_bit - Sets a bit in memory
 * @bit: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does not
 * contain a memory barrier, so if it is used for locking purposes, you should
 * call smp_mb__before_atomic() and/or smp_mb__after_atomic() in order to
 * ensure changes are visible on other processors.
 */
static __always_inline
void iso_clear_bit(long bit, volatile unsigned long *addr, int memorder)
{
	volatile unsigned int *addr32 = (volatile unsigned int *)addr;
	unsigned int mask = 1U << (bit & (32 - 1));

	addr32 += bit >> 5;
	__atomic_fetch_and(addr32, ~mask, memorder);
}

#define clear_bit(b, a) iso_clear_bit((b), (a), __ATOMIC_ACQ_REL)

/**
 * clear_bit_unlock - Clears a bit in memory with release semantics
 * @bit: Bit to clear
 * @addr: Address to start counting from
 *
 * This function is atomic and implies release semantics before the memory
 * operation. It can be used for an unlock.
 */
#define clear_bit_unlock(b, a) iso_clear_bit((b), (a), __ATOMIC_RELEASE)

/**
 * change_bit - Toggle a bit in memory
 * @bit: Bit to change
 * @addr: Address to start counting from
 *
 * change_bit() is atomic and may not be reordered.  Note that @bit may be
 * almost arbitrarily large; this function is not restricted to acting on a
 * single-word quantity.
 */
static __always_inline
void iso_change_bit(long bit, volatile unsigned long *addr, int memorder)
{
	volatile unsigned int *addr32 = (volatile unsigned int *)addr;
	unsigned int mask = 1U << (bit & (32 - 1));

	addr32 += bit >> 5;
	__atomic_fetch_xor(addr32, mask, memorder);
}

#define change_bit(b, a) iso_change_bit((b), (a), __ATOMIC_ACQ_REL)

/**
 * test_and_set_bit - Set a bit and return its old value
 * @bit: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  It also implies memory
 * barriers both sides.
 */
static __always_inline
bool iso_test_and_set_bit(long bit, volatile unsigned long *addr, int memorder)
{
	volatile unsigned int *addr32 = (volatile unsigned int *)addr;
	unsigned int mask = 1U << (bit & (32 - 1));
	unsigned int old;

	addr32 += bit >> 5;
	old = __atomic_fetch_or(addr32, mask, memorder);
	return old & mask;
}

#define test_and_set_bit(b, a)      iso_test_and_set_bit((b), (a), __ATOMIC_ACQ_REL)
#define test_and_set_bit_lock(b, a) iso_test_and_set_bit((b), (a), __ATOMIC_ACQUIRE)

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @bit: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  It also implies memory
 * barriers both sides.
 */
static __always_inline
bool iso_test_and_clear_bit(long bit, volatile unsigned long *addr, int memorder)
{
	volatile unsigned int *addr32 = (volatile unsigned int *)addr;
	unsigned int mask = 1U << (bit & (32 - 1));
	unsigned int old;

	addr32 += bit >> 5;
	old = __atomic_fetch_and(addr32, ~mask, memorder);
	return old & mask;
}

#define test_and_clear_bit(b, a)      iso_test_and_clear_bit((b), (a), __ATOMIC_ACQ_REL)
#define test_and_clear_bit_lock(b, a) iso_test_and_clear_bit((b), (a), __ATOMIC_ACQUIRE)

/**
 * test_and_change_bit - Toggle a bit and return its old value
 * @bit: Bit to toggle
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  It also implies memory
 * barriers both sides.
 */
static __always_inline
bool iso_test_and_change_bit(long bit, volatile unsigned long *addr, int memorder)
{
	volatile unsigned int *addr32 = (volatile unsigned int *)addr;
	unsigned int mask = 1U << (bit & (32 - 1));
	unsigned int old;

	addr32 += bit >> 5;
	old = __atomic_fetch_xor(addr32, mask, memorder);
	return old & mask;
}

#define test_and_change_bit(b, a)     iso_test_and_change_bit((b), (a), __ATOMIC_ACQ_REL)

#endif /* _ASM_GENERIC_ISO_BITOPS_H */
