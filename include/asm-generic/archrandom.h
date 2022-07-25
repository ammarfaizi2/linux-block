/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_ARCHRANDOM_H__
#define __ASM_GENERIC_ARCHRANDOM_H__

/*
 * This should only be used by drivers/char/random.c. Other drivers *must*
 * use get_random_bytes() instead.
 */
static inline size_t __must_check arch_get_random_longs(unsigned long *v, size_t max_longs)
{
	return 0;
}

/*
 * This should only be used by drivers/char/random.c. Other drivers *must*
 * use get_random_bytes() instead.
 */
static inline size_t __must_check arch_get_random_seed_longs(unsigned long *v, size_t max_longs)
{
	return 0;
}

#endif
