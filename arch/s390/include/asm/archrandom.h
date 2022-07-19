/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel interface for the s390 arch_random_* functions
 *
 * Copyright IBM Corp. 2017, 2020
 *
 * Author: Harald Freudenberger <freude@de.ibm.com>
 *
 */

#ifndef _ASM_S390_ARCHRANDOM_H
#define _ASM_S390_ARCHRANDOM_H

#include <linux/static_key.h>
#include <linux/atomic.h>
#include <asm/cpacf.h>

DECLARE_STATIC_KEY_FALSE(s390_arch_random_available);
extern atomic64_t s390_arch_random_counter;

static inline size_t __must_check arch_get_random_words(unsigned long *v, size_t words)
{
	return 0;
}

static inline size_t __must_check arch_get_random_seed_words(unsigned long *v, size_t words)
{
	if (static_branch_likely(&s390_arch_random_available)) {
		cpacf_trng(NULL, 0, (u8 *)v, words * sizeof(*v));
		atomic64_add(words * sizeof(*v), &s390_arch_random_counter);
		return words;
	}
	return 0;
}

#endif /* _ASM_S390_ARCHRANDOM_H */
