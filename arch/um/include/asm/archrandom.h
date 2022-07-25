/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_UM_ARCHRANDOM_H__
#define __ASM_UM_ARCHRANDOM_H__

#include <linux/types.h>

/* This is from <os.h>, but better not to #include that in a global header here. */
ssize_t os_getrandom(void *buf, size_t len, unsigned int flags);

/*
 * This should only be used by drivers/char/random.c. Other drivers *must*
 * use get_random_bytes() instead.
 */
static inline size_t __must_check arch_get_random_longs(unsigned long *v, size_t max_longs)
{
	ssize_t ret;

	ret = os_getrandom(v, max_longs * sizeof(*v), 0);
	if (ret < 0)
		return 0;
	return ret / sizeof(*v);
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
