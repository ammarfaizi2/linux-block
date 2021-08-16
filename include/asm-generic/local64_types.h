/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_LOCAL64_TYPES_H
#define _ASM_GENERIC_LOCAL64_TYPES_H

#include <asm/bitsperlong.h>

#if BITS_PER_LONG == 64

#include <asm/local_types.h>

typedef struct {
	local_t a;
} local64_t;

#define LOCAL64_INIT(i)	{ LOCAL_INIT(i) }

#else /* BITS_PER_LONG != 64 */

#include <linux/atomic_api.h>

/* Don't use typedef: don't want them to be mixed with atomic_t's. */
typedef struct {
	atomic64_t a;
} local64_t;

#define LOCAL64_INIT(i)	{ ATOMIC_LONG_INIT(i) }

#endif /* BITS_PER_LONG != 64 */

#endif /* _ASM_GENERIC_LOCAL64_TYPES_H */
