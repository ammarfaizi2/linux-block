/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_LOCAL_TYPES_H
#define _ASM_X86_LOCAL_TYPES_H

#include <linux/types.h>

typedef struct {
	atomic_long_t a;
} local_t;

#define LOCAL_INIT(i)	{ ATOMIC_LONG_INIT(i) }

#endif /* _ASM_X86_LOCAL_TYPES_H */
