/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _KREF_TYPES_H
#define _KREF_TYPES_H

#include <linux/refcount_types.h>

struct kref {
	refcount_t refcount;
};

#define KREF_INIT(n)	{ .refcount = REFCOUNT_INIT(n), }

#endif /* _KREF_TYPES_H */
