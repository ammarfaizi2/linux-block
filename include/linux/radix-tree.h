/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 */
#ifndef _LINUX_RADIX_TREE_H
#define _LINUX_RADIX_TREE_H

#include <linux/preempt.h>
#include <linux/percpu.h>
#include <linux/bitops.h>
#include <linux/gfp.h>
#include <linux/lockdep.h>
#include <linux/xarray_types.h>

/* Keep unconverted code working */
#define radix_tree_root		xarray
#define radix_tree_node		xa_node

/* The IDR tag is stored in the low bits of xa_flags */
#define ROOT_IS_IDR	((__force gfp_t)4)
/* The top bits of xa_flags are used to store the root tags */
#define ROOT_TAG_SHIFT	(__GFP_BITS_SHIFT)

#define RADIX_TREE_INIT(name, mask)	XARRAY_INIT(name, mask)

#define RADIX_TREE(name, mask) \
	struct radix_tree_root name = RADIX_TREE_INIT(name, mask)

#define INIT_RADIX_TREE(root, mask) xa_init_flags(root, mask)

#endif /* _LINUX_RADIX_TREE_H */
