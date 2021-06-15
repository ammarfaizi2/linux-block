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
#include <linux/local_lock.h>
#include <linux/percpu.h>
#include <linux/bitops.h>
#include <linux/preempt.h>
#include <linux/sched.h>

/* Keep unconverted code working */
#define radix_tree_root		xarray
#define radix_tree_node		xa_node

#endif /* _LINUX_RADIX_TREE_H */
