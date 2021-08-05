/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Sleepable Read-Copy Update mechanism for mutual exclusion
 *
 * Copyright (C) IBM Corporation, 2006
 * Copyright (C) Fujitsu, 2012
 *
 * Author: Paul McKenney <paulmck@linux.ibm.com>
 *	   Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 *		Documentation/RCU/ *.txt
 *
 */
#ifndef _LINUX_SRCU_TYPES_H
#define _LINUX_SRCU_TYPES_H

#include <linux/rcu_segcblist.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define __SRCU_DEP_MAP_INIT(srcu_name)	.dep_map = { .name = #srcu_name },
#else
# define __SRCU_DEP_MAP_INIT(srcu_name)
#endif

#ifdef CONFIG_TINY_SRCU
# include <linux/srcutiny.h>
#elif defined(CONFIG_TREE_SRCU)
# include <linux/srcutree.h>
#elif defined(CONFIG_SRCU)
# error "Unknown SRCU implementation specified to kernel configuration"
#else
/* Dummy definition for things like notifiers.  Actual use gets link error. */
struct srcu_struct { };
#endif

#endif /* _LINUX_SRCU_TYPES_H */
