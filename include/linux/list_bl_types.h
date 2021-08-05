/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LIST_BL_TYPES_H
#define _LINUX_LIST_BL_TYPES_H

#include <linux/types.h>

/*
 * Special version of lists, where head of the list has a lock in the lowest
 * bit. This is useful for scalable hash tables without increasing memory
 * footprint overhead.
 *
 * For modification operations, the 0 bit of hlist_bl_head->first
 * pointer must be set.
 *
 * With some small modifications, this can easily be adapted to store several
 * arbitrary bits (not just a single lock bit), if the need arises to store
 * some fast and compact auxiliary data.
 */

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
#define LIST_BL_LOCKMASK	1UL
#else
#define LIST_BL_LOCKMASK	0UL
#endif

#ifdef CONFIG_DEBUG_LIST
#define LIST_BL_BUG_ON(x) BUG_ON(x)
#else
#define LIST_BL_BUG_ON(x)
#endif


struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next, **pprev;
};
#define INIT_HLIST_BL_HEAD(ptr) \
	((ptr)->first = NULL)

static inline void INIT_HLIST_BL_NODE(struct hlist_bl_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

#define hlist_bl_entry(ptr, type, member) container_of(ptr,type,member)

#endif
