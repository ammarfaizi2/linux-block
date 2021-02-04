/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NS_COMMON_H
#define _LINUX_NS_COMMON_H

#include <linux/refcount.h>
#include <linux/slab.h>

struct proc_ns_operations;

/*
 * Comparable tag for namespaces so that namespaces don't have to be pinned by
 * something that wishes to detect if a namespace matches a criterion.
 */
struct ns_tag {
	refcount_t	usage;
};

struct ns_common {
	atomic_long_t stashed;
	const struct proc_ns_operations *ops;
	struct ns_tag *tag;
	unsigned int inum;
	refcount_t count;
};

static inline struct ns_tag *get_ns_tag(struct ns_tag *tag)
{
	if (tag)
		refcount_inc(&tag->usage);
	return tag;
}

static inline void put_ns_tag(struct ns_tag *tag)
{
	if (tag && refcount_dec_and_test(&tag->usage))
		kfree(tag);
}

#endif
