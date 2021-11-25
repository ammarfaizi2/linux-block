/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_API_KVMALLOC_H
#define _LINUX_MM_API_KVMALLOC_H

#include <linux/overflow.h>
#include <linux/numa_types.h>
#include <linux/gfp_types.h>

extern void *kvmalloc_node(size_t size, gfp_t flags, int node) __alloc_size(1);
static inline __alloc_size(1) void *kvmalloc(size_t size, gfp_t flags)
{
	return kvmalloc_node(size, flags, NUMA_NO_NODE);
}
static inline __alloc_size(1) void *kvzalloc_node(size_t size, gfp_t flags, int node)
{
	return kvmalloc_node(size, flags | __GFP_ZERO, node);
}
static inline __alloc_size(1) void *kvzalloc(size_t size, gfp_t flags)
{
	return kvmalloc(size, flags | __GFP_ZERO);
}

static inline __alloc_size(1, 2) void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;

	return kvmalloc(bytes, flags);
}

static inline __alloc_size(1, 2) void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
	return kvmalloc_array(n, size, flags | __GFP_ZERO);
}

extern void *kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
		      __alloc_size(3);
extern void kvfree(const void *addr);
extern void kvfree_sensitive(const void *addr, size_t len);

#endif /* _LINUX_MM_API_KVMALLOC_H */
