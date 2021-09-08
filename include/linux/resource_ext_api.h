/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015, Intel Corporation
 * Author: Jiang Liu <jiang.liu@linux.intel.com>
 */
#ifndef _LINUX_RESOURCE_EXT_API_H
#define _LINUX_RESOURCE_EXT_API_H

#include <linux/resource_ext_types.h>

#include <linux/types.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kernel.h>

extern struct resource_entry *
resource_list_create_entry(struct resource *res, size_t extra_size);
extern void resource_list_free(struct list_head *head);

static inline void resource_list_add(struct resource_entry *entry,
				     struct list_head *head)
{
	list_add(&entry->node, head);
}

static inline void resource_list_add_tail(struct resource_entry *entry,
					  struct list_head *head)
{
	list_add_tail(&entry->node, head);
}

static inline void resource_list_del(struct resource_entry *entry)
{
	list_del(&entry->node);
}

static inline void resource_list_free_entry(struct resource_entry *entry)
{
	kfree(entry);
}

static inline void
resource_list_destroy_entry(struct resource_entry *entry)
{
	resource_list_del(entry);
	resource_list_free_entry(entry);
}

#define resource_list_for_each_entry(entry, list)	\
	list_for_each_entry((entry), (list), node)

#define resource_list_for_each_entry_safe(entry, tmp, list)	\
	list_for_each_entry_safe((entry), (tmp), (list), node)

static inline struct resource_entry *
resource_list_first_type(struct list_head *list, unsigned long type)
{
	struct resource_entry *entry;

	resource_list_for_each_entry(entry, list) {
		if (resource_type(entry->res) == type)
			return entry;
	}
	return NULL;
}

#endif /* _LINUX_RESOURCE_EXT_API_H */
