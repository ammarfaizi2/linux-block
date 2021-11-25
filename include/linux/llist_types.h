/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LLIST_TYPES_H
#define LLIST_TYPES_H

#include <linux/stddef.h>

struct llist_head {
	struct llist_node *first;
};

struct llist_node {
	struct llist_node *next;
};

#define LLIST_HEAD_INIT(name)	{ NULL }
#define LLIST_HEAD(name)	struct llist_head name = LLIST_HEAD_INIT(name)

/**
 * init_llist_head - initialize lock-less list head
 * @head:	the head for your lock-less list
 */
static inline void init_llist_head(struct llist_head *list)
{
	list->first = NULL;
}

#endif /* LLIST_TYPES_H */
