/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2013 Red Hat, Inc. and Parallels Inc. All rights reserved.
 * Authors: David Chinner and Glauber Costa
 *
 * Generic LRU infrastructure
 */
#ifndef _LINUX_LIST_LRU_TYPES_H
#define _LINUX_LIST_LRU_TYPES_H

#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/cache.h>

struct mem_cgroup;
struct lock_class_key;

/* list_lru_walk_cb has to always return one of those */
enum lru_status {
	LRU_REMOVED,		/* item removed from list */
	LRU_REMOVED_RETRY,	/* item removed, but lock has been
				   dropped and reacquired */
	LRU_ROTATE,		/* item referenced, give another pass */
	LRU_SKIP,		/* item cannot be locked, skip */
	LRU_RETRY,		/* item not freeable. May drop the lock
				   internally, but has to return locked. */
};

struct list_lru_one {
	struct list_head	list;
	/* may become negative during memcg reparenting */
	long			nr_items;
};

struct list_lru_memcg {
	struct rcu_head		rcu;
	/* array of per cgroup lists, indexed by memcg_cache_id */
	struct list_lru_one	*lru[];
};

struct ____cacheline_aligned_in_smp list_lru_node {
	/* protects all lists on the node, including per cgroup */
	spinlock_t		lock;
	/* global list, used for the root cgroup in cgroup aware lrus */
	struct list_lru_one	lru;
#ifdef CONFIG_MEMCG_KMEM
	/* for cgroup aware lrus points to per cgroup lists, otherwise NULL */
	struct list_lru_memcg	__rcu *memcg_lrus;
#endif
	long nr_items;
};

struct list_lru {
	struct list_lru_node	*node;
#ifdef CONFIG_MEMCG_KMEM
	struct list_head	list;
	int			shrinker_id;
	bool			memcg_aware;
#endif
};

struct shrinker;

void list_lru_destroy(struct list_lru *lru);
int __list_lru_init(struct list_lru *lru, bool memcg_aware,
		    struct lock_class_key *key, struct shrinker *shrinker);

#define list_lru_init(lru)				\
	__list_lru_init((lru), false, NULL, NULL)
#define list_lru_init_key(lru, key)			\
	__list_lru_init((lru), false, (key), NULL)
#define list_lru_init_memcg(lru, shrinker)		\
	__list_lru_init((lru), true, NULL, shrinker)

#endif /* _LINUX_LIST_LRU_TYPES_H */
