/* User-mappable watch queue
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_WATCH_QUEUE_H
#define _LINUX_WATCH_QUEUE_H

#include <uapi/linux/watch_queue.h>

#ifdef CONFIG_WATCH_QUEUE

struct watch_queue;

/*
 * Representation of a watch on an object.
 */
struct watch {
	union {
		struct rcu_head	rcu;
		u32		info_id;	/* ID to be OR'd in to info field */
	};
	struct watch_queue __rcu *queue;	/* Queue to post events to */
	struct hlist_node	queue_node;	/* Link in queue->watches */
	struct watch_list __rcu	*watch_list;
	struct hlist_node	list_node;	/* Link in watch_list->watchers */
	void			*private;	/* Private data for the watched object */
	u64			id;		/* Internal identifier */
	refcount_t		usage;
};

/*
 * List of watches on an object.
 */
struct watch_list {
	struct rcu_head		rcu;
	struct hlist_head	watchers;
	void (*release_watch)(struct watch_list *, struct watch *);
	spinlock_t		lock;
};

extern void __post_watch_notification(struct watch_list *,
				      struct watch_notification *,
				      const struct cred *,
				      u64);
extern struct watch_queue *get_watch_queue(int);
extern void put_watch_queue(struct watch_queue *);
extern void put_watch_list(struct watch_list *);
extern int add_watch_to_object(struct watch *);
extern int remove_watch_from_object(struct watch_list *, struct watch_queue *, u64, bool);

static inline void init_watch_list(struct watch_list *wlist)
{
	INIT_HLIST_HEAD(&wlist->watchers);
	spin_lock_init(&wlist->lock);
}

static inline void init_watch(struct watch *watch)
{
	refcount_set(&watch->usage, 1);
	INIT_HLIST_NODE(&watch->list_node);
	INIT_HLIST_NODE(&watch->queue_node);
}

static inline void post_watch_notification(struct watch_list *wlist,
					   struct watch_notification *n,
					   const struct cred *cred,
					   u64 id)
{
	if (unlikely(wlist))
		__post_watch_notification(wlist, n, cred, id);
}

static inline void remove_watch_list(struct watch_list *wlist)
{
	if (wlist) {
		remove_watch_from_object(wlist, NULL, 0, true);
		kfree_rcu(wlist, rcu);
	}
}

#endif

#endif /* _LINUX_WATCH_QUEUE_H */
