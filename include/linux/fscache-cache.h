/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General filesystem caching backing cache interface
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/backend-api.rst
 *
 * for a description of the cache backend interface declared here.
 */

#ifndef _LINUX_FSCACHE_CACHE_H
#define _LINUX_FSCACHE_CACHE_H

#include <linux/fscache.h>
#include <linux/sched.h>
#include <linux/workqueue.h>

#define NR_MAXCACHES BITS_PER_LONG

struct fscache_cache;
struct fscache_cache_ops;
struct fscache_object;

enum fscache_obj_ref_trace {
	fscache_obj_get_add_to_deps,
	fscache_obj_get_queue,
	fscache_obj_put_alloc_fail,
	fscache_obj_put_attach_fail,
	fscache_obj_put_drop_obj,
	fscache_obj_put_enq_dep,
	fscache_obj_put_queue,
	fscache_obj_put_work,
	fscache_obj_ref__nr_traces
};

/*
 * cache tag definition
 */
struct fscache_cache_tag {
	struct list_head	link;
	struct fscache_cache	*cache;		/* cache referred to by this tag */
	unsigned long		flags;
#define FSCACHE_TAG_RESERVED	0		/* T if tag is reserved for a cache */
	atomic_t		usage;		/* Number of using netfs's */
	refcount_t		ref;		/* Reference count on structure */
	char			name[];		/* tag name */
};

/*
 * cache definition
 */
struct fscache_cache {
	const struct fscache_cache_ops *ops;
	struct fscache_cache_tag *tag;		/* tag representing this cache */
	struct kobject		*kobj;		/* system representation of this cache */
	struct list_head	link;		/* link in list of caches */
	size_t			max_index_size;	/* maximum size of index data */
	char			identifier[36];	/* cache label */

	/* node management */
	struct list_head	object_list;	/* list of data/index objects */
	spinlock_t		object_list_lock;
	atomic_t		object_count;	/* no. of live objects in this cache */
	struct fscache_object	*fsdef;		/* object for the fsdef index */
	unsigned long		flags;
#define FSCACHE_IOERROR		0	/* cache stopped on I/O error */
#define FSCACHE_CACHE_WITHDRAWN	1	/* cache has been withdrawn */
};

extern wait_queue_head_t fscache_cache_cleared_wq;

/*
 * cache operations
 */
struct fscache_cache_ops {
	/* name of cache provider */
	const char *name;

	/* allocate an object record for a cookie */
	struct fscache_object *(*alloc_object)(struct fscache_cache *cache,
					       struct fscache_cookie *cookie);

	/* look up the object for a cookie
	 * - return -ETIMEDOUT to be requeued
	 */
	int (*lookup_object)(struct fscache_object *object);

	/* finished looking up */
	void (*lookup_complete)(struct fscache_object *object);

	/* increment the usage count on this object (may fail if unmounting) */
	struct fscache_object *(*grab_object)(struct fscache_object *object,
					      enum fscache_obj_ref_trace why);

	/* pin an object in the cache */
	int (*pin_object)(struct fscache_object *object);

	/* unpin an object in the cache */
	void (*unpin_object)(struct fscache_object *object);

	/* store the updated auxiliary data on an object */
	void (*update_object)(struct fscache_object *object);

	/* Invalidate an object */
	void (*invalidate_object)(struct fscache_object *object);

	/* discard the resources pinned by an object and effect retirement if
	 * necessary */
	void (*drop_object)(struct fscache_object *object);

	/* dispose of a reference to an object */
	void (*put_object)(struct fscache_object *object,
			   enum fscache_obj_ref_trace why);

	/* sync a cache */
	void (*sync_cache)(struct fscache_cache *cache);

	/* reserve space for an object's data and associated metadata */
	int (*reserve_space)(struct fscache_object *object, loff_t i_size);

	/* Begin a read operation for the netfs lib */
	int (*begin_read_operation)(struct netfs_read_request *rreq);
};

extern struct fscache_cookie fscache_fsdef_index;

/*
 * Event list for fscache_object::{event_mask,events}
 */
enum {
	FSCACHE_OBJECT_EV_NEW_CHILD,	/* T if object has a new child */
	FSCACHE_OBJECT_EV_PARENT_READY,	/* T if object's parent is ready */
	FSCACHE_OBJECT_EV_UPDATE,	/* T if object should be updated */
	FSCACHE_OBJECT_EV_INVALIDATE,	/* T if cache requested object invalidation */
	FSCACHE_OBJECT_EV_CLEARED,	/* T if accessors all gone */
	FSCACHE_OBJECT_EV_ERROR,	/* T if fatal error occurred during processing */
	FSCACHE_OBJECT_EV_KILL,		/* T if netfs relinquished or cache withdrew object */
	NR_FSCACHE_OBJECT_EVENTS
};

#define FSCACHE_OBJECT_EVENTS_MASK ((1UL << NR_FSCACHE_OBJECT_EVENTS) - 1)

/*
 * States for object state machine.
 */
struct fscache_transition {
	unsigned long events;
	const struct fscache_state *transit_to;
};

struct fscache_state {
	char name[24];
	char short_name[8];
	const struct fscache_state *(*work)(struct fscache_object *object,
					    int event);
	const struct fscache_transition transitions[];
};

/*
 * on-disk cache file or index handle
 */
struct fscache_object {
	const struct fscache_state *state;	/* Object state machine state */
	const struct fscache_transition *oob_table; /* OOB state transition table */
	int			debug_id;	/* debugging ID */
	int			n_children;	/* number of child objects */
	int			n_ops;		/* number of extant ops on object */
	int			n_obj_ops;	/* number of object ops outstanding on object */
	spinlock_t		lock;		/* state and operations lock */

	unsigned long		lookup_jif;	/* time at which lookup started */
	unsigned long		oob_event_mask;	/* OOB events this object is interested in */
	unsigned long		event_mask;	/* events this object is interested in */
	unsigned long		events;		/* events to be processed by this object
						 * (order is important - using fls) */

	unsigned long		flags;
#define FSCACHE_OBJECT_LOCK		0	/* T if object is busy being processed */
#define FSCACHE_OBJECT_WAITING		2	/* T if object is waiting on its parent */
#define FSCACHE_OBJECT_IS_LIVE		3	/* T if object is not withdrawn or relinquished */
#define FSCACHE_OBJECT_IS_LOOKED_UP	4	/* T if object has been looked up */
#define FSCACHE_OBJECT_IS_AVAILABLE	5	/* T if object has become active */
#define FSCACHE_OBJECT_RETIRED		6	/* T if object was retired on relinquishment */
#define FSCACHE_OBJECT_KILLED_BY_CACHE	7	/* T if object was killed by the cache */
#define FSCACHE_OBJECT_RUN_AFTER_DEAD	8	/* T if object has been dispatched after death */

	struct list_head	cache_link;	/* link in cache->object_list */
	struct hlist_node	cookie_link;	/* link in cookie->backing_objects */
	struct fscache_cache	*cache;		/* cache that supplied this object */
	struct fscache_cookie	*cookie;	/* netfs's file/index object */
	struct fscache_object	*parent;	/* parent object */
	struct work_struct	work;		/* attention scheduling record */
	struct list_head	dependents;	/* FIFO of dependent objects */
	struct list_head	dep_link;	/* link in parent's dependents list */
#ifdef CONFIG_FSCACHE_OBJECT_LIST
	struct rb_node		objlist_link;	/* link in global object list */
#endif
};

extern void fscache_object_init(struct fscache_object *, struct fscache_cookie *,
				struct fscache_cache *);
extern void fscache_object_destroy(struct fscache_object *);

extern void fscache_object_lookup_negative(struct fscache_object *object);
extern void fscache_obtained_object(struct fscache_object *object);

static inline bool fscache_object_is_live(struct fscache_object *object)
{
	return test_bit(FSCACHE_OBJECT_IS_LIVE, &object->flags);
}

static inline bool fscache_object_is_dying(struct fscache_object *object)
{
	return !fscache_object_is_live(object);
}

static inline bool fscache_object_is_available(struct fscache_object *object)
{
	return test_bit(FSCACHE_OBJECT_IS_AVAILABLE, &object->flags);
}

static inline bool fscache_cache_is_broken(struct fscache_object *object)
{
	return test_bit(FSCACHE_IOERROR, &object->cache->flags);
}

static inline bool fscache_object_is_active(struct fscache_object *object)
{
	return fscache_object_is_available(object) &&
		fscache_object_is_live(object) &&
		!fscache_cache_is_broken(object);
}

/**
 * fscache_object_destroyed - Note destruction of an object in a cache
 * @cache: The cache from which the object came
 *
 * Note the destruction and deallocation of an object record in a cache.
 */
static inline void fscache_object_destroyed(struct fscache_cache *cache)
{
	if (atomic_dec_and_test(&cache->object_count))
		wake_up_all(&fscache_cache_cleared_wq);
}

/**
 * fscache_object_lookup_error - Note an object encountered an error
 * @object: The object on which the error was encountered
 *
 * Note that an object encountered a fatal error (usually an I/O error) and
 * that it should be withdrawn as soon as possible.
 */
static inline void fscache_object_lookup_error(struct fscache_object *object)
{
	set_bit(FSCACHE_OBJECT_EV_ERROR, &object->events);
}

static inline void __fscache_use_cookie(struct fscache_cookie *cookie)
{
	atomic_inc(&cookie->n_active);
}

/**
 * fscache_use_cookie - Request usage of cookie attached to an object
 * @object: Object description
 * 
 * Request usage of the cookie attached to an object.  NULL is returned if the
 * relinquishment had reduced the cookie usage count to 0.
 */
static inline bool fscache_use_cookie(struct fscache_object *object)
{
	struct fscache_cookie *cookie = object->cookie;
	return atomic_inc_not_zero(&cookie->n_active) != 0;
}

static inline bool __fscache_unuse_cookie(struct fscache_cookie *cookie)
{
	return atomic_dec_and_test(&cookie->n_active);
}

static inline void __fscache_wake_unused_cookie(struct fscache_cookie *cookie)
{
	wake_up_var(&cookie->n_active);
}

/**
 * fscache_unuse_cookie - Cease usage of cookie attached to an object
 * @object: Object description
 * 
 * Cease usage of the cookie attached to an object.  When the users count
 * reaches zero then the cookie relinquishment will be permitted to proceed.
 */
static inline void fscache_unuse_cookie(struct fscache_object *object)
{
	struct fscache_cookie *cookie = object->cookie;
	if (__fscache_unuse_cookie(cookie))
		__fscache_wake_unused_cookie(cookie);
}

/*
 * out-of-line cache backend functions
 */
extern __printf(3, 4)
void fscache_init_cache(struct fscache_cache *cache,
			const struct fscache_cache_ops *ops,
			const char *idfmt, ...);

extern int fscache_add_cache(struct fscache_cache *cache,
			     struct fscache_object *fsdef,
			     const char *tagname);
extern void fscache_withdraw_cache(struct fscache_cache *cache);

extern void fscache_io_error(struct fscache_cache *cache);

extern bool fscache_object_sleep_till_congested(signed long *timeoutp);

extern void fscache_object_retrying_stale(struct fscache_object *object);

enum fscache_why_object_killed {
	FSCACHE_OBJECT_IS_STALE,
	FSCACHE_OBJECT_NO_SPACE,
	FSCACHE_OBJECT_WAS_RETIRED,
	FSCACHE_OBJECT_WAS_CULLED,
};
extern void fscache_object_mark_killed(struct fscache_object *object,
				       enum fscache_why_object_killed why);

/*
 * Find the key on a cookie.
 */
static inline void *fscache_get_key(struct fscache_cookie *cookie)
{
	if (cookie->key_len <= sizeof(cookie->inline_key))
		return cookie->inline_key;
	else
		return cookie->key;
}

/*
 * Find the auxiliary data on a cookie.
 */
static inline void *fscache_get_aux(struct fscache_cookie *cookie)
{
	if (cookie->aux_len <= sizeof(cookie->inline_aux))
		return cookie->inline_aux;
	else
		return cookie->aux;
}

#endif /* _LINUX_FSCACHE_CACHE_H */
