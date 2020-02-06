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

#define NR_MAXCACHES BITS_PER_LONG

struct seq_file;
struct fscache_cache;
struct fscache_cache_ops;
struct fscache_object;

enum fscache_obj_ref_trace {
	fscache_obj_get_attach,
	fscache_obj_get_exists,
	fscache_obj_get_inval,
	fscache_obj_get_ioreq,
	fscache_obj_get_wait,
	fscache_obj_get_withdraw,
	fscache_obj_new,
	fscache_obj_put,
	fscache_obj_put_alloc_dup,
	fscache_obj_put_alloc_fail,
	fscache_obj_put_attach_fail,
	fscache_obj_put_drop_child,
	fscache_obj_put_drop_obj,
	fscache_obj_put_inval,
	fscache_obj_put_ioreq,
	fscache_obj_put_lookup_fail,
	fscache_obj_put_withdraw,
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
	struct fscache_object *(*alloc_object)(struct fscache_cookie *cookie,
					       struct fscache_cache *cache,
					       struct fscache_object *parent);

	/* Prepare data used in lookup */
	void *(*prepare_lookup_data)(struct fscache_object *object);

	/* Look up the object for a cookie */
	bool (*lookup_object)(struct fscache_object *object, void *lookup_data);

	/* Create the object for a cookie */
	bool (*create_object)(struct fscache_object *object, void *lookup_data);

	/* Clean up lookup data */
	void (*free_lookup_data)(struct fscache_object *object, void *lookup_data);

	/* increment the usage count on this object (may fail if unmounting) */
	struct fscache_object *(*grab_object)(struct fscache_object *object,
					      enum fscache_obj_ref_trace why);

	/* pin an object in the cache */
	int (*pin_object)(struct fscache_object *object);

	/* unpin an object in the cache */
	void (*unpin_object)(struct fscache_object *object);

	/* Change the size of a data object */
	void (*resize_object)(struct fscache_object *object, loff_t new_size);

	/* Invalidate an object */
	bool (*invalidate_object)(struct fscache_object *object,
				  unsigned int flags);

	/* discard the resources pinned by an object and effect retirement if
	 * necessary */
	void (*drop_object)(struct fscache_object *object, bool invalidate);

	/* dispose of a reference to an object */
	void (*put_object)(struct fscache_object *object,
			   enum fscache_obj_ref_trace why);

	/* Get object usage count */
	unsigned int (*get_object_usage)(const struct fscache_object *object);

	/* sync a cache */
	void (*sync_cache)(struct fscache_cache *cache);

	/* reserve space for an object's data and associated metadata */
	int (*reserve_space)(struct fscache_object *object, loff_t i_size);

	/* Begin an operation on a cache object */
	void (*begin_operation)(struct fscache_op_resources *opr);

	/* Prepare to write to a live cache object */
	int (*prepare_to_write)(struct fscache_object *object);

	/* Display object info in /proc/fs/fscache/objects */
	int (*display_object)(struct seq_file *m, struct fscache_object *object);
};

extern struct fscache_cookie fscache_fsdef_index;

enum fscache_object_stage {
	FSCACHE_OBJECT_STAGE_INITIAL,
	FSCACHE_OBJECT_STAGE_LOOKING_UP,
	FSCACHE_OBJECT_STAGE_UNCREATED,		/* Needs creation */
	FSCACHE_OBJECT_STAGE_LIVE_TEMP,		/* Temporary object created, can be no hits */
	FSCACHE_OBJECT_STAGE_LIVE_EMPTY,	/* Object was freshly created, can be no hits */
	FSCACHE_OBJECT_STAGE_LIVE,		/* Object is populated */
	FSCACHE_OBJECT_STAGE_DESTROYING,
	FSCACHE_OBJECT_STAGE_DEAD,
};

/*
 * on-disk cache file or index handle
 */
struct fscache_object {
	int			debug_id;	/* debugging ID */
	int			n_children;	/* number of child objects */
	unsigned int		inval_counter;	/* Number of invalidations applied */
	enum fscache_object_stage stage;	/* Stage of object's lifecycle */
	spinlock_t		lock;		/* state and operations lock */

	unsigned long		flags;
#define FSCACHE_OBJECT_LOCAL_WRITE	1	/* T if the object is being modified locally */
#define FSCACHE_OBJECT_NEEDS_INVAL	8	/* T if object needs invalidation */
#define FSCACHE_OBJECT_NEEDS_UPDATE	9	/* T if object attrs need writing to disk */

	struct list_head	cache_link;	/* link in cache->object_list */
	struct hlist_node	cookie_link;	/* link in cookie->backing_objects */
	struct fscache_cache	*cache;		/* cache that supplied this object */
	struct fscache_cookie	*cookie;	/* netfs's file/index object */
	struct fscache_object	*parent;	/* parent object */
#ifdef CONFIG_FSCACHE_OBJECT_LIST
	struct rb_node		objlist_link;	/* link in global object list */
#endif
};

extern void fscache_object_init(struct fscache_object *, struct fscache_cookie *,
				struct fscache_cache *);
extern void fscache_object_destroy(struct fscache_object *);

static inline bool fscache_cache_is_broken(struct fscache_object *object)
{
	return test_bit(FSCACHE_IOERROR, &object->cache->flags);
}

extern void fscache_object_destroyed(struct fscache_cache *cache);

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

/*
 * Count the start of an I/O operation
 */
static inline void fscache_count_io_operation(struct fscache_cookie *cookie)
{
	atomic_inc(&cookie->n_ops);
}

/*
 * Count the end of an I/O operation
 */
static inline void fscache_uncount_io_operation(struct fscache_cookie *cookie)
{
	if (atomic_dec_and_test(&cookie->n_ops))
		wake_up_var(&cookie->n_ops);
}

extern void __fscache_wait_for_operation(struct fscache_op_resources *, enum fscache_want_stage);
extern void __fscache_end_operation(struct fscache_op_resources *);

#ifdef CONFIG_FSCACHE_STATS
extern atomic_t fscache_n_read;
extern atomic_t fscache_n_write;
#define fscache_count_read() atomic_inc(&fscache_n_read)
#define fscache_count_write() atomic_inc(&fscache_n_write)
#else
#define fscache_count_read() do {} while(0)
#define fscache_count_write() do {} while(0)
#endif

#endif /* _LINUX_FSCACHE_CACHE_H */
