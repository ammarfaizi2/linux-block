/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Internal definitions for FS-Cache
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

/*
 * Lock order, in the order in which multiple locks should be obtained:
 * - fscache_addremove_sem
 * - cookie->lock
 * - cookie->parent->lock
 * - cache->object_list_lock
 * - object->lock
 * - object->parent->lock
 * - cookie->stores_lock
 * - fscache_thread_lock
 *
 */

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "FS-Cache: " fmt

#include <linux/slab.h>
#include <linux/fscache-cache.h>
#include <trace/events/fscache.h>
#include <linux/sched.h>
#include <linux/seq_file.h>

#define FSCACHE_MIN_THREADS	4
#define FSCACHE_MAX_THREADS	32

/*
 * cache.c
 */
extern struct list_head fscache_cache_list;
extern struct rw_semaphore fscache_addremove_sem;

extern struct fscache_cache *fscache_select_cache_for_object(
	struct fscache_cookie *);

static inline
struct fscache_cache_tag *fscache_get_cache_tag(struct fscache_cache_tag *tag)
{
	if (tag)
		refcount_inc(&tag->ref);
	return tag;
}

static inline void fscache_put_cache_tag(struct fscache_cache_tag *tag)
{
	if (tag && refcount_dec_and_test(&tag->ref))
		kfree(tag);
}

/*
 * cache_init.c
 */
extern int __init fscache_init_caching(void);
extern void __exit fscache_exit_caching(void);

/*
 * cookie.c
 */
extern void fscache_print_cookie(struct fscache_cookie *cookie, char prefix);
extern struct kmem_cache *fscache_cookie_jar;
extern const struct seq_operations fscache_cookies_seq_ops;

extern void fscache_free_cookie(struct fscache_cookie *);
extern struct fscache_cookie *fscache_alloc_cookie(struct fscache_cookie *,
						   enum fscache_cookie_type,
						   const char *,
						   u8,
						   struct fscache_cache_tag *,
						   const void *, size_t,
						   const void *, size_t,
						   loff_t);
extern struct fscache_cookie *fscache_hash_cookie(struct fscache_cookie *);
extern void fscache_cookie_put(struct fscache_cookie *,
			       enum fscache_cookie_trace);
extern struct fscache_object *fscache_attach_object(struct fscache_cookie *,
						    struct fscache_object *);
extern void fscache_set_cookie_stage(struct fscache_cookie *,
				     enum fscache_cookie_stage);
extern void fscache_drop_cookie(struct fscache_cookie *);

static inline void wake_up_cookie_stage(struct fscache_cookie *cookie)
{
	/* Use a barrier to ensure that waiters see the stage variable
	 * change, as spin_unlock doesn't guarantee a barrier.
	 *
	 * See comments over wake_up_bit() and waitqueue_active().
	 */
	smp_mb();
	wake_up_var(&cookie->stage);
}


/*
 * dispatcher.c
 */
extern void fscache_dispatch(struct fscache_cookie *, struct fscache_object *, int,
			     void (*func)(struct fscache_cookie *, struct fscache_object *, int));
extern int fscache_init_dispatchers(void);
extern void fscache_kill_dispatchers(void);

/*
 * fsdef.c
 */
extern struct fscache_cookie fscache_fsdef_index;

/*
 * histogram.c
 */
extern atomic_t fscache_obj_instantiate_histogram[HZ];
extern atomic_t fscache_objs_histogram[HZ];
extern atomic_t fscache_ops_histogram[HZ];
extern atomic_t fscache_retrieval_delay_histogram[HZ];
extern atomic_t fscache_retrieval_histogram[HZ];

#ifdef CONFIG_FSCACHE_HISTOGRAM
static inline void fscache_hist(atomic_t histogram[], unsigned long start_jif)
{
	unsigned long jif = jiffies - start_jif;
	if (jif >= HZ)
		jif = HZ - 1;
	atomic_inc(&histogram[jif]);
}

extern const struct seq_operations fscache_histogram_ops;

#else
static inline void fscache_hist(atomic_t histogram[], unsigned long start_jif)
{
}
#endif

/*
 * main.c
 */
extern unsigned fscache_debug;
extern struct kobject *fscache_root;
extern struct workqueue_struct *fscache_op_wq;

/*
 * obj.c
 */
extern void fscache_lookup_object(struct fscache_cookie *, struct fscache_object *, int);
extern void fscache_invalidate_object(struct fscache_cookie *, struct fscache_object *, int);
extern void fscache_drop_object(struct fscache_cookie *, struct fscache_object *, bool);
extern void fscache_relinquish_objects(struct fscache_cookie *, struct fscache_object *, int);
extern void fscache_prepare_to_write(struct fscache_cookie *, struct fscache_object *, int);

/*
 * object-list.c
 */
#ifdef CONFIG_FSCACHE_OBJECT_LIST
extern const struct proc_ops fscache_objlist_proc_ops;

extern void fscache_objlist_add(struct fscache_object *);
extern void fscache_objlist_remove(struct fscache_object *);
#else
#define fscache_objlist_add(object) do {} while(0)
#define fscache_objlist_remove(object) do {} while(0)
#endif

/*
 * proc.c
 */
#ifdef CONFIG_PROC_FS
extern int __init fscache_proc_caching_init(void);
#else
#define fscache_proc_init()	(0)
#endif

/*
 * stats.c
 */
#ifdef CONFIG_FSCACHE_STATS
extern atomic_t fscache_n_acquires;
extern atomic_t fscache_n_acquires_null;
extern atomic_t fscache_n_acquires_no_cache;
extern atomic_t fscache_n_acquires_ok;
extern atomic_t fscache_n_acquires_oom;

extern atomic_t fscache_n_invalidates;

extern atomic_t fscache_n_updates;

extern atomic_t fscache_n_relinquishes;
extern atomic_t fscache_n_relinquishes_retire;

extern atomic_t fscache_n_resizes;
extern atomic_t fscache_n_resizes_null;

extern atomic_t fscache_n_cookie_index;
extern atomic_t fscache_n_cookie_data;
extern atomic_t fscache_n_cookie_special;

extern atomic_t fscache_n_object_alloc;
extern atomic_t fscache_n_object_no_alloc;
extern atomic_t fscache_n_object_lookups;
extern atomic_t fscache_n_object_lookups_negative;
extern atomic_t fscache_n_object_lookups_positive;
extern atomic_t fscache_n_object_creates;
extern atomic_t fscache_n_object_avail;
extern atomic_t fscache_n_object_dead;

extern atomic_t fscache_n_cop_alloc_object;
extern atomic_t fscache_n_cop_lookup_object;
extern atomic_t fscache_n_cop_create_object;
extern atomic_t fscache_n_cop_invalidate_object;
extern atomic_t fscache_n_cop_drop_object;
extern atomic_t fscache_n_cop_put_object;
extern atomic_t fscache_n_cop_sync_cache;
extern atomic_t fscache_n_cop_attr_changed;

extern atomic_t fscache_n_cache_no_space_reject;
extern atomic_t fscache_n_cache_stale_objects;
extern atomic_t fscache_n_cache_retired_objects;
extern atomic_t fscache_n_cache_culled_objects;

extern atomic_t fscache_n_dispatch_count;
extern atomic_t fscache_n_dispatch_deferred;
extern atomic_t fscache_n_dispatch_inline;
extern atomic_t fscache_n_dispatch_in_pool;

static inline void fscache_stat(atomic_t *stat)
{
	atomic_inc(stat);
}

static inline void fscache_stat_d(atomic_t *stat)
{
	atomic_dec(stat);
}

#define __fscache_stat(stat) (stat)

extern int __init fscache_proc_stats_init(void);

#else
#define __fscache_stat(stat) (NULL)
#define fscache_stat(stat) do {} while (0)
#define fscache_stat_d(stat) do {} while (0)
#define fscache_proc_stats_init(void) 0
#endif

static inline
struct fscache_cookie *fscache_cookie_get(struct fscache_cookie *cookie,
					  enum fscache_cookie_trace where)
{
	int usage = atomic_inc_return(&cookie->usage);

	trace_fscache_cookie(cookie, where, usage);
	return cookie;
}

/*
 * Update the auxiliary data on a cookie.
 */
static inline
void fscache_update_aux(struct fscache_cookie *cookie,
			const void *aux_data, const loff_t *object_size)
{
	void *p = fscache_get_aux(cookie);

	if (aux_data && p)
		memcpy(p, aux_data, cookie->aux_len);
	if (object_size)
		cookie->object_size = *object_size;
}

/*****************************************************************************/
/*
 * debug tracing
 */
#define dbgprintk(FMT, ...) \
	printk(KERN_DEBUG "[%-6.6s] "FMT"\n", current->comm, ##__VA_ARGS__)

#define kenter(FMT, ...) dbgprintk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) dbgprintk("<== %s()"FMT"", __func__, ##__VA_ARGS__)
#define kdebug(FMT, ...) dbgprintk(FMT, ##__VA_ARGS__)

#define kjournal(FMT, ...) no_printk(FMT, ##__VA_ARGS__)

#ifdef __KDEBUG
#define _enter(FMT, ...) kenter(FMT, ##__VA_ARGS__)
#define _leave(FMT, ...) kleave(FMT, ##__VA_ARGS__)
#define _debug(FMT, ...) kdebug(FMT, ##__VA_ARGS__)

#elif defined(CONFIG_FSCACHE_DEBUG)
#define _enter(FMT, ...)			\
do {						\
	if (__do_kdebug(ENTER))			\
		kenter(FMT, ##__VA_ARGS__);	\
} while (0)

#define _leave(FMT, ...)			\
do {						\
	if (__do_kdebug(LEAVE))			\
		kleave(FMT, ##__VA_ARGS__);	\
} while (0)

#define _debug(FMT, ...)			\
do {						\
	if (__do_kdebug(DEBUG))			\
		kdebug(FMT, ##__VA_ARGS__);	\
} while (0)

#else
#define _enter(FMT, ...) no_printk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define _leave(FMT, ...) no_printk("<== %s()"FMT"", __func__, ##__VA_ARGS__)
#define _debug(FMT, ...) no_printk(FMT, ##__VA_ARGS__)
#endif

/*
 * determine whether a particular optional debugging point should be logged
 * - we need to go through three steps to persuade cpp to correctly join the
 *   shorthand in FSCACHE_DEBUG_LEVEL with its prefix
 */
#define ____do_kdebug(LEVEL, POINT) \
	unlikely((fscache_debug & \
		  (FSCACHE_POINT_##POINT << (FSCACHE_DEBUG_ ## LEVEL * 3))))
#define ___do_kdebug(LEVEL, POINT) \
	____do_kdebug(LEVEL, POINT)
#define __do_kdebug(POINT) \
	___do_kdebug(FSCACHE_DEBUG_LEVEL, POINT)

#define FSCACHE_DEBUG_CACHE	0
#define FSCACHE_DEBUG_COOKIE	1
#define FSCACHE_DEBUG_OBJECT	2
#define FSCACHE_DEBUG_OPERATION	3

#define FSCACHE_POINT_ENTER	1
#define FSCACHE_POINT_LEAVE	2
#define FSCACHE_POINT_DEBUG	4

#ifndef FSCACHE_DEBUG_LEVEL
#define FSCACHE_DEBUG_LEVEL CACHE
#endif

/*
 * assertions
 */
#if 1 /* defined(__KDEBUGALL) */

#define ASSERT(X)							\
do {									\
	if (unlikely(!(X))) {						\
		pr_err("\n");					\
		pr_err("Assertion failed\n");	\
		BUG();							\
	}								\
} while (0)

#define ASSERTCMP(X, OP, Y)						\
do {									\
	if (unlikely(!((X) OP (Y)))) {					\
		pr_err("\n");					\
		pr_err("Assertion failed\n");	\
		pr_err("%lx " #OP " %lx is false\n",		\
		       (unsigned long)(X), (unsigned long)(Y));		\
		BUG();							\
	}								\
} while (0)

#define ASSERTIF(C, X)							\
do {									\
	if (unlikely((C) && !(X))) {					\
		pr_err("\n");					\
		pr_err("Assertion failed\n");	\
		BUG();							\
	}								\
} while (0)

#define ASSERTIFCMP(C, X, OP, Y)					\
do {									\
	if (unlikely((C) && !((X) OP (Y)))) {				\
		pr_err("\n");					\
		pr_err("Assertion failed\n");	\
		pr_err("%lx " #OP " %lx is false\n",		\
		       (unsigned long)(X), (unsigned long)(Y));		\
		BUG();							\
	}								\
} while (0)

#else

#define ASSERT(X)			do {} while (0)
#define ASSERTCMP(X, OP, Y)		do {} while (0)
#define ASSERTIF(C, X)			do {} while (0)
#define ASSERTIFCMP(C, X, OP, Y)	do {} while (0)

#endif /* assert or not */
