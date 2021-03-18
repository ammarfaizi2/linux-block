/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General netfs cache on cache files internal defs
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "CacheFiles: " fmt


#include <linux/fscache-cache.h>
#include <linux/timer.h>
#include <linux/wait_bit.h>
#include <linux/cred.h>
#include <linux/workqueue.h>
#include <linux/security.h>

/* Cachefile granularity */
#define CACHEFILES_GRAN_SIZE	(256 * 1024)
#define CACHEFILES_DIO_BLOCK_SIZE 4096
#define CACHEFILES_SIZE_LIMIT	(512 * 8 * CACHEFILES_GRAN_SIZE)

struct cachefiles_cache;
struct cachefiles_object;

extern unsigned cachefiles_debug;
#define CACHEFILES_DEBUG_KENTER	1
#define CACHEFILES_DEBUG_KLEAVE	2
#define CACHEFILES_DEBUG_KDEBUG	4

#define cachefiles_gfp (__GFP_RECLAIM | __GFP_NORETRY | __GFP_NOMEMALLOC)

enum cachefiles_content {
	/* These values are saved on disk */
	CACHEFILES_CONTENT_NO_DATA	= 0, /* No content stored */
	CACHEFILES_CONTENT_SINGLE	= 1, /* Content is monolithic, all is present */
	CACHEFILES_CONTENT_ALL		= 2, /* Content is all present, no map */
	CACHEFILES_CONTENT_MAP		= 3, /* Content is piecemeal, map in use */
	CACHEFILES_CONTENT_DIRTY	= 4, /* Content is dirty (only seen on disk) */
	nr__cachefiles_content
};

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

	struct list_head	cache_link;	/* link in cache->object_list */
	struct fscache_cache	*cache;		/* cache that supplied this object */
	struct fscache_cookie	*cookie;	/* netfs's file/index object */
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
 * node records
 */
struct cachefiles_object {
	struct fscache_object		fscache;	/* fscache handle */
	struct dentry			*dentry;	/* the file/dir representing this object */
	struct dentry			*old;		/* backing file */
	struct file			*backing_file;	/* File open on backing storage */
	loff_t				i_size;		/* object size */
	atomic_t			usage;		/* object usage count */
	unsigned long			flags;
#define CACHEFILES_OBJECT_USING_TMPFILE	0		/* Object has a tmpfile that need linking */
	uint8_t				type;		/* object type */
	bool				new;		/* T if object new */

	/* Map of the content blocks in the object */
	enum cachefiles_content		content_info:8;	/* Info about content presence */
	bool				content_map_changed;
	u8				*content_map;		/* Content present bitmap */
	unsigned int			content_map_size;	/* Size of buffer */
	rwlock_t			content_map_lock;
};

extern struct kmem_cache *cachefiles_object_jar;

/*
 * Cache files cache definition
 */
struct cachefiles_cache {
	struct fscache_cache		cache;		/* FS-Cache record */
	struct vfsmount			*mnt;		/* mountpoint holding the cache */
	struct dentry			*graveyard;	/* directory into which dead objects go */
	struct file			*cachefilesd;	/* manager daemon handle */
	const struct cred		*cache_cred;	/* security override for accessing cache */
	struct mutex			daemon_mutex;	/* command serialisation mutex */
	wait_queue_head_t		daemon_pollwq;	/* poll waitqueue for daemon */
	atomic_t			gravecounter;	/* graveyard uniquifier */
	atomic_t			f_released;	/* number of objects released lately */
	atomic_long_t			b_released;	/* number of blocks released lately */
	unsigned			frun_percent;	/* when to stop culling (% files) */
	unsigned			fcull_percent;	/* when to start culling (% files) */
	unsigned			fstop_percent;	/* when to stop allocating (% files) */
	unsigned			brun_percent;	/* when to stop culling (% blocks) */
	unsigned			bcull_percent;	/* when to start culling (% blocks) */
	unsigned			bstop_percent;	/* when to stop allocating (% blocks) */
	unsigned			bsize;		/* cache's block size */
	unsigned			bshift;		/* min(ilog2(PAGE_SIZE / bsize), 0) */
	uint64_t			frun;		/* when to stop culling */
	uint64_t			fcull;		/* when to start culling */
	uint64_t			fstop;		/* when to stop allocating */
	sector_t			brun;		/* when to stop culling */
	sector_t			bcull;		/* when to start culling */
	sector_t			bstop;		/* when to stop allocating */
	unsigned long			flags;
#define CACHEFILES_READY		0	/* T if cache prepared */
#define CACHEFILES_DEAD			1	/* T if cache dead */
#define CACHEFILES_CULLING		2	/* T if cull engaged */
#define CACHEFILES_STATE_CHANGED	3	/* T if state changed (poll trigger) */
	char				*rootdirname;	/* name of cache root directory */
	char				*secctx;	/* LSM security context */
	char				*tag;		/* cache binding tag */
};

#include <trace/events/cachefiles.h>

static inline
struct cachefiles_object *cachefiles_cres_object(struct netfs_cache_resources *cres)
{
	return container_of(fscache_cres_object(cres),
			    struct cachefiles_object, fscache);

}

/*
 * note change of state for daemon
 */
static inline void cachefiles_state_changed(struct cachefiles_cache *cache)
{
	set_bit(CACHEFILES_STATE_CHANGED, &cache->flags);
	wake_up_all(&cache->daemon_pollwq);
}

/*
 * bind.c
 */
extern int cachefiles_daemon_bind(struct cachefiles_cache *cache, char *args);
extern void cachefiles_daemon_unbind(struct cachefiles_cache *cache);

/*
 * content-map.c
 */
extern void cachefiles_expand_readahead(struct netfs_cache_resources *cres,
					loff_t *_start, size_t *_len, loff_t i_size);
extern enum netfs_read_source cachefiles_prepare_read(struct netfs_read_subrequest *subreq,
						      loff_t i_size);
extern u8 *cachefiles_new_content_map(struct cachefiles_object *object,
				      unsigned int *_size);
extern void cachefiles_mark_content_map(struct cachefiles_object *object,
					loff_t start, loff_t len, unsigned int inval_counter);
extern void cachefiles_expand_content_map(struct cachefiles_object *object, loff_t size);
extern void cachefiles_shorten_content_map(struct cachefiles_object *object, loff_t new_size);
extern int cachefiles_prepare_write(struct netfs_cache_resources *cres,
				    loff_t *_start, size_t *_len, loff_t i_size);
extern bool cachefiles_load_content_map(struct cachefiles_object *object);
extern void cachefiles_save_content_map(struct cachefiles_object *object);
extern int cachefiles_display_object(struct seq_file *m, struct fscache_object *object);

/*
 * daemon.c
 */
extern const struct file_operations cachefiles_daemon_fops;

extern int cachefiles_has_space(struct cachefiles_cache *cache,
				unsigned fnr, unsigned bnr);

/*
 * interface.c
 */
extern const struct fscache_cache_ops cachefiles_cache_ops;
extern struct fscache_object *cachefiles_grab_object(struct fscache_object *_object,
						     enum fscache_obj_ref_trace why);
extern void cachefiles_put_object(struct fscache_object *_object,
				  enum fscache_obj_ref_trace why);

void cachefiles_put_object(struct fscache_object *_object,
			   enum fscache_obj_ref_trace why);

/*
 * io.c
 */
extern bool cachefiles_open_object(struct cachefiles_object *obj);

/*
 * key.c
 */
extern char *cachefiles_cook_key(const u8 *raw, int keylen, uint8_t type);

/*
 * namei.c
 */
extern void cachefiles_unmark_inode_in_use(struct cachefiles_object *object,
				    struct dentry *dentry);
extern int cachefiles_delete_object(struct cachefiles_cache *cache,
				    struct cachefiles_object *object);
extern bool cachefiles_walk_to_object(struct cachefiles_object *parent,
				      struct cachefiles_object *object,
				      const char *key);
extern struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					       struct dentry *dir,
					       const char *name);

extern int cachefiles_cull(struct cachefiles_cache *cache, struct dentry *dir,
			   char *filename);

extern int cachefiles_check_in_use(struct cachefiles_cache *cache,
				   struct dentry *dir, char *filename);

extern bool cachefiles_commit_tmpfile(struct cachefiles_cache *cache,
				      struct cachefiles_object *object);

/*
 * proc.c
 */
extern atomic_t cachefiles_lookup_histogram[HZ];
extern atomic_t cachefiles_mkdir_histogram[HZ];
extern atomic_t cachefiles_create_histogram[HZ];

#ifdef CONFIG_CACHEFILES_HISTOGRAM
extern int __init cachefiles_proc_init(void);
extern void cachefiles_proc_cleanup(void);
static inline
void cachefiles_hist(atomic_t histogram[], unsigned long start_jif)
{
	unsigned long jif = jiffies - start_jif;
	if (jif >= HZ)
		jif = HZ - 1;
	atomic_inc(&histogram[jif]);
}

#else
#define cachefiles_proc_init()		(0)
#define cachefiles_proc_cleanup()	do {} while (0)
static inline
void cachefiles_hist(atomic_t histogram[], unsigned long start_jif)
{
}
#endif

/*
 * rdwr2.c
 */
extern int cachefiles_begin_operation(struct netfs_cache_resources *);

/*
 * security.c
 */
extern int cachefiles_get_security_ID(struct cachefiles_cache *cache);
extern int cachefiles_determine_cache_security(struct cachefiles_cache *cache,
					       struct dentry *root,
					       const struct cred **_saved_cred);

static inline void cachefiles_begin_secure(struct cachefiles_cache *cache,
					   const struct cred **_saved_cred)
{
	*_saved_cred = override_creds(cache->cache_cred);
}

static inline void cachefiles_end_secure(struct cachefiles_cache *cache,
					 const struct cred *saved_cred)
{
	revert_creds(saved_cred);
}

/*
 * xattr.c
 */
extern int cachefiles_check_object_type(struct cachefiles_object *object);
extern int cachefiles_set_object_xattr(struct cachefiles_object *object);
extern int cachefiles_check_auxdata(struct cachefiles_object *object);
extern int cachefiles_remove_object_xattr(struct cachefiles_cache *cache,
					  struct dentry *dentry);
extern int cachefiles_prepare_to_write(struct fscache_object *object);

/*
 * error handling
 */

#define cachefiles_io_error(___cache, FMT, ...)		\
do {							\
	pr_err("I/O Error: " FMT"\n", ##__VA_ARGS__);	\
	fscache_io_error(&(___cache)->cache);		\
	set_bit(CACHEFILES_DEAD, &(___cache)->flags);	\
} while (0)

#define cachefiles_io_error_obj(object, FMT, ...)			\
do {									\
	struct cachefiles_cache *___cache;				\
									\
	___cache = container_of((object)->fscache.cache,		\
				struct cachefiles_cache, cache);	\
	cachefiles_io_error(___cache, FMT " [o=%08x]", ##__VA_ARGS__,	\
			    object->fscache.debug_id);			\
} while (0)


/*
 * debug tracing
 */
#define dbgprintk(FMT, ...) \
	printk(KERN_DEBUG "[%-6.6s] "FMT"\n", current->comm, ##__VA_ARGS__)

#define kenter(FMT, ...) dbgprintk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) dbgprintk("<== %s()"FMT"", __func__, ##__VA_ARGS__)
#define kdebug(FMT, ...) dbgprintk(FMT, ##__VA_ARGS__)


#if defined(__KDEBUG)
#define _enter(FMT, ...) kenter(FMT, ##__VA_ARGS__)
#define _leave(FMT, ...) kleave(FMT, ##__VA_ARGS__)
#define _debug(FMT, ...) kdebug(FMT, ##__VA_ARGS__)

#elif defined(CONFIG_CACHEFILES_DEBUG)
#define _enter(FMT, ...)				\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KENTER)	\
		kenter(FMT, ##__VA_ARGS__);		\
} while (0)

#define _leave(FMT, ...)				\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KLEAVE)	\
		kleave(FMT, ##__VA_ARGS__);		\
} while (0)

#define _debug(FMT, ...)				\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KDEBUG)	\
		kdebug(FMT, ##__VA_ARGS__);		\
} while (0)

#else
#define _enter(FMT, ...) no_printk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define _leave(FMT, ...) no_printk("<== %s()"FMT"", __func__, ##__VA_ARGS__)
#define _debug(FMT, ...) no_printk(FMT, ##__VA_ARGS__)
#endif

#if 1 /* defined(__KDEBUGALL) */

#define ASSERT(X)							\
do {									\
	if (unlikely(!(X))) {						\
		pr_err("\n");						\
		pr_err("Assertion failed\n");		\
		BUG();							\
	}								\
} while (0)

#define ASSERTCMP(X, OP, Y)						\
do {									\
	if (unlikely(!((X) OP (Y)))) {					\
		pr_err("\n");						\
		pr_err("Assertion failed\n");		\
		pr_err("%lx " #OP " %lx is false\n",			\
		       (unsigned long)(X), (unsigned long)(Y));		\
		BUG();							\
	}								\
} while (0)

#define ASSERTIF(C, X)							\
do {									\
	if (unlikely((C) && !(X))) {					\
		pr_err("\n");						\
		pr_err("Assertion failed\n");		\
		BUG();							\
	}								\
} while (0)

#define ASSERTIFCMP(C, X, OP, Y)					\
do {									\
	if (unlikely((C) && !((X) OP (Y)))) {				\
		pr_err("\n");						\
		pr_err("Assertion failed\n");		\
		pr_err("%lx " #OP " %lx is false\n",			\
		       (unsigned long)(X), (unsigned long)(Y));		\
		BUG();							\
	}								\
} while (0)

#else

#define ASSERT(X)			do {} while (0)
#define ASSERTCMP(X, OP, Y)		do {} while (0)
#define ASSERTIF(C, X)			do {} while (0)
#define ASSERTIFCMP(C, X, OP, Y)	do {} while (0)

#endif
