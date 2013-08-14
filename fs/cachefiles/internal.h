/* General netfs cache on cache files internal defs
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "CacheFiles: " fmt


#include <linux/fscache-cache.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/security.h>

/*
 * The cachefiles disk format employed:
 *
 * 1: Directory tree mirroring cookie tree.
 */
#define cachefiles_disk_format 1

struct cachefiles_cache;
struct cachefiles_object;

extern unsigned cachefiles_debug;
#define CACHEFILES_DEBUG_KENTER	1
#define CACHEFILES_DEBUG_KLEAVE	2
#define CACHEFILES_DEBUG_KDEBUG	4

#define cachefiles_gfp (__GFP_WAIT | __GFP_NORETRY | __GFP_NOMEMALLOC)

/*
 * node records
 */
struct cachefiles_object {
	struct fscache_object		fscache;	/* fscache handle */
	struct cachefiles_lookup_data	*lookup_data;	/* cached lookup data */
	struct dentry			*dentry;	/* the file/dir representing this object */
	struct dentry			*backer;	/* backing file */
	loff_t				i_size;		/* object size */
	unsigned long			flags;
#define CACHEFILES_OBJECT_ACTIVE	0		/* T if marked active */
#define CACHEFILES_OBJECT_NEW		1		/* T if object is new */
#define CACHEFILES_OBJECT_UPDATE_XATTR	2		/* T if xattr should be updated */
	atomic_t			usage;		/* object usage count */
	uint8_t				type;		/* object type */
	unsigned			cull_slot;	/* slot in cull index */
	spinlock_t			work_lock;
	struct rb_node			active_node;	/* link in active tree (dentry is key) */
};

extern struct kmem_cache *cachefiles_object_jar;

/*
 * Cache files cache definition
 */
struct cachefiles_cache {
	struct fscache_cache		cache;		/* FS-Cache record */
	struct dentry                   *root;
	struct vfsmount			*mnt;		/* mountpoint holding the cache */
	struct dentry			*graveyard;	/* directory into which dead objects go */
	struct file			*cull_index;	/* file containing cull FH index */
	struct file			*cull_atimes;	/* file containing cull atime array */
	struct file			*cachefilesd;	/* manager daemon handle */
	const struct cred		*cache_cred;	/* security override for accessing cache */
	struct rw_semaphore		cull_file_sem;	/* access to cull index files */
	struct mutex			daemon_mutex;	/* command serialisation mutex */
	wait_queue_head_t		daemon_pollwq;	/* poll waitqueue for daemon */
	struct rb_root			cull_bitmap;	/* culling index free space bitmap */
	struct rb_root			active_nodes;	/* active nodes (can't be culled) */
	rwlock_t			active_lock;	/* lock for active_nodes */
	spinlock_t			cull_bitmap_lock; /* access lock for cull_bitmap */
	struct mutex			xattr_mutex;	/* access mutex for xattrs */
	atomic_t			gravecounter;	/* graveyard uniquifier */
	unsigned short			cx_entsize;	/* size of culling index entry */
	unsigned short			cx_nperpage;	/* number of elements per page */
	unsigned			frun_percent;	/* when to stop culling (% files) */
	unsigned			fcull_percent;	/* when to start culling (% files) */
	unsigned			fstop_percent;	/* when to stop allocating (% files) */
	unsigned			brun_percent;	/* when to stop culling (% blocks) */
	unsigned			bcull_percent;	/* when to start culling (% blocks) */
	unsigned			bstop_percent;	/* when to stop allocating (% blocks) */
	unsigned			bsize;		/* cache's block size */
	unsigned			bshift;		/* min(ilog2(PAGE_SIZE / bsize), 0) */
	time_t				atime_base;	/* atime base for culling */
	uint64_t			frun;		/* when to stop culling */
	uint64_t			fcull;		/* when to start culling */
	uint64_t			fstop;		/* when to stop allocating */
	sector_t			brun;		/* when to stop culling */
	sector_t			bcull;		/* when to start culling */
	sector_t			bstop;		/* when to stop allocating */
	unsigned long			cull_nslots;	/* # of culling slots allocated on disk */
	unsigned long			flags;
#define CACHEFILES_READY		0	/* T if cache prepared */
#define CACHEFILES_DEAD			1	/* T if cache dead */
#define CACHEFILES_CULLING		2	/* T if cull engaged */
#define CACHEFILES_STATE_CHANGED	3	/* T if state changed (poll trigger) */
#define CACHEFILES_NEED_FSCK		4	/* T if index inconsistency found */
	char				*rootdirname;	/* name of cache root directory */
	char				*secctx;	/* LSM security context */
	char				*tag;		/* cache binding tag */
};

/*
 * backing file read tracking
 */
struct cachefiles_one_read {
	wait_queue_t			monitor;	/* link into monitored waitqueue */
	struct page			*back_page;	/* backing file page we're waiting for */
	struct page			*netfs_page;	/* netfs page we're going to fill */
	struct fscache_retrieval	*op;		/* retrieval op covering this */
	struct list_head		op_link;	/* link in op's todo list */
};

/*
 * backing file write tracking
 */
struct cachefiles_one_write {
	struct page			*netfs_page;	/* netfs page to copy */
	struct cachefiles_object	*object;
	struct list_head		obj_link;	/* link in object's lists */
	fscache_rw_complete_t		end_io_func;
	void				*context;
};

/*
 * auxiliary data xattr buffer
 */
struct cachefiles_xattr {
	unsigned			len;
	/* everything after here will be written as the xattr data */
	__le32				cull_slot;	/* assigned culling index slot */
#define CACHEFILES_NO_CULL_SLOT		UINT_MAX
#define CACHEFILES_PINNED		(UINT_MAX - 1)
	uint8_t				type;
	uint8_t				data[];
};

/*
 * culling index free slots bitmap and cullable slots bitmap block
 */
struct cachefiles_cx_bitmap {
	struct rb_node			rb;		/* link in bitmap tree */
	unsigned			offset;		/* offset of bitmap in rb */
	unsigned			nfreeslots;	/* # of free slots in this block */
	unsigned			nslots;		/* # of slots actually allocated on disk */
	struct page			*free_slots;	/* bits indicating free slots */
	struct page			*cullable_slots; /* bits indicating cullable slots */
};

/*
 * culling index entry layout
 */
struct cachefiles_cx_entry {
	uint8_t				len;		/* fh len */
	uint8_t				type;		/* exportfs enum fid_type */
	__u32				fh[0];		/* exportfs file handle */
} __attribute__((packed));

/*
 * note change of state for daemon
 */
static inline void cachefiles_state_changed(struct cachefiles_cache *cache)
{
	set_bit(CACHEFILES_STATE_CHANGED, &cache->flags);
	wake_up_all(&cache->daemon_pollwq);
}

static inline void cachefiles_mark_dirty(struct cachefiles_cache *cache)
{
	set_bit(CACHEFILES_NEED_FSCK, &cache->flags);
	set_bit(CACHEFILES_STATE_CHANGED, &cache->flags);
}

static inline void cachefiles_mark_clean(struct cachefiles_cache *cache)
{
	clear_bit(CACHEFILES_NEED_FSCK, &cache->flags);
	set_bit(CACHEFILES_STATE_CHANGED, &cache->flags);
}

/*
 * bind.c
 */
extern int cachefiles_daemon_bind(struct cachefiles_cache *cache, char *args);
extern void cachefiles_daemon_unbind(struct cachefiles_cache *cache);

/*
 * cull_index.c
 */
extern void cachefiles_cx_free_bitmap(struct cachefiles_cache *cache);
extern void cachefiles_cx_mark_cullable(struct cachefiles_cache *cache,
					unsigned slot, bool cullable);
extern int cachefiles_cx_generate_bitmap(struct cachefiles_cache *cache);
extern void cachefiles_cx_unalloc_slot(struct cachefiles_cache *cache,
				       unsigned slot);
extern void cachefiles_cx_clear_slot(struct cachefiles_cache *cache,
				     unsigned slot);
extern int cachefiles_cx_get_slot(struct cachefiles_cache *cache,
				  struct cachefiles_object *object,
				  __le32 *_xattr_slot);
extern void cachefiles_cx_mark_access(struct cachefiles_cache *cache,
				      struct cachefiles_object *object);
extern int cachefiles_cx_lookup(struct cachefiles_cache *cache,
				unsigned slot,
				struct dentry **_dir,
				struct dentry **_object);
extern int cachefiles_cx_validate_slot(struct cachefiles_cache *cache,
				       struct dentry *dentry,
				       unsigned slot);
extern int cachefiles_cx_fixslot(struct cachefiles_cache *cache,
				 unsigned slot);

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

/*
 * key.c
 */
extern char *cachefiles_cook_key(const u8 *raw, int keylen, uint8_t type);

/*
 * namei.c
 */
extern int cachefiles_delete_object(struct cachefiles_cache *cache,
				    struct cachefiles_object *object);
extern int cachefiles_walk_to_object(struct cachefiles_object *parent,
				     struct cachefiles_object *object,
				     const char *key,
				     struct cachefiles_xattr *auxdata);
extern struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					       struct dentry *dir,
					       const char *name);
extern struct dentry *cachefiles_lookup_file(struct dentry *dir,
					     const char *filename);
extern struct file *cachefiles_get_file(struct cachefiles_cache *cache,
					struct dentry *dir,
					const char *filename,
					bool create);

extern int cachefiles_cull(struct cachefiles_cache *cache, struct dentry *dir,
			   char *filename);
extern int cachefiles_cullslot(struct cachefiles_cache *cache, unsigned slot);

extern int cachefiles_check_in_use(struct cachefiles_cache *cache,
				   struct dentry *dir, char *filename);

int cachefiles_check_dentry_active(struct cachefiles_cache *cache,
				   struct dentry *dir,
				   struct dentry *victim);

/*
 * proc.c
 */
#ifdef CONFIG_CACHEFILES_HISTOGRAM
extern atomic_t cachefiles_lookup_histogram[HZ];
extern atomic_t cachefiles_mkdir_histogram[HZ];
extern atomic_t cachefiles_create_histogram[HZ];

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
#define cachefiles_hist(hist, start_jif) do {} while (0)
#endif

/*
 * rdwr.c
 */
extern int cachefiles_read_or_alloc_page(struct fscache_retrieval *,
					 struct page *, gfp_t);
extern int cachefiles_read_or_alloc_pages(struct fscache_retrieval *,
					  struct list_head *, unsigned *,
					  gfp_t);
extern int cachefiles_allocate_page(struct fscache_retrieval *, struct page *,
				    gfp_t);
extern int cachefiles_allocate_pages(struct fscache_retrieval *,
				     struct list_head *, unsigned *, gfp_t);
extern int cachefiles_write_page(struct fscache_storage *, struct page *);
extern void cachefiles_uncache_page(struct fscache_object *, struct page *);

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
extern int cachefiles_check_root_object_type(struct cachefiles_object *object);
extern int cachefiles_set_object_xattr(struct cachefiles_object *object,
				       struct cachefiles_xattr *auxdata);
extern int cachefiles_update_object_xattr(struct cachefiles_object *object,
					  struct cachefiles_xattr *auxdata);
extern int cachefiles_check_auxdata(struct cachefiles_object *object);
extern int cachefiles_check_object_xattr(struct cachefiles_object *object,
					 struct cachefiles_xattr *auxdata);
extern unsigned cachefiles_read_cull_slot(struct cachefiles_cache *cache,
					  struct dentry *dentry);
extern int cachefiles_remove_object_xattr(struct cachefiles_cache *cache,
					  struct dentry *dentry);
extern int cachefiles_check_cull_index(struct cachefiles_cache *cache);
extern int cachefiles_get_set_atime_base(struct cachefiles_cache *cache);
extern int cachefiles_reset_slot(struct dentry *dentry, unsigned slot);


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
	cachefiles_io_error(___cache, FMT, ##__VA_ARGS__);		\
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
