/* VFS-based union mounts for Linux
 *
 * Copyright (C) 2004-2007 IBM Corporation, IBM Deutschland Entwicklung GmbH.
 * Copyright (C) 2007-2009 Novell Inc.
 * Copyright (C) 2009-2012 Red Hat, Inc.
 *
 *   Author(s): Jan Blunck (j.blunck@tu-harburg.de)
 *              Valerie Aurora <vaurora@redhat.com>
 *              David Howells <dhowells@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/bug.h>

/*
 * WARNING! Confusing terminology alert.
 *
 * Note that the directions "up" and "down" in union mounts are the opposite of
 * "up" and "down" in normal VFS operation terminology.  "Up" in the rest of
 * the VFS means "towards the root of the mount tree."  If you mount B on top
 * of A, following B "up" will get you A.  In union mounts, "up" means "towards
 * the most recently mounted layer of the union stack."  If you union mount B
 * on top of A, following A "up" will get you to B.  Another way to put it is
 * that "up" in the VFS means going from this mount towards the direction of
 * its mnt->mnt_parent pointer, but "up" in union mounts means going in the
 * opposite direction (until you run out of union layers).
 */

/*
 * The union_stack structure.  It is an array of struct paths of
 * directories below the topmost directory in a unioned directory, The
 * topmost dentry has a pointer to this structure.  The topmost dentry
 * can only be part of one union, so we can reference it from the
 * dentry, but lower dentries can be part of multiple union stacks.
 *
 * The number of dirs actually allocated is kept in the superblock,
 * s_union_count.
 */
struct union_stack {
	struct path u_dirs[0];
};

/**
 * union_alloc - allocate a union stack
 * @path: path of topmost directory
 *
 * Allocate a union_stack large enough to contain the maximum number
 * of layers in this union mount.
 */
static inline struct union_stack *union_alloc_stack(const struct path *topmost)
{
	unsigned layers = topmost->dentry->d_sb->s_union_count;
	return kcalloc(sizeof(struct path), layers, GFP_KERNEL);
}

#ifdef CONFIG_UNION_MOUNT

static inline bool IS_MNT_UNION(const struct vfsmount *mnt)
{
	return mnt->mnt_flags & MNT_UNION;
}

static inline bool IS_PATH_UNIONED(const struct path *path)
{
	return IS_MNT_UNION(path->mnt);
}

static inline bool IS_DIR_UNIONED(const struct dentry *dentry)
{
	return !!dentry->d_union_stack;
}

extern void d_free_unions(struct dentry *);
extern int union_add_dir(struct path *, struct path *, unsigned int);

static inline
struct path *union_find_dir(struct dentry *dentry, unsigned int layer)
{
	BUG_ON(layer >= dentry->d_sb->s_union_count);
	return &dentry->d_union_stack->u_dirs[layer];
}


extern int union_create_topmost_dir(struct path *, struct path *, struct union_stack *);

extern int __union_copy_up_dir(struct path *);

#else /* CONFIG_UNION_MOUNT */

static inline bool IS_MNT_UNION(struct vfsmount *mnt) { return false; }
static inline bool IS_PATH_UNIONED(const struct path *path) { return false; }
static inline bool IS_DIR_UNIONED(struct dentry *dentry) { return false; }
static inline void d_free_unions(struct dentry *dentry) {}

static inline
int union_add_dir(struct path *topmost, struct path *lower, unsigned layer)
{
	BUG();
	return 0;
}

static inline struct path *union_find_dir(struct dentry *dentry, unsigned layer)
{
	BUG();
	return NULL;
}

static inline int union_create_topmost_dir(struct path *parent,
					   struct path *topmost,
					   struct union_stack *d)
{
	BUG();
	return 0;
}

static inline int __union_copy_up_dir(struct path *topmost_path)
{
	BUG();
	return 0;
}

#endif	/* CONFIG_UNION_MOUNT */

/*
 * Make sure that an upper directory is opaque (ie. totally copied up if it is
 * in fact unioned with some lower dirs).
 */
static inline int union_copy_up_dir(struct path *path)
{
	if (IS_OPAQUE(path->dentry->d_inode))
		return 0;
	return __union_copy_up_dir(path);
}

extern struct inode *__union_get_inode_locked(struct dentry *parent,
					      struct path *upper,
					      struct path *_lower_cache,
					      struct path *_actual);
extern struct inode *__union_get_inode(struct path *upper,
				       struct path *_lower_cache,
				       struct path *_actual);
extern int __union_copy_up(struct path *path, struct path *actual,
			   const loff_t *truncate_to);

extern int __union_copy_up_locked(struct path *parent, struct path *path,
				  struct path *actual,
				  const loff_t *truncate_to);

static inline void path_put_maybe(struct path *path)
{
	/* These optimise away if CONFIG_UNION_MOUNT=n */
	if (unlikely(path->dentry))
		dput(path->dentry);
	if (unlikely(path->mnt))
		mntput(path->mnt);
}

/**
 * union_get_inode_locked - Get the actual inode and dentry for a dentry
 * @parent: The locked parent of the object we're interested in.
 * @path: The object we're interested in.
 * @_lower_cache: Cache for lower dentry pinning.
 * @_actual: The point actually corresponding to the returned inode.
 *
 * Gets the inode to be used for a dentry where that inode may exist on a lower
 * layer in a union.  Note that we don't get a ref on the inode, so to pin it
 * temporarily, we may point *_lower at the lower dentry.
 *
 * The caller must hold i_mutex on the parent.
 *
 * Returns a pointer to the inode to use if a positive dentry is found, NULL if
 * a negative dentry is found and an error if lookup in the lower layers
 * failed.
 *
 * On a successful return (positive or negative dentry), *_actual will be set
 * to point to the dentry that we determined was the one of interest.  This
 * does not hold any refs of its own.
 *
 * The caller should call path_put_maybe() on *_lower_cache to clear any pins
 * it may contain.
 */
static inline struct inode *union_get_inode_locked(struct dentry *parent,
						   struct path *path,
						   struct path *_lower_cache,
						   struct path *_actual)
{
	/* Optimise for the non-unionmount case. */
	_lower_cache->dentry = NULL;
	_lower_cache->mnt = NULL;
	*_actual = *path;

#ifndef CONFIG_UNION_MOUNT
	return path->dentry->d_inode;
#else
	/* The normal case is that the inode is right where we expect... */
	if (likely(path->dentry->d_inode))
		return path->dentry->d_inode;

	/* ... or the dentry is ordinarily negative. */
	if (likely(!path->dentry->d_sb->s_union_lower_mnts))
		return NULL;

	if (d_is_whiteout(path->dentry) ||
	    (!d_is_fallthru(path->dentry) && IS_OPAQUE(parent->d_inode)))
		return NULL;

	/* We have to lock the parent and do a lookup. */
	return __union_get_inode_locked(parent, path, _lower_cache, _actual);
#endif
}

/**
 * union_get_inode - Get the actual inode and dentry for an object
 * @path: The object we're interested in.
 * @_lower_cache: Cache for lower dentry pinning.
 * @_actual: The point actually corresponding to the returned inode.
 *
 * Gets the inode to be used for a dentry where that inode may exist on a lower
 * layer in a union.  Note that we don't get a ref on the inode, so to pin it
 * temporarily, we may return a dentry in *_lower.
 *
 * Returns a pointer to the inode to use if a positive dentry is found, NULL if
 * a negative dentry is found and an error if lookup in the lower layers
 * failed.
 *
 * On a successful return (positive or negative dentry), *_actual will be set
 * to point to the dentry that we determined was the one of interest.  This
 * does not have its own ref taken and thus does not need to be dput().
 */
static inline struct inode *union_get_inode(struct path *path,
					    struct path *_lower_cache,
					    struct path *_actual)
{
	_lower_cache->mnt = NULL;
	_lower_cache->dentry = NULL;
	*_actual = *path;

#ifndef CONFIG_UNION_MOUNT
	return path->dentry->d_inode;
#else
	/* The normal case is that the inode is right where we expect... */
	if (likely(path->dentry->d_inode))
		return path->dentry->d_inode;

	/* ... or the dentry is ordinarily negative. */
	if (likely(!path->dentry->d_sb->s_union_lower_mnts))
		return NULL;

	if (d_is_whiteout(path->dentry))
		return NULL;

	/* We have to lock the parent and do a lookup. */
	return __union_get_inode(path, _lower_cache, _actual);
#endif
}

/**
 * union_truncated_copy_up - If needed, partially copy up a file (truncate)
 * path: The target object.
 * lower: The lower dentry (or NULL) from union_get_inode().
 * truncate_to: The amount to copy up.
 */
static inline int union_truncated_copy_up(struct path *path, struct path *actual,
					  const loff_t *truncate_to)
{
#ifdef CONFIG_UNION_MOUNT
	if (unlikely(!path->dentry->d_inode))
		return __union_copy_up(path, actual, truncate_to);
#endif
	return 0;
}

/**
 * union_copy_up - If needed, copy up a file in its entirety
 * path: The target object.
 * lower: The lower dentry (or NULL) from union_get_inode().
 */
static inline int union_copy_up(struct path *path, struct path *actual)
{
#ifdef CONFIG_UNION_MOUNT
	if (unlikely(!path->dentry->d_inode))
		return __union_copy_up(path, actual, NULL);
#endif
	return 0;
}

/**
 * union_copy_up_locked - If needed, copy up a file, caller holds parent lock
 * parent: The parent directory of the target object
 * path: The target object.
 * lower: The lower dentry (or NULL) from union_get_inode().
 *
 * The parent must hold i_mutex on the parent directory.
 */
static inline int union_copy_up_locked(struct path *parent, struct path *path,
				       struct path *actual)
{
#ifdef CONFIG_UNION_MOUNT
	if (unlikely(!path->dentry->d_inode))
	//	return __union_copy_up_locked(parent, path, actual, true, 0);
		return -ENOANO;
#endif
	return 0;
	
}

extern int __union_copy_up_for_do_last(struct path *, struct path *, bool);

/**
 * union_copy_up_do_last - If needed, copy up a file (maybe truncated)
 * path: The target object.
 * lower: The lower dentry (or NULL) from union_get_inode().
 * will_truncate: Whether to honour O_TRUNC or not.
 */
static inline int union_copy_up_for_do_last(struct path *parent, struct path *path,
					    bool will_truncate)
{
#ifdef CONFIG_UNION_MOUNT
	if (unlikely(!path->dentry->d_inode))
		return __union_copy_up_for_do_last(parent, path, will_truncate);
#endif
	return 0;
}

static inline bool d_is_unioned(const struct dentry *dentry, const struct path *actual)
{
#ifndef CONFIG_UNION_MOUNT
	return false;
#else
	return unlikely(dentry != actual->dentry);
#endif
}

static inline bool is_unioned(const struct dentry *dentry, const struct inode *inode)
{
#ifndef CONFIG_UNION_MOUNT
	return false;
#else
	return unlikely(dentry->d_inode != inode);
#endif
}

extern struct union_stack *union_alloc(const struct path *topmost);

static inline void union_free(const struct path *path, struct union_stack *d)
{
	unsigned i, layers = path->dentry->d_sb->s_union_count;

	if (d) {
		for (i = 0; i < layers; i++)
			path_put(&d->u_dirs[i]);
		kfree(d);
	}
}
