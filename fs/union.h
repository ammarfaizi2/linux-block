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

#ifdef CONFIG_UNION_MOUNT

#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/path.h>
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

static inline bool IS_MNT_UNION(struct vfsmount *mnt)
{
	return mnt->mnt_flags & MNT_UNION;
}

static inline bool IS_MNT_LOWER(struct vfsmount *mnt)
{
	return mnt->mnt_flags & MNT_UNION_LOWER;
}

static inline bool IS_DIR_UNIONED(struct dentry *dentry)
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


extern int union_create_topmost_dir(struct path *, struct qstr *, struct path *,
				    struct path *);

/*
 * Determine whether we need to perform unionmount traversal or the copyup of a
 * dentry.
 */
static inline
bool needs_lookup_union(struct nameidata *nd,
			struct path *parent_path, struct path *path)
{
	if (!IS_DIR_UNIONED(parent_path->dentry))
		return false;

	/* Either already built or crossed a mountpoint to not-unioned mnt */
	/* XXX are bind mounts root? think not */
	if (IS_ROOT(path->dentry))
		return false;

	/* If this is a fallthru dentry and the caller requires the underlying
	 * inode to be copied up, then do so.
	 */
	if (nd->flags & LOOKUP_COPY_UP && d_is_fallthru(path->dentry))
		return true;

	/* It's okay not to have the lock; will recheck in lookup_union() */
	/* XXX set for root dentry at mount? */
	return !(path->dentry->d_flags & DCACHE_UNION_LOOKUP_DONE);
}

#else /* CONFIG_UNION_MOUNT */

static inline bool IS_MNT_UNION(struct vfsmount *mnt) { return false; }
static inline bool IS_MNT_LOWER(struct vfsmount *mnt) { return false; }
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

static inline int union_create_topmost_dir(struct path *parent, struct qstr *name,
					   struct path *topmost, struct path *lower)
{
	BUG();
	return 0;
}

static inline bool needs_lookup_union(struct nameidata *nd,
				      struct path *parent_path, struct path *path)
{
	return false;
}

#endif	/* CONFIG_UNION_MOUNT */
