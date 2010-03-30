 /*
 * VFS-based union mounts for Linux
 *
 * Copyright (C) 2004-2007 IBM Corporation, IBM Deutschland Entwicklung GmbH.
 * Copyright (C) 2007-2009 Novell Inc.
 * Copyright (C) 2009-2010 Red Hat, Inc.
 *
 *   Author(s): Jan Blunck (j.blunck@tu-harburg.de)
 *              Valerie Aurora <vaurora@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */
#ifndef __LINUX_UNION_H
#define __LINUX_UNION_H
#ifdef __KERNEL__

#ifdef CONFIG_UNION_MOUNT

/*
 * WARNING! Confusing terminology alert.
 *
 * Note that the directions "up" and "down" in union mounts are the
 * opposite of "up" and "down" in normal VFS operation terminology.
 * "up" in the rest of the VFS means "towards the root of the mount
 * tree."  If you mount B on top of A, following B "up" will get you
 * A.  In union mounts, "up" means "towards the most recently mounted
 * layer of the union stack."  If you union mount B on top of A,
 * following A "up" will get you to B.  Another way to put it is that
 * "up" in the VFS means going from this mount towards the direction
 * of its mnt->mnt_parent pointer, but "up" in union mounts means
 * going in the opposite direction (until you run out of union
 * layers).
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

#define IS_MNT_UNION(mnt)	((mnt)->mnt_flags & MNT_UNION)
#define IS_DIR_UNIONED(dentry)	((dentry)->d_union_stack)

extern void d_free_unions(struct dentry *);
extern int union_add_dir(struct path *, struct path *, unsigned int);
extern int union_create_topmost_dir(struct path *, struct qstr *, struct path *,
				    struct path *);
extern int union_copyup_dir(struct path *);
extern int generic_readdir_fallthru(struct dentry *topmost_dentry, const char *name,
				    int namlen, ino_t *ino, unsigned char *d_type);
extern int union_copyup(struct nameidata *, struct path *);
extern int __union_copyup(struct nameidata *, struct path *);
extern int union_copyup_len(struct nameidata *, struct path *, size_t len);

static inline int needs_lookup_union(struct path *parent_path, struct path *path)
{
	if (!IS_DIR_UNIONED(parent_path->dentry))
		return 0;

	/* Either already built or crossed a mountpoint to not-unioned mnt */
	/* XXX are bind mounts root? think not */
	if (IS_ROOT(path->dentry))
		return 0;

	/* It's okay not to have the lock; will recheck in lookup_union() */
	/* XXX set for root dentry at mount? */
	return !(path->dentry->d_flags & DCACHE_UNION_LOOKUP_DONE);
}

static inline struct path *union_find_dir(struct dentry *dentry,
					  unsigned int layer) {
	BUG_ON(layer >= dentry->d_sb->s_union_count);
	return &(dentry->d_union_stack->u_dirs[layer]);
}

#else /* CONFIG_UNION_MOUNT */

#define IS_MNT_UNION(x)			(0)
#define IS_DIR_UNIONED(x)		(0)

#define d_free_unions(x)		do { } while (0)
#define union_add_dir(x, y, z)		({ BUG(); (0); })
#define union_find_dir(x, y)		({ BUG(); (NULL); })
#define union_create_topmost_dir(w, x, y, z)	({ BUG(); (0); })
#define needs_lookup_union(x, y)	({ (0); })
#define union_copyup_dir(x)		({ BUG(); (0); })
#define generic_readdir_fallthru(w, x, y, z)	({ BUG(); (0); })
#define union_copyup(x, y)		({ BUG(); (0); })
#define __union_copyup(x, y)		({ BUG(); (0); })
#define union_copyup_len(x, y, z)	({ BUG(); (0); })

#endif	/* CONFIG_UNION_MOUNT */
#endif	/* __KERNEL__ */
#endif	/* __LINUX_UNION_H */
