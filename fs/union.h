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

static inline struct path *union_find_dir(struct dentry *dentry,
					  unsigned int layer) {
	BUG_ON(layer >= dentry->d_sb->s_union_count);
	return &(dentry->d_union_stack->u_dirs[layer]);
}

#else /* CONFIG_UNION_MOUNT */

#define union_find_dir(x, y)		({ BUG(); (NULL); })

#endif	/* CONFIG_UNION_MOUNT */
#endif	/* __KERNEL__ */
#endif	/* __LINUX_UNION_H */
