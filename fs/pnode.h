/*
 *  linux/fs/pnode.h
 *
 * (C) Copyright IBM Corporation 2005.
 *	Released under GPL v2.
 *
 */
#ifndef _LINUX_PNODE_H
#define _LINUX_PNODE_H

#include <linux/list.h>
#include "mount.h"

#define IS_MNT_SHARED(m) ((m)->mnt.mnt_flags & MNT_SHARED)
#define IS_MNT_SLAVE(m) ((m)->mnt_master)
#define IS_MNT_NEW(m)  (!(m)->mnt_ns)
#define CLEAR_MNT_SHARED(m) ((m)->mnt.mnt_flags &= ~MNT_SHARED)
#define IS_MNT_UNBINDABLE(m) ((m)->mnt.mnt_flags & MNT_UNBINDABLE)

#define CL_EXPIRE    		0x0001
#define CL_SLAVE     		0x0002
#define CL_COPY_UNBINDABLE	0x0004
#define CL_MAKE_SHARED 		0x0008
#define CL_PRIVATE 		0x0010
#define CL_SHARED_TO_SLAVE	0x0020
#define CL_UNPRIVILEGED		0x0040
#define CL_COPY_MNT_NS_FILE	0x0080
#define CL_NO_SHARED 		0x0100
#define CL_NO_SLAVE 		0x0200
#define CL_MAKE_HARD_READONLY	0x0400

#define CL_COPY_ALL		(CL_COPY_UNBINDABLE | CL_COPY_MNT_NS_FILE)

static inline void set_mnt_shared(struct mount *mnt)
{
	mnt->mnt.mnt_flags &= ~MNT_SHARED_MASK;
	mnt->mnt.mnt_flags |= MNT_SHARED;
}

void change_mnt_propagation(struct mount *, int);
int propagate_mnt(struct mount *, struct mountpoint *, struct mount *,
		struct list_head *);
int propagate_umount(struct list_head *);
int propagate_mount_busy(struct mount *, int);
void mnt_release_group_id(struct mount *);
int get_dominating_id(struct mount *mnt, const struct path *root);
unsigned int mnt_get_count(struct mount *mnt);
void mnt_set_mountpoint(struct mount *, struct mountpoint *,
			struct mount *);
void umount_tree(struct mount *, int);
struct mount *copy_tree(struct mount *, struct dentry *, int);
bool is_path_reachable(struct mount *, struct dentry *,
			 const struct path *root);
#endif /* _LINUX_PNODE_H */
