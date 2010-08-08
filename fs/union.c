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

#include <linux/bootmem.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/security.h>

#include "union.h"

/**
 * union_alloc - allocate a union stack
 *
 * @path: path of topmost directory
 *
 * Allocate a union_stack large enough to contain the maximum number
 * of layers in this union mount.
 */

static struct union_stack *union_alloc(struct path *topmost)
{
	unsigned int layers = topmost->dentry->d_sb->s_union_count;
	BUG_ON(!S_ISDIR(topmost->dentry->d_inode->i_mode));

	return kzalloc(sizeof(struct path) * layers, GFP_KERNEL);
}

/**
 * d_free_unions - free all unions for this dentry
 *
 * @dentry - topmost dentry in the union stack to remove
 *
 * This must be called when freeing a dentry.
 */
void d_free_unions(struct dentry *topmost)
{
	struct path *path;
	unsigned int i, layers = topmost->d_sb->s_union_count;

	if (!IS_DIR_UNIONED(topmost))
		return;

	for (i = 0; i < layers; i++) {
		path = union_find_dir(topmost, i);
		if (path->mnt)
			path_put(path);
	}
	kfree(topmost->d_union_stack);
	topmost->d_union_stack = NULL;
}

/**
 * union_add_dir - Add another layer to a unioned directory
 *
 * @topmost - topmost directory
 * @lower - directory in the current layer
 * @layer - index of layer to add this at
 *
 * @layer counts starting at 0 for the dir below the topmost dir.
 * Must take a reference to @lower (call path_get()) before calling
 * this function.
 */

int union_add_dir(struct path *topmost, struct path *lower,
		  unsigned int layer)
{
	struct path *path;
	struct dentry *dentry = topmost->dentry;
	BUG_ON(layer >= dentry->d_sb->s_union_count);

	if (!dentry->d_union_stack)
		dentry->d_union_stack = union_alloc(topmost);
	if (!dentry->d_union_stack)
		return -ENOMEM;
	path = union_find_dir(dentry, layer);
	*path = *lower;
	return 0;
}

/**
 * union_create_topmost_dir - Create a matching dir in the topmost file system
 *
 * @parent - parent of target on topmost layer
 * @name - name of target
 * @topmost - path of target on topmost layer
 * @lower - path of source on lower layer
 *
 * As we lookup each directory on the lower layer of a union, we
 * create a matching directory on the topmost layer if it does not
 * already exist.
 *
 * We don't use vfs_mkdir() for a few reasons: don't want to do the
 * security check, don't want to make the dir opaque, don't need to
 * sanitize the mode.
 *
 * XXX - owner is wrong, set credentials properly
 * XXX - rmdir() directory on failure of xattr copyup
 * XXX - not atomic w/ respect to crash
 */

int union_create_topmost_dir(struct path *parent, struct qstr *name,
			     struct path *topmost, struct path *lower)
{
	struct inode *dir = parent->dentry->d_inode;
	int mode = lower->dentry->d_inode->i_mode;
	int error;

	BUG_ON(topmost->dentry->d_inode);

	/* XXX - Do we even need to check this? */
	if (!dir->i_op->mkdir)
		return -EPERM;

	error = mnt_want_write(parent->mnt);
	if (error)
		return error;

	error = dir->i_op->mkdir(dir, topmost->dentry, mode);
	if (error)
		goto out;

	error = union_copyup_xattr(lower->dentry, topmost->dentry);
	if (error)
		dput(topmost->dentry);

	fsnotify_mkdir(dir, topmost->dentry);
out:
	mnt_drop_write(parent->mnt);

	return error;
}

struct union_filldir_info {
	struct dentry *topmost_dentry;
	int error;
};

/**
 * union_copyup_dir_one - copy up a single directory entry
 *
 * Individual directory entry copyup function for union_copyup_dir.
 * We get the entries from higher level layers first.
 */

static int union_copyup_dir_one(void *buf, const char *name, int namlen,
				loff_t offset, u64 ino, unsigned int d_type)
{
	struct union_filldir_info *ufi = (struct union_filldir_info *) buf;
	struct dentry *topmost_dentry = ufi->topmost_dentry;
	struct dentry *dentry;
	int err = 0;

	switch (namlen) {
	case 2:
		if (name[1] != '.')
			break;
	case 1:
		if (name[0] != '.')
			break;
		return 0;
	}

	/* Lookup this entry in the topmost directory */
	dentry = lookup_one_len(name, topmost_dentry, namlen);

	if (IS_ERR(dentry)) {
		printk(KERN_WARNING "%s: error looking up %s\n", __func__,
		       dentry->d_name.name);
		err = PTR_ERR(dentry);
		goto out;
	}

	/* XXX do we need to revalidate on readdir anyway? think NFS */
	if (dentry->d_op && dentry->d_op->d_revalidate)
		goto fallthru;
	/*
	 * If the entry already exists, one of the following is true:
	 * it was already copied up (due to an earlier lookup), an
	 * entry with the same name already exists on the topmost file
	 * system, it is a whiteout, or it is a fallthru.  In each
	 * case, the top level entry masks any entries from lower file
	 * systems, so don't copy up this entry.
	 */
	if (dentry->d_inode || d_is_whiteout(dentry) || d_is_fallthru(dentry))
		goto out_dput;

	/*
	 * If the entry doesn't exist, create a fallthru entry in the
	 * topmost file system.  All possible directory types are
	 * used, so each file system must implement its own way of
	 * storing a fallthru entry.
	 */
fallthru:
	err = topmost_dentry->d_inode->i_op->fallthru(topmost_dentry->d_inode,
						      dentry);

	/* It's okay if it exists, ultimate responsibility rests with ->fallthru() */
	if (err == -EEXIST)
		err = 0;
out_dput:
	dput(dentry);
out:
	if (err)
		ufi->error = err;
	return err;
}

/**
 * union_copyup_dir - copy up low-level directory entries to topmost dir
 *
 * readdir() is difficult to support on union file systems for two
 * reasons: We must eliminate duplicates and apply whiteouts, and we
 * must return something in f_pos that lets us restart in the same
 * place when we return.  Our solution is to, on first readdir() of
 * the directory, copy up all visible entries from the low-level file
 * systems and mark the entries that refer to low-level file system
 * objects as "fallthru" entries.
 *
 * Locking strategy: We hold the topmost dir's i_mutex on entry.  We
 * grab the i_mutex on lower directories one by one.  So the locking
 * order is:
 *
 * Writable/topmost layers > Read-only/lower layers
 *
 * So there is no problem with lock ordering for union stacks with
 * multiple lower layers.  E.g.:
 *
 * (topmost) A->B->C (bottom)
 * (topmost) D->C->B (bottom)
 *
 */

int union_copyup_dir(struct path *topmost_path)
{
	struct union_filldir_info ufi;
	struct dentry *topmost_dentry = topmost_path->dentry;
	unsigned int i, layers = topmost_dentry->d_sb->s_union_count;
	int error = 0;

	BUG_ON(IS_OPAQUE(topmost_dentry->d_inode));

	if (!topmost_dentry->d_inode->i_op || !topmost_dentry->d_inode->i_op->fallthru)
		return -EOPNOTSUPP;

	error = mnt_want_write(topmost_path->mnt);
	if (error)
		return error;

	for (i = 0; i < layers; i++) {
		struct file * ftmp;
		struct inode * inode;
		struct path *path;

		path = union_find_dir(topmost_dentry, i);
		if (!path->mnt)
			continue;
		/* dentry_open() doesn't get a path reference itself */
		path_get(path);
		ftmp = dentry_open(path->dentry, path->mnt,
				   O_RDONLY | O_DIRECTORY | O_NOATIME,
				   current_cred());
		if (IS_ERR(ftmp)) {
			printk (KERN_ERR "unable to open dir %s for "
				"directory copyup: %ld\n",
				path->dentry->d_name.name, PTR_ERR(ftmp));
			path_put(path);
			error = PTR_ERR(ftmp);
			break;
		}

		inode = path->dentry->d_inode;
		mutex_lock(&inode->i_mutex);

		error = -ENOENT;
		if (IS_DEADDIR(inode))
			goto out_fput;
		/*
		 * Read the whole directory, calling our directory
		 * entry copyup function on each entry.
		 */
		ufi.topmost_dentry = topmost_dentry;
		ufi.error = 0;
		error = ftmp->f_op->readdir(ftmp, &ufi, union_copyup_dir_one);
out_fput:
		mutex_unlock(&inode->i_mutex);
		fput(ftmp);

		if (ufi.error)
			error = ufi.error;
		if (error)
			break;

		/* XXX Should process directories below an opaque
		 * directory in case there are fallthrus in it */
		if (IS_OPAQUE(path->dentry->d_inode))
			break;
	}
	/*
	 * Mark this dir opaque to show that we have already copied up
	 * the lower entries.  Be sure to do this AFTER the directory
	 * entries have been copied up so that if we crash in the
	 * middle of copyup, we will try to copyup the dir next time
	 * we read it.
	 *
	 * XXX - Could leave directory non-opaque, and force
	 * reread/copyup of directory each time it is read in from
	 * disk.  That would make it easy to update lower file systems
	 * (when not union mounted) and have the changes show up when
	 * union mounted again.
	 */
	if (!error) {
		topmost_dentry->d_inode->i_flags |= S_OPAQUE;
		mark_inode_dirty(topmost_dentry->d_inode);
	}

	mnt_drop_write(topmost_path->mnt);
	return error;
}

/* Relationship between i_mode and the DT_xxx types */
static inline unsigned char dt_type(struct inode *inode)
{
	return (inode->i_mode >> 12) & 15;
}

/**
 * generic_readdir_fallthru - Helper to lookup target of a fallthru
 *
 * @topmost_dentry: dentry for the topmost dentry of the dir being read
 * @name: name of fallthru dirent
 * @namelen: length of @name
 * @ino: return inode number of target, if found
 * @d_type: return directory type of target, if found
 *
 * In readdir(), client file systems need to lookup the target of a
 * fallthru in a lower layer for three reasons: (1) fill in d_ino, (2)
 * fill in d_type, (2) make sure there is something to fall through to
 * (and if not, don't return this dentry).  Upon detecting a fallthru
 * dentry in readdir(), the client file system should call this function.
 *
 * Returns 0 on success and -ENOENT if no matching directory entry was
 * found (which can happen when the topmost file system is unmounted
 * and remounted over a different file system than).  Any other errors
 * are unexpected.
 */

int
generic_readdir_fallthru(struct dentry *topmost_dentry, const char *name,
			 int namlen, ino_t *ino, unsigned char *d_type)
{
	struct path *parent;
	struct dentry *dentry;
	unsigned int i, layers = topmost_dentry->d_sb->s_union_count;

	BUG_ON(!mutex_is_locked(&topmost_dentry->d_inode->i_mutex));

	for (i = 0; i < layers; i++) {
		parent = union_find_dir(topmost_dentry, i);
		mutex_lock(&parent->dentry->d_inode->i_mutex);
		dentry = lookup_one_len(name, parent->dentry, namlen);
		mutex_unlock(&parent->dentry->d_inode->i_mutex);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
		if (dentry->d_inode) {
			*ino = dentry->d_inode->i_ino;
			*d_type = dt_type(dentry->d_inode);
			dput(dentry);
			return 0;
		}
		dput(dentry);
	}
	return -ENOENT;
}
