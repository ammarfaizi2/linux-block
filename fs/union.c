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
#include <linux/splice.h>
#include <linux/xattr.h>

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
 * union_copyup_xattr
 *
 * @old: dentry of original file
 * @new: dentry of new copy
 *
 * Copy up extended attributes from the original file to the new one.
 *
 * XXX - Permissions?  For now, copying up every xattr.
 */

static int union_copyup_xattr(struct dentry *old, struct dentry *new)
{
	ssize_t list_size, size;
	char *buf, *name, *value;
	int error;

	/* Check for xattr support */
	if (!old->d_inode->i_op->getxattr ||
	    !new->d_inode->i_op->getxattr)
		return 0;

	/* Find out how big the list of xattrs is */
	list_size = vfs_listxattr(old, NULL, 0);
	if (list_size <= 0)
		return list_size;

	/* Allocate memory for the list */
	buf = kzalloc(list_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Allocate memory for the xattr's value */
	error = -ENOMEM;
	value = kmalloc(XATTR_SIZE_MAX, GFP_KERNEL);
	if (!value)
		goto out;

	/* Actually get the list of xattrs */
	list_size = vfs_listxattr(old, buf, list_size);
	if (list_size <= 0) {
		error = list_size;
		goto out_free_value;
	}

	for (name = buf; name < (buf + list_size); name += strlen(name) + 1) {
		/* XXX Locking? old is on read-only fs */
		size = vfs_getxattr(old, name, value, XATTR_SIZE_MAX);
		if (size <= 0) {
			error = size;
			goto out_free_value;
		}
		/* XXX do we really need to check for size overflow? */
		/* XXX locks new dentry, lock ordering problems? */
		error = vfs_setxattr(new, name, value, size, 0);
		if (error)
			goto out_free_value;
	}

out_free_value:
	kfree(value);
out:
	kfree(buf);
	return error;
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
		goto out_rmdir;

	fsnotify_mkdir(dir, topmost->dentry);

	mnt_drop_write(parent->mnt);

	return 0;
out_rmdir:
	/* XXX rm created dir */
	dput(topmost->dentry);
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

/**
 * union_create_file
 *
 * @nd: namediata for source file
 * @old: path of the source file
 * @new: path of the new file, negative dentry
 *
 * Must already have mnt_want_write() on the mnt and the parent's
 * i_mutex.
 */

static int union_create_file(struct nameidata *nd, struct path *old,
			     struct dentry *new)
{
	struct path *parent = &nd->path;
	BUG_ON(!mutex_is_locked(&parent->dentry->d_inode->i_mutex));

	return vfs_create(parent->dentry->d_inode, new,
			  old->dentry->d_inode->i_mode, nd);
}

/**
 * union_create_symlink
 *
 * @nd: namediata for source symlink
 * @old: path of the source symlink
 * @new: path of the new symlink, negative dentry
 *
 * Must already have mnt_want_write() on the mnt and the parent's
 * i_mutex.
 */

static int union_create_symlink(struct nameidata *nd, struct path *old,
				struct dentry *new)
{
	void *cookie;
	int error;

	BUG_ON(!mutex_is_locked(&nd->path.dentry->d_inode->i_mutex));
	/*
	 * We want the contents of this symlink, not to follow it, so
	 * this is modeled on generic_readlink() rather than
	 * do_follow_link().
	 */
	nd->depth = 0;
	cookie = old->dentry->d_inode->i_op->follow_link(old->dentry, nd);
	if (IS_ERR(cookie))
		return PTR_ERR(cookie);
	/* Create a copy of the link on the top layer */
	error = vfs_symlink(nd->path.dentry->d_inode, new,
			    nd_get_link(nd));
	if (old->dentry->d_inode->i_op->put_link)
		old->dentry->d_inode->i_op->put_link(old->dentry, nd, cookie);
	return error;
}

/**
 * union_copyup_data - Copy up len bytes of old's data to new
 *
 * @old: path of source file
 * @new_mnt: vfsmount of target file
 * @new_dentry: dentry of target file
 * @len: number of bytes to copy
 */

static int union_copyup_data(struct path *old, struct vfsmount *new_mnt,
			     struct dentry *new_dentry, size_t len)
{
	struct file *old_file;
	struct file *new_file;
	const struct cred *cred = current_cred();
	loff_t offset = 0;
	long bytes;
	int error = 0;

	if (len == 0)
		return 0;

	/* Get reference to balance later fput() */
	path_get(old);
	old_file = dentry_open(old->dentry, old->mnt, O_RDONLY, cred);
	if (IS_ERR(old_file))
		return PTR_ERR(old_file);

	mntget(new_mnt);
	dget(new_dentry);
	new_file = dentry_open(new_dentry, new_mnt, O_WRONLY, cred);
	if (IS_ERR(new_file)) {
		error = PTR_ERR(new_file);
		goto out_fput;
	}

	bytes = do_splice_direct(old_file, &offset, new_file, len,
				 SPLICE_F_MOVE);
	if (bytes < 0)
		error = bytes;

	fput(new_file);
out_fput:
	fput(old_file);
	return error;
}

/**
 * __union_copyup_len - Copy up a file and len bytes of data
 *
 * @nd: nameidata for topmost parent dir
 * @path: path of file to be copied up
 * @len: number of bytes of file data to copy up
 *
 * Parent's i_mutex must be held by caller.  Newly copied up path is
 * returned in @path and original is path_put().
 */

static int __union_copyup_len(struct nameidata *nd, struct path *path,
			      size_t len)
{
	struct path *parent = &nd->path;
	struct dentry *dentry;
	int error;

	BUG_ON(!mutex_is_locked(&parent->dentry->d_inode->i_mutex));

	dentry = lookup_one_len(path->dentry->d_name.name, parent->dentry,
				path->dentry->d_name.len);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (dentry->d_inode) {
		/*
		 * We raced with someone else and "lost."  That's
		 * okay, they did all the work of copying up the file.
		 * Note that currently data copyup happens under the
		 * parent dir's i_mutex.  If we move it outside that,
		 * we'll need some way of waiting for the data copyup
		 * to complete here.
		 */
		error = 0;
		goto out_newpath;
	}
	if (S_ISREG(path->dentry->d_inode->i_mode)) {
		/* Create file */
		error = union_create_file(nd, path, dentry);
		if (error)
			goto out_dput;
		/* Copyup data */
		error = union_copyup_data(path, parent->mnt, dentry, len);
	} else {
		BUG_ON(!S_ISLNK(path->dentry->d_inode->i_mode));
		error = union_create_symlink(nd, path, dentry);
	}
	if (error) {
		/* Most likely error: ENOSPC */
		vfs_unlink(parent->dentry->d_inode, dentry);
		goto out_dput;
	}
	/* XXX Copyup xattrs and any other dangly bits */
	error = union_copyup_xattr(path->dentry, dentry);
	if (error)
		goto out_dput;
out_newpath:
	/* path_put() of original must happen before we copy in new */
	path_put(path);
	path->dentry = dentry;
	path->mnt = mntget(parent->mnt);
	return error;
out_dput:
	/* Don't path_put(path), let caller unwind */
	dput(dentry);
	return error;
}

/**
 * do_union_copyup_len - Copy up a file given its path (and its parent's)
 *
 * @nd: nameidata for topmost parent dir
 * @path: path of file to be copied up
 * @copy_all: if set, copy all of the file's data and ignore @len
 * @len: if @copy_all is not set, number of bytes of file data to copy up
 *
 * Newly copied up path is returned in @path.
 */

static int do_union_copyup_len(struct nameidata *nd, struct path *path,
			       int copy_all, size_t len)
{
	struct path *parent = &nd->path;
	int error;

	if (!IS_DIR_UNIONED(parent->dentry))
		return 0;
	if (parent->mnt == path->mnt)
		return 0;
	if (!S_ISREG(path->dentry->d_inode->i_mode) &&
	    !S_ISLNK(path->dentry->d_inode->i_mode))
		return 0;

	BUG_ON(!S_ISDIR(parent->dentry->d_inode->i_mode));

	mutex_lock(&parent->dentry->d_inode->i_mutex);
	error = -ENOENT;
	if (IS_DEADDIR(parent->dentry->d_inode))
		goto out_unlock;

	if (copy_all && S_ISREG(path->dentry->d_inode->i_mode)) {
		error = -EFBIG;
		len = i_size_read(path->dentry->d_inode);
		/* Check for overflow of file size */
		if (((size_t)len != len) || ((ssize_t)len != len))
			goto out_unlock;
	}

	error = __union_copyup_len(nd, path, len);

out_unlock:
	mutex_unlock(&parent->dentry->d_inode->i_mutex);
	return error;
}

/*
 * Helper function to copy up all of a file
 */
int union_copyup(struct nameidata *nd, struct path *path)
{
	return do_union_copyup_len(nd, path, 1, 0);
}

/*
 * Unlocked helper function to copy up all of a file
 */
int __union_copyup(struct nameidata *nd, struct path *path)
{
	size_t len;
	len = i_size_read(path->dentry->d_inode);
	if (((size_t)len != len) || ((ssize_t)len != len))
		return -EFBIG;

	return __union_copyup_len(nd, path, len);
}

/*
 * Helper function to copy up part of a file
 */
int union_copyup_len(struct nameidata *nd, struct path *path, size_t len)
{
	return do_union_copyup_len(nd, path, 0, len);
}
