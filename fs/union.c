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
#define DEBUG
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>
#include <linux/fsnotify.h>
#include <linux/xattr.h>
#include <linux/file.h>
#include <linux/security.h>
#include <linux/splice.h>
#include <linux/ratelimit.h>

#include "internal.h"
#include "union.h"

/**
 * d_free_unions - free all unions for this dentry
 * @dentry: topmost dentry in the union stack to remove
 *
 * This must be called when freeing a dentry.  d_inode may point to a defunct
 * inode or may have been cleared by the time we get here.
 */
void d_free_unions(struct dentry *topmost)
{
	struct path *path;
	unsigned int i, layers = topmost->d_sb->s_union_count;

	if (topmost->d_union_stack) {
		if (topmost->d_flags & DCACHE_UNION_PINNING_LOWER) {
			/* A negative non-dir upper dentry is pinning
			 * a single lower dentry so that f_inode
			 * doesn't have to.
			 */
			printk("free pin: %pd\n", topmost);
			dput(topmost->d_fallthru);
		} else {
			/* A positive directory dentry is pinning a
			 * stack of lower dirs.
			 */
			printk("free dirstack: %pd\n", topmost);

			for (i = 0; i < layers; i++) {
				path = union_find_dir(topmost, i);
				if (path->mnt)
					path_put(path);
			}
			kfree(topmost->d_union_stack);
		}
		topmost->d_union_stack = NULL;
	}
}

/**
 * union_add_dir - Add another layer to a unioned directory
 * @topmost: topmost directory
 * @lower: directory in the current layer
 * @layer: index of layer to add this at
 *
 * @layer counts starting at 0 for the dir below the topmost dir.
 *
 * This transfers the caller's references to the constituents of *lower to the
 * union stack.
 */
int union_add_dir(struct path *topmost, struct path *lower, unsigned layer)
{
	struct dentry *dentry = topmost->dentry;
	struct path *path;

	BUG_ON(layer >= dentry->d_sb->s_union_count);
	BUG_ON(d_is_fallthru(dentry));

	if (!dentry->d_union_stack)
		dentry->d_union_stack = union_alloc_stack(topmost);
	if (!dentry->d_union_stack)
		return -ENOMEM;

	path = union_find_dir(dentry, layer);
	*path = *lower;
	return 0;
}

/**
 * union_copy_up_xattr
 * @new: dentry of new copy
 * @old: dentry of original file
 *
 * Copy up extended attributes from the original file to the new one.
 *
 * XXX - Permissions?  For now, copying up every xattr.
 */
static int union_copy_up_xattr(struct path *new, struct dentry *old)
{
	ssize_t list_size, size;
	char *buf, *name, *value;
	int error;

	/* Check for xattr support */
	if (!old->d_inode->i_op->getxattr ||
	    !new->dentry->d_inode->i_op->getxattr)
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
 * @parent - parent of target on topmost layer
 * @topmost - path of target on topmost layer
 * @d - stack of source directories in lower layers
 *
 * As we lookup each directory on the lower layer of a union, we create a
 * matching directory on the topmost layer if it does not already exist.
 *
 * We don't use vfs_mkdir() for a few reasons: don't want to do the security
 * check, don't want to make the dir opaque, don't need to sanitize the mode.
 *
 * The caller must hold the parent i_mutex lock and the mnt_want_write lock.
 *
 * XXX - owner is wrong, set credentials properly
 * XXX - rmdir() directory on failure of xattr copyup
 * XXX - not atomic w/ respect to crash
 */
int union_create_topmost_dir(struct path *parent,
			     struct path *topmost,
			     struct union_stack *d)
{
	struct dentry *lower;
	struct inode *dir = parent->dentry->d_inode;
	unsigned i, layers = parent->dentry->d_sb->s_union_count;
	int error;

	BUG_ON(topmost->dentry->d_inode);

	for (i = 0; i < layers; i++)
		if ((lower = d->u_dirs[i].dentry))
			break;

	/* XXX - Do we even need to check this? */
	if (!dir->i_op->mkdir)
		return -EPERM;

	error = dir->i_op->mkdir(dir, topmost->dentry, lower->d_inode->i_mode);
	if (error)
		return error;

	error = union_copy_up_xattr(topmost, lower);
	if (error)
		goto out_rmdir;

	fsnotify_mkdir(dir, topmost->dentry);
	return 0;

out_rmdir:
	/* XXX rm created dir */
	dput(topmost->dentry);
	return error;
}

struct union_iterate_context {
	struct dir_context ctx;
	struct dentry *topmost_dentry;
	int error;
};

/**
 * union_copy_up_one_dirent - copy up a single directory entry
 *
 * Individual directory entry copyup function for union_copy_up_dir.
 * We get the entries from higher level layers first.
 */
static int union_copy_up_one_dirent(void *buf, const char *name, int namelen,
				    loff_t offset, u64 ino, unsigned int d_type)
{
	struct union_iterate_context *uic = (struct union_iterate_context *)buf;
	struct dentry *topmost_dentry = uic->topmost_dentry;
	struct dentry *dentry;
	int err = 0;

	switch (namelen) {
	case 2:
		if (name[1] != '.')
			break;
	case 1:
		if (name[0] != '.')
			break;
		return 0;
	}

	/* Lookup this entry in the topmost directory */
	dentry = lookup_one_len(name, topmost_dentry, namelen);

	if (IS_ERR(dentry)) {
		printk(KERN_WARNING "%s: error looking up %*.*s\n",
		       __func__, namelen, namelen, name);
		err = PTR_ERR(dentry);
		goto out;
	}

	/* XXX do we need to revalidate on readdir anyway? think NFS */
	if (dentry->d_op && dentry->d_op->d_revalidate)
		goto fallthru;

	/* If the entry already exists, one of the following is true: it was
	 * already copied up (due to an earlier lookup), an entry with the same
	 * name already exists on the topmost file system, it is a whiteout, or
	 * it is a fallthru.  In each case, the top level entry masks any
	 * entries from lower file systems, so don't copy up this entry.
	 */
	if (dentry->d_inode || d_is_whiteout(dentry) || d_is_fallthru(dentry))
		goto out_dput;

	/* If the entry doesn't exist, create a fallthru entry in the topmost
	 * file system.  All possible directory types are used, so each file
	 * system must implement its own way of storing a fallthru entry.
	 */
fallthru:
	err = topmost_dentry->d_inode->i_op->fallthru(topmost_dentry->d_inode,
						      dentry);

	/* It's okay if it exists, ultimate responsibility rests with
	 * ->fallthru() */
	if (err == -EEXIST)
		err = 0;
out_dput:
	dput(dentry);
out:
	if (err)
		uic->error = err;
	return err;
}

/**
 * __union_copy_up_dir - Non-recursive directory copy up
 *
 * Copy up the specified directory only, without recursing into the subtree
 * rooted at this point.
 *
 * During the operation, where a directory entry exists in one of the lower
 * directories, a fallthrough dentry will be created in the upper directory if
 * the upper directory doesn't already have an entry that obscures it.  At the
 * end of the operation, the upper directory will be marked opaque on the
 * medium - thus preventing further copy up attempts on this directory.
 *
 * TODO: At some point in the future, on-medium whiteouts should be culled from
 * a directory that is marked opaque as they then serve no purpose.
 *
 * The primary reason for this function is that readdir() is difficult to
 * support on union file systems for two reasons: We must eliminate duplicates
 * and apply whiteouts, and we must return something in f_pos that lets us
 * restart in the same place when we return.  Our solution is to, on first
 * readdir() of the directory, copy up all visible entries from the low-level
 * file systems and mark the entries that refer to low-level file system
 * objects as "fallthrough" entries.
 *
 * Sadly, this function is also necessary for rmdir().  To work out whether a
 * directory is empty, we have to work out if there are entries in lower
 * directories that are not obscured by whiteouts in the upper.  This is not a
 * trivial operation.  The simplest way is, therefore, to copy up and then
 * check the combined opaque directory.
 *
 *
 * Locking strategy: We hold the topmost dir's i_mutex on entry.  We grab the
 * i_mutex on lower directories one by one.  So the locking order is:
 *
 *	Writable/topmost layers > Read-only/lower layers
 *
 * So there is no problem with lock ordering for union stacks with
 * multiple lower layers.  E.g.:
 *
 *	(topmost) A->B->C (bottom)
 *	(topmost) D->C->B (bottom)
 *
 */
int __union_copy_up_dir(struct path *topmost_path)
{
	struct dentry *topmost_dentry = topmost_path->dentry;
	unsigned int i, layers = topmost_dentry->d_sb->s_union_count;
	int error = 0;

	struct union_iterate_context uic = {
		.ctx.actor = union_copy_up_one_dirent,
		.topmost_dentry = topmost_dentry,
	};


	if (IS_OPAQUE(topmost_dentry->d_inode))
		return 0;

	if (!topmost_dentry->d_inode->i_op ||
	    !topmost_dentry->d_inode->i_op->fallthru)
		return -EOPNOTSUPP;

	for (i = 0; i < layers; i++) {
		struct inode *inode;
		struct file *ftmp;
		struct path *path;

		path = union_find_dir(topmost_dentry, i);
		if (!path->mnt)
			continue;

		ftmp = dentry_open(path, O_RDONLY | O_DIRECTORY | O_NOATIME,
				   current_cred());
		if (IS_ERR(ftmp)) {
			printk(KERN_ERR "unable to open dir %pd for "
			       "directory copyup: %ld\n",
			       path->dentry, PTR_ERR(ftmp));
			error = PTR_ERR(ftmp);
			break;
		}

		inode = file_inode(ftmp);
		mutex_lock(&inode->i_mutex);

		error = -ENOENT;
		if (IS_DEADDIR(inode))
			goto out_fput;

		/* Read the whole directory, calling our directory entry copyup
		 * function on each entry.
		 */
		uic.ctx.pos = 0;
		uic.error = 0;
		error = ftmp->f_op->iterate(ftmp, &uic.ctx);
out_fput:
		mutex_unlock(&inode->i_mutex);
		fput(ftmp);

		if (uic.error)
			error = uic.error;
		if (error)
			break;

		/* XXX Should process directories below an opaque directory in
		 * case there are fallthrus in it
		 */
		if (IS_OPAQUE(path->dentry->d_inode))
			break;
	}

	/* Mark this dir opaque to show that we have already copied up the
	 * lower entries.  Be sure to do this AFTER the directory entries have
	 * been copied up so that if we crash in the middle of copyup, we will
	 * try to copyup the dir next time we read it.
	 *
	 * XXX - Could leave directory non-opaque, and force reread/copyup of
	 * directory each time it is read in from disk.  That would make it
	 * easy to update lower file systems (when not union mounted) and have
	 * the changes show up when union mounted again.
	 */
	if (!error) {
		topmost_dentry->d_inode->i_flags |= S_OPAQUE;
		mark_inode_dirty(topmost_dentry->d_inode);
	}

	return error;
}

/* Relationship between i_mode and the DT_xxx types */
static inline unsigned char dt_type(struct inode *inode)
{
	return (inode->i_mode >> 12) & 15;
}

/**
 * generic_readdir_fallthru - Helper to lookup target of a fallthru
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
int generic_readdir_fallthru(struct dentry *topmost_dentry, const char *name,
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
EXPORT_SYMBOL(generic_readdir_fallthru);

/*
 * Get the inode and path for a dentry where that inode may exist on a lower
 * layer in a union.
 *
 * The caller must preclear the elements of *_lower_cache and prime *_actual
 * with the contents of *upper (as is done by wrappers in union.h) and must
 * also hold parent->i_mutex.
 *
 * Note that we don't get a ref on the inode or the lower vfsmount (if
 * returned).  We leave it to the caller to iget/mntget them if appropriate.
 * This should be safe as the caller holds parent->i_mutex.  The lower dentry
 * (if returned) is dget'd, however.
 *
 * The pointers returned in *_actual are not dget'd/mntget'd as it is assumed
 * they're pinned by the caller's ref on upper->mnt (if set), upper->dentry; or
 * by the fact that parent->i_mutex is locked and _lower_cache->dentry is
 * dget'd.
 */
struct inode *__union_get_inode_locked(struct dentry *parent,
				       struct path *upper,
				       struct path *_lower_cache,
				       struct path *_actual)
{
	const struct union_stack *d;
	struct dentry *dentry = upper->dentry;
	unsigned i, layers = parent->d_sb->s_union_count;

	pr_devel("-->%s(%pd,)\n", __func__, dentry);

	BUG_ON(d_is_whiteout(dentry));

	/* Check for a race with copy up. */
	if (likely(dentry->d_inode)) {
		pr_devel("<--%s() = upper\n", __func__);
		*_actual = *upper;
		return dentry->d_inode;
	}

	BUG_ON(!(dentry->d_flags & DCACHE_UNION_PINNING_LOWER));

	pr_devel("<--%s() = fallthru\n", __func__);
	smp_rmb();
	_actual->dentry = dentry->d_fallthru;
	d = parent->d_union_stack;
	for (i = 0; i < layers; i++) {
		if (d->u_dirs[i].dentry == dentry->d_fallthru->d_parent) {
			_lower_cache->mnt = d->u_dirs[i].mnt;
			break;
		}
	}
	if (unlikely(!_lower_cache->mnt))
		goto out_badcache;
	_actual->mnt = mntget(_lower_cache->mnt);
	return dentry->d_fallthru->d_inode;

out_badcache:
	printk_ratelimited(KERN_WARNING "UNION: Bad cached fallthru (%pd/%pd)\n",
			   parent, upper->dentry);
	return ERR_PTR(-EIO);
}

/*
 * Get the inode for a dentry where that inode may exist on a lower layer in a
 * union.
 *
 * Note that we don't get a ref on the inode, so we may need to pin it by
 * getting a ref on a dentry pointing to it - in which case, a pointer to that
 * dentry will be returned in *_lower and the caller is expected to dput() the
 * ref on it.
 */
struct inode *__union_get_inode(struct path *upper, struct path *_lower_cache,
				struct path *_actual)
{
	struct dentry *parent, *dentry = upper->dentry;
	struct inode *inode;
	int ret;

	pr_devel("-->%s(%pd,)\n", __func__, dentry);

	/* We need the parent directory so that we can find the stack of lower
	 * directories in which to do lookups.  Use the rename mutex to prevent
	 * rename from getting underfoot whilst we get the parent.
	 */
	if (mutex_lock_interruptible(&dentry->d_sb->s_vfs_rename_mutex) < 0)
		return ERR_PTR(-EINTR);

	parent = dget_parent(dentry);
	if (IS_OPAQUE(parent->d_inode) && !d_is_fallthru(dentry)) {
		mutex_unlock(&dentry->d_sb->s_vfs_rename_mutex);
		inode = NULL;
	} else {
		ret = mutex_lock_interruptible(&parent->d_inode->i_mutex);
		mutex_unlock(&dentry->d_sb->s_vfs_rename_mutex);
		if (ret < 0) {
			inode = ERR_PTR(ret);
		} else {
			inode = __union_get_inode_locked(parent, upper,
							 _lower_cache, _actual);
			mutex_unlock(&parent->d_inode->i_mutex);
		}
	}
	dput(parent);
	return inode;
}

/**
 * union_create_file
 * @parent: path of the upper parent directory
 * @upper: path of the negative dentry to become new file
 * @lower: path of the source file
 *
 * Must already have mnt_want_write() on the mnt and the parent's i_mutex.
 */
static int union_create_file(struct path *parent, struct path *upper,
			     struct path *lower)
{
	struct inode *dir = parent->dentry->d_inode;
	int ret;

	if (!dir->i_op->tmpfile)
		return -EPERM;

	ret = dir->i_op->tmpfile(dir, upper->dentry,
				 lower->dentry->d_inode->i_mode);
	if (ret == 0) {
		spin_lock(&upper->dentry->d_inode->i_lock);
		upper->dentry->d_inode->i_state |= I_LINKABLE;
		spin_unlock(&upper->dentry->d_inode->i_lock);
	}
	return ret;
}

/**
 * union_create_symlink
 * @parent: Upper parent of the symlink
 * @upper: Path of the negative dentry to become new symlink.
 * @lower: Path of the source symlink
 *
 * Must already have mnt_want_write() on the mnt and the parent's i_mutex.
 */
static int union_create_symlink(struct path *parent, struct path *upper,
				struct path *lower)
{
	struct inode *inode = lower->dentry->d_inode;
	char *content;
	int error;

	content = kmalloc(PATH_MAX + 2, GFP_KERNEL);
	if (!content)
		return -ENOMEM;

	error = inode->i_op->readlink(lower->dentry, content, PATH_MAX + 1);
	if (error < 0)
		goto error;
	content[error] = 0;

	error = vfs_symlink(parent->dentry->d_inode, upper->dentry, content);
error:
	kfree(content);
	return error;
}

/**
 * union_copy_up_data - Copy up len bytes of old's data to new
 * @path: path of target file
 * @actual: path of source file in lower layer
 * @truncate_to: number of bytes to copy (or NULL if all)
 */
static int union_copy_up_data(struct path *path, struct path *actual,
			      const loff_t *truncate_to)
{
	const struct cred *cred = current_cred();
	struct file *lower_file;
	struct file *new_file;
	loff_t filesize, loffset = 0, noffset = 0;
	size_t len;
	long bytes;
	int error = 0;

	filesize = i_size_read(actual->dentry->d_inode);
	if (truncate_to && *truncate_to < filesize)
		filesize = *truncate_to;

	/* Check for overflow of file size */
	len = filesize;
	if (len != filesize)
		return -EFBIG;

	if (len == 0)
		return 0;

	lower_file = dentry_open(actual, O_RDONLY, cred);
	if (IS_ERR(lower_file))
		return PTR_ERR(lower_file);

	new_file = dentry_open(path, O_WRONLY, cred);
	if (IS_ERR(new_file)) {
		error = PTR_ERR(new_file);
		goto out_fput;
	}

	bytes = do_splice_direct(lower_file, &loffset,
				 new_file, &noffset, len,
				 SPLICE_F_MOVE);
	if (bytes < 0)
		error = bytes;

	fput(new_file);
out_fput:
	fput(lower_file);
	return error;
}

/*
 * Create a temporary file.  We don't want to inline this as it uses quite a
 * lot of stack space.
 *
 * The caller should make sure _tmpfile->mnt is set to the upper vfsmount and
 * that ->dentry is NULL.
 *
 * Note: we don't return with a ref on _tmpfile->mnt as path is holding a ref.
 * Further, we may return with a dentry in _tmpfile->dentry that needs
 * dput'ing, even if an error occurred.
 */
static int union_create_tmpfile(struct path *parent, struct path *path,
				struct path *actual, struct path *_tmpfile)
{
	static const struct qstr nameless = { .name = "", .len = 0, .hash = 0 };
	struct dentry *dentry;
	int ret;

	pr_devel("-->%s(%pd)\n", __func__, path->dentry);

	/* Create a nameless file not directly attached to the parent
	 * directory, but still associated with it for layout optimisation
	 * reasons.  The upperfs should check for the file being of zero
	 * length.
	 * 
	 * We will then hard link the file into place when we're done copying
	 * up - and mount/fsck will clean it up in the event of a crash and
	 * dget() will clean it up in the event of an error.
	 */
	dentry = d_alloc(parent->dentry, &nameless);
	if (!IS_ERR(dentry)) {
		_tmpfile->dentry = dentry;
		if (S_ISREG(actual->dentry->d_inode->i_mode))
			ret = union_create_file(parent, _tmpfile, actual);
		else if (S_ISLNK(actual->dentry->d_inode->i_mode))
			ret = union_create_symlink(parent, _tmpfile, actual);
		else
			BUG();
	} else {
		ret = PTR_ERR(dentry);
	}

	pr_devel("<--%s() = %d\n", __func__, ret);
	return ret;
}

/**
 * Copy up a file or symlink to a temporary file in the specially prepared
 * directory and return the dentry of that.
 */
static int union_copy_up_to_tmpfile(struct path *parent, struct path *path,
				    struct path *actual, struct path *_tmpfile,
				    const loff_t *truncate_to)
{
	struct dentry *dentry = actual->dentry;
	int ret;

	ret = union_create_tmpfile(parent, path, actual, _tmpfile);

	if (ret == 0 && S_ISREG(dentry->d_inode->i_mode))
		ret = union_copy_up_data(_tmpfile, actual, truncate_to);
	if (ret == 0)
		ret = union_copy_up_xattr(_tmpfile, actual->dentry);
	return ret;
}

/*
 * Create a hardlink from the temporary file to the actual location.
 */
static int union_hard_link_to_tmpfile(struct path *parent, struct path *path,
				      struct path *tmpfile)
{
	int ret;

	pr_devel("-->%s(%pd,%pd,%pd)\n",
		 __func__, parent->dentry, path->dentry, tmpfile->dentry);

	ret = vfs_link(tmpfile->dentry, parent->dentry->d_inode, path->dentry,
		       NULL);
	return ret;
}

/**
 * union_copy_up_via_tmpfile - Copy up lower file via temporary file
 *
 * Copy up a file or symlink to a temporary file in the specially prepared
 * directory, then hard link across and unlink the temp file.
 */
static int union_copy_up_via_tmpfile(struct path *parent, struct path *path,
				     struct path *actual,
				     const loff_t *truncate_to)
{
	const struct cred *saved_cred;
	struct cred *override_cred;
	struct path tmpfile = { .mnt = path->mnt, .dentry = NULL };
	int ret;

	pr_devel("-->%s(,%pd,%pd,%pd,,%lld)\n",
		 __func__, parent->dentry, path->dentry, actual->dentry,
		 truncate_to ? *truncate_to : -1);

	override_cred = prepare_kernel_cred(NULL);
	if (!override_cred)
		return -ENOMEM;

	override_cred->fsuid = actual->dentry->d_inode->i_uid;
	override_cred->fsgid = actual->dentry->d_inode->i_gid;

	saved_cred = override_creds(override_cred);

	ret = union_copy_up_to_tmpfile(parent, path, actual, &tmpfile,
				       truncate_to);

	if (ret == 0)
		ret = union_hard_link_to_tmpfile(parent, path, &tmpfile);

	/* Discard the temporary dentry */
	dput(tmpfile.dentry);

	revert_creds(saved_cred);

	put_cred(override_cred);
	pr_devel("<--%s() = %d\n", __func__, ret);
	return ret;
}

/**
 * __union_copy_up - Copy a non-directory file up to the upper layer.
 */
int __union_copy_up(struct path *path, struct path *actual,
		    const loff_t *truncate_to)
{
	struct dentry *upper = path->dentry;
	struct path parent;
	int ret;

	pr_devel("-->%s(%pd)\n", __func__, path->dentry);

	/* We don't currently support copyup of special files, though in theory
	 * there's no reason we couldn't at least copy up blockdev and chrdev
	 * files.  FIFO files are problematic if open.  Socket files are
	 * managed by AF_UNIX and would need help from there.  Directories are
	 * handled by pathwalk.
	 */
	if (!S_ISREG(actual->dentry->d_inode->i_mode) &&
	    !S_ISLNK(actual->dentry->d_inode->i_mode))
		return -EACCES;

	parent.mnt = path->mnt;

	/* We need to get the parent directory and then we need to lock it.
	 * Use the rename mutex to prevent rename from getting underfoot whilst
	 * we do this.
	 */
	if (mutex_lock_interruptible(&upper->d_sb->s_vfs_rename_mutex) < 0)
		return -EINTR;

	if (upper->d_inode) {
		mutex_unlock(&upper->d_sb->s_vfs_rename_mutex);
		goto already_copied_up;
	}

	parent.dentry = dget_parent(upper);
	BUG_ON(IS_OPAQUE(parent.dentry->d_inode) && !d_is_fallthru(upper));
	BUG_ON(d_is_whiteout(upper));

	ret = mutex_lock_interruptible(&parent.dentry->d_inode->i_mutex);
	mutex_unlock(&upper->d_sb->s_vfs_rename_mutex);
	if (ret < 0) {
		dput(parent.dentry);
		goto out;
	}

	if (upper->d_inode)
		goto already_copied_up_unlock;

	/* Do the copy up */
	ret = union_copy_up_via_tmpfile(&parent, path, actual, truncate_to);
	mutex_unlock(&parent.dentry->d_inode->i_mutex);
	dput(parent.dentry);

out:
	pr_devel("<--%s() = %d\n", __func__, ret);
	return ret;

already_copied_up_unlock:
	mutex_unlock(&parent.dentry->d_inode->i_mutex);
	dput(parent.dentry);
already_copied_up:
	pr_devel("<--%s() = 0 [already done]\n", __func__);
	*actual = *path;
	return 0;
}

/**
 * __union_copy_up_for_do_last - Copy up a file for do_last()
 * @parent: The parent directory of the file to be copied up.
 * @path: The file to be copied up _to_.
 * @will_truncate: Whether or not O_TRUNC is in force.
 *
 * Copy up for do_last().  It is expected that the caller will hold the
 * want-write lock and will have called union_lookup_point*() first.
 */
int __union_copy_up_for_do_last(struct path *parent, struct path *path,
				bool will_truncate)
{
	struct path lower_cache, actual;
	struct inode *inode;
	loff_t zero = 0;
	int ret;

	pr_devel("-->%s(,%pd{%pd},)\n",
		 __func__, path->dentry,
		 path->dentry->d_fallthru ? path->dentry->d_fallthru : NULL);

	BUG_ON(!(path->dentry->d_flags & DCACHE_UNION_LOOKUP_DONE));
	BUG_ON(!(path->dentry->d_flags & DCACHE_UNION_PINNING_LOWER));
	BUG_ON(!path->dentry->d_fallthru);

	ret = mutex_lock_interruptible(&parent->dentry->d_inode->i_mutex);
	if (ret < 0)
		return ret;

	/* Check to see if we raced with another copy-up or an unlink */
	ret = 0;
	if (path->dentry->d_parent != parent->dentry ||
	    path->dentry->d_inode)
		goto unlock_out;

	inode = union_get_inode_locked(parent->dentry, path,
				       &lower_cache, &actual);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto unlock_out;
	}

	/* Do the copy up */
	ret = union_copy_up_via_tmpfile(parent, path, &actual,
					will_truncate ? &zero : 0);
	mutex_unlock(&parent->dentry->d_inode->i_mutex);
	path_put_maybe(&lower_cache);

	pr_devel("<--%s() = %d [post]\n", __func__, ret);
	return ret;

unlock_out:
	mutex_unlock(&parent->dentry->d_inode->i_mutex);
	pr_devel("<--%s() = %d [pre]\n", __func__, ret);
	return ret;
}
