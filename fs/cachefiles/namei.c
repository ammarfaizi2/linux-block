// SPDX-License-Identifier: GPL-2.0-or-later
/* CacheFiles path walking and related routines
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/quotaops.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * get a subdirectory
 */
struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					struct dentry *dir,
					const char *dirname)
{
	struct dentry *subdir;
	struct path path;
	int ret;

	_enter(",,%s", dirname);

	/* search the current directory for the element name */
	inode_lock(d_inode(dir));

retry:
	ret = cachefiles_inject_read_error();
	if (ret == 0)
		subdir = lookup_one_len(dirname, dir, strlen(dirname));
	else
		subdir = ERR_PTR(ret);
	if (IS_ERR(subdir)) {
		trace_cachefiles_vfs_error(NULL, d_backing_inode(dir),
					   PTR_ERR(subdir),
					   cachefiles_trace_lookup_error);
		if (PTR_ERR(subdir) == -ENOMEM)
			goto nomem_d_alloc;
		goto lookup_error;
	}

	_debug("subdir -> %pd %s",
	       subdir, d_backing_inode(subdir) ? "positive" : "negative");

	/* we need to create the subdir if it doesn't exist yet */
	if (d_is_negative(subdir)) {
		if (cache->store) {
			ret = cachefiles_has_space(cache, 1, 0);
			if (ret < 0)
				goto mkdir_error;
		}

		_debug("attempt mkdir");

		path.mnt = cache->mnt;
		path.dentry = dir;
		ret = security_path_mkdir(&path, subdir, 0700);
		if (ret < 0)
			goto mkdir_error;
		ret = cachefiles_inject_write_error();
		if (ret == 0)
			ret = vfs_mkdir(&init_user_ns, d_inode(dir), subdir, 0700);
		if (ret < 0) {
			trace_cachefiles_vfs_error(NULL, d_inode(dir), ret,
						   cachefiles_trace_mkdir_error);
			goto mkdir_error;
		}

		if (unlikely(d_unhashed(subdir))) {
			dput(subdir);
			goto retry;
		}
		ASSERT(d_backing_inode(subdir));

		_debug("mkdir -> %pd{ino=%lu}",
		       subdir, d_backing_inode(subdir)->i_ino);
	}

	inode_unlock(d_inode(dir));

	/* we need to make sure the subdir is a directory */
	ASSERT(d_backing_inode(subdir));

	if (!d_can_lookup(subdir)) {
		pr_err("%s is not a directory\n", dirname);
		ret = -EIO;
		goto check_error;
	}

	ret = -EPERM;
	if (!(d_backing_inode(subdir)->i_opflags & IOP_XATTR) ||
	    !d_backing_inode(subdir)->i_op->lookup ||
	    !d_backing_inode(subdir)->i_op->mkdir ||
	    !d_backing_inode(subdir)->i_op->rename ||
	    !d_backing_inode(subdir)->i_op->rmdir ||
	    !d_backing_inode(subdir)->i_op->unlink)
		goto check_error;

	_leave(" = [%lu]", d_backing_inode(subdir)->i_ino);
	return subdir;

check_error:
	dput(subdir);
	_leave(" = %d [check]", ret);
	return ERR_PTR(ret);

mkdir_error:
	inode_unlock(d_inode(dir));
	dput(subdir);
	pr_err("mkdir %s failed with error %d\n", dirname, ret);
	return ERR_PTR(ret);

lookup_error:
	inode_unlock(d_inode(dir));
	ret = PTR_ERR(subdir);
	pr_err("Lookup %s failed with error %d\n", dirname, ret);
	return ERR_PTR(ret);

nomem_d_alloc:
	inode_unlock(d_inode(dir));
	_leave(" = -ENOMEM");
	return ERR_PTR(-ENOMEM);
}
