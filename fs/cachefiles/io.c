// SPDX-License-Identifier: GPL-2.0-or-later
/* Data I/O routines
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/xattr.h>
#include "internal.h"
#include <trace/events/fscache.h>

/*
 * Initiate a read from the cache.
 */
int cachefiles_read(struct fscache_op_resources *opr,
		    loff_t start_pos,
		    struct iov_iter *iter,
		    bool seek_data,
		    fscache_io_terminated_t term_func,
		    void *term_func_priv)
{
	fscache_wait_for_operation(opr, FSCACHE_WANT_READ);
	fscache_count_io_operation(opr->object->cookie);
	if (term_func)
		term_func(term_func_priv, -ENODATA);
	return -ENODATA;
}

/*
 * Initiate a write to the cache.
 */
int cachefiles_write(struct fscache_op_resources *opr,
		     loff_t start_pos,
		     struct iov_iter *iter,
		     fscache_io_terminated_t term_func,
		     void *term_func_priv)
{
	fscache_wait_for_operation(opr, FSCACHE_WANT_WRITE);
	fscache_count_io_operation(opr->object->cookie);
	if (term_func)
		term_func(term_func_priv, -ENOBUFS);
	return -ENOBUFS;
}

/*
 * Open a cache object.
 */
bool cachefiles_open_object(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache =
		container_of(object->fscache.cache, struct cachefiles_cache, cache);
	struct file *file;
	struct path path;

	path.mnt = cache->mnt;
	path.dentry = object->dentry;

	file = open_with_fake_path(&path,
				   O_RDWR | O_LARGEFILE | O_DIRECT,
				   d_backing_inode(object->dentry),
				   cache->cache_cred);
	if (IS_ERR(file))
		goto error;

	if (!S_ISREG(file_inode(file)->i_mode))
		goto error_file;

	if (unlikely(!file->f_op->read_iter) ||
	    unlikely(!file->f_op->write_iter)) {
		pr_notice("Cache does not support read_iter and write_iter\n");
		goto error_file;
	}

	object->backing_file = file;
	return true;

error_file:
	fput(file);
error:
	return false;
}
