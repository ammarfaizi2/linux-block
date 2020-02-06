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

/*
 * Initiate a read from the cache.
 */
int cachefiles_read(struct fscache_object *object,
		    struct fscache_io_request *req,
		    struct iov_iter *iter)
{
	req->error = -ENODATA;
	if (req->io_done)
		req->io_done(req);
	return -ENODATA;
}

/*
 * Initiate a write to the cache.
 */
int cachefiles_write(struct fscache_object *object,
		     struct fscache_io_request *req,
		     struct iov_iter *iter)
{
	req->error = -ENOBUFS;
	if (req->io_done)
		req->io_done(req);
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

	if (object->content_info == CACHEFILES_CONTENT_MAP &&
	    !cachefiles_load_content_map(object))
		goto error;

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
