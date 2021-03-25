// SPDX-License-Identifier: GPL-2.0-or-later
/* kiocb-using read/write
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/sched/mm.h>
#include <trace/events/fscache.h>
#include "internal.h"

struct cachefiles_kiocb {
	struct kiocb		iocb;
	refcount_t		ki_refcnt;
	unsigned int		inval_counter;
	loff_t			start;
	union {
		size_t		skipped;
		size_t		len;
	};
	struct cachefiles_object *object;
	netfs_io_terminated_t	term_func;
	void			*term_func_priv;
	bool			was_async;
};

static inline void cachefiles_put_kiocb(struct cachefiles_kiocb *ki)
{
	if (refcount_dec_and_test(&ki->ki_refcnt)) {
		cachefiles_put_object(ki->object, cachefiles_obj_put_ioreq);
		fput(ki->iocb.ki_filp);
		kfree(ki);
	}
}

/*
 * Handle completion of a read from the cache.
 */
static void cachefiles_read_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct cachefiles_kiocb *ki = container_of(iocb, struct cachefiles_kiocb, iocb);

	_enter("%ld,%ld", ret, ret2);

	if (ret >= 0) {
		if (ki->object->cookie->inval_counter == ki->inval_counter)
			ki->skipped += ret;
		else
			ret = -ESTALE;
	}

	if (ki->term_func)
		ki->term_func(ki->term_func_priv, ret, ki->was_async);

	cachefiles_put_kiocb(ki);
}

/*
 * Initiate a read from the cache.
 */
static int cachefiles_read(struct netfs_cache_resources *cres,
			   loff_t start_pos,
			   struct iov_iter *iter,
			   bool seek_data,
			   netfs_io_terminated_t term_func,
			   void *term_func_priv)
{
	struct cachefiles_object *object = cachefiles_cres_object(cres);
	struct cachefiles_kiocb *ki;
	struct file *file = cres->cache_priv2;
	unsigned int old_nofs;
	ssize_t ret = -ENOBUFS;
	size_t len = iov_iter_count(iter), skipped = 0;

	_enter("%pD,%li,%llx,%zx/%llx",
	       file, file_inode(file)->i_ino, start_pos, len,
	       i_size_read(file->f_inode));

	__fscache_wait_for_operation(cres, FSCACHE_WANT_READ);
	fscache_count_read();

	/* If the caller asked us to seek for data before doing the read, then
	 * we should do that now.  If we find a gap, we fill it with zeros.
	 */
	if (seek_data) {
		loff_t off = start_pos, off2;

		off2 = vfs_llseek(file, off, SEEK_DATA);
		if (off2 < 0 && off2 >= (loff_t)-MAX_ERRNO && off2 != -ENXIO) {
			skipped = 0;
			ret = off2;
			goto presubmission_error;
		}

		if (off2 == -ENXIO || off2 >= start_pos + len) {
			/* The region is beyond the EOF or there's no more data
			 * in the region, so clear the rest of the buffer and
			 * return success.
			 */
			iov_iter_zero(len, iter);
			skipped = len;
			ret = 0;
			goto presubmission_error;
		}

		skipped = off2 - off;
		iov_iter_zero(skipped, iter);
	}

	ret = -ENOBUFS;
	ki = kzalloc(sizeof(struct cachefiles_kiocb), GFP_KERNEL);
	if (!ki)
		goto presubmission_error;

	refcount_set(&ki->ki_refcnt, 2);
	ki->iocb.ki_filp	= file;
	ki->iocb.ki_pos		= start_pos + skipped;
	ki->iocb.ki_flags	= IOCB_DIRECT;
	ki->iocb.ki_hint	= ki_hint_validate(file_write_hint(file));
	ki->iocb.ki_ioprio	= get_current_ioprio();
	ki->inval_counter	= cres->inval_counter;
	ki->skipped		= skipped;
	ki->object		= object;
	ki->term_func		= term_func;
	ki->term_func_priv	= term_func_priv;
	ki->was_async		= true;

	if (ki->term_func)
		ki->iocb.ki_complete = cachefiles_read_complete;

	get_file(ki->iocb.ki_filp);
	cachefiles_grab_object(object, cachefiles_obj_get_ioreq);

	trace_cachefiles_read(object, file_inode(file), ki->iocb.ki_pos, len - skipped);
	old_nofs = memalloc_nofs_save();
	ret = vfs_iocb_iter_read(file, &ki->iocb, iter);
	memalloc_nofs_restore(old_nofs);
	switch (ret) {
	case -EIOCBQUEUED:
		goto in_progress;

	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		/* There's no easy way to restart the syscall since other AIO's
		 * may be already running. Just fail this IO with EINTR.
		 */
		ret = -EINTR;
		fallthrough;
	default:
		ki->was_async = false;
		cachefiles_read_complete(&ki->iocb, ret, 0);
		if (ret > 0)
			ret = 0;
		break;
	}

in_progress:
	cachefiles_put_kiocb(ki);
	_leave(" = %zd", ret);
	return ret;

presubmission_error:
	if (term_func)
		term_func(term_func_priv, ret < 0 ? ret : skipped, false);
	return ret;
}

/*
 * Handle completion of a write to the cache.
 */
static void cachefiles_write_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct cachefiles_kiocb *ki = container_of(iocb, struct cachefiles_kiocb, iocb);
	struct inode *inode = file_inode(ki->iocb.ki_filp);

	_enter("%ld,%ld", ret, ret2);

	/* Tell lockdep we inherited freeze protection from submission thread */
	__sb_writers_acquired(inode->i_sb, SB_FREEZE_WRITE);
	__sb_end_write(inode->i_sb, SB_FREEZE_WRITE);

	if (ret == ki->len)
		cachefiles_mark_content_map(ki->object, ki->start, ki->len,
					    ki->inval_counter);
	if (ki->term_func)
		ki->term_func(ki->term_func_priv, ret, ki->was_async);
	cachefiles_put_kiocb(ki);
}

/*
 * Initiate a write to the cache.
 */
static int cachefiles_write(struct netfs_cache_resources *cres,
			    loff_t start_pos,
			    struct iov_iter *iter,
			    netfs_io_terminated_t term_func,
			    void *term_func_priv)
{
	struct cachefiles_object *object = cachefiles_cres_object(cres);
	struct cachefiles_kiocb *ki;
	struct inode *inode;
	struct file *file = cres->cache_priv2;
	unsigned int old_nofs;
	ssize_t ret = -ENOBUFS;
	size_t len = iov_iter_count(iter);

	_enter("%pD,%li,%llx,%zx/%llx",
	       file, file_inode(file)->i_ino, start_pos, len,
	       i_size_read(file->f_inode));

	__fscache_wait_for_operation(cres, FSCACHE_WANT_WRITE);
	fscache_count_write();

	ki = kzalloc(sizeof(struct cachefiles_kiocb), GFP_KERNEL);
	if (!ki)
		goto presubmission_error;

	refcount_set(&ki->ki_refcnt, 2);
	ki->iocb.ki_filp	= file;
	ki->iocb.ki_pos		= start_pos;
	ki->iocb.ki_flags	= IOCB_DIRECT | IOCB_WRITE;
	ki->iocb.ki_hint	= ki_hint_validate(file_write_hint(file));
	ki->iocb.ki_ioprio	= get_current_ioprio();
	ki->inval_counter	= cres->inval_counter;
	ki->start		= start_pos;
	ki->len			= len;
	ki->object		= object;
	ki->term_func		= term_func;
	ki->term_func_priv	= term_func_priv;
	ki->was_async		= true;

	if (ki->term_func)
		ki->iocb.ki_complete = cachefiles_write_complete;

	/* Open-code file_start_write here to grab freeze protection, which
	 * will be released by another thread in aio_complete_rw().  Fool
	 * lockdep by telling it the lock got released so that it doesn't
	 * complain about the held lock when we return to userspace.
	 */
	inode = file_inode(file);
	__sb_start_write(inode->i_sb, SB_FREEZE_WRITE);
	__sb_writers_release(inode->i_sb, SB_FREEZE_WRITE);

	get_file(ki->iocb.ki_filp);
	cachefiles_grab_object(object, cachefiles_obj_get_ioreq);

	trace_cachefiles_write(object, inode, ki->iocb.ki_pos, len);
	old_nofs = memalloc_nofs_save();
	ret = vfs_iocb_iter_write(file, &ki->iocb, iter);
	memalloc_nofs_restore(old_nofs);
	switch (ret) {
	case -EIOCBQUEUED:
		goto in_progress;

	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		/* There's no easy way to restart the syscall since other AIO's
		 * may be already running. Just fail this IO with EINTR.
		 */
		ret = -EINTR;
		fallthrough;
	default:
		ki->was_async = false;
		cachefiles_write_complete(&ki->iocb, ret, 0);
		if (ret > 0)
			ret = 0;
		break;
	}

in_progress:
	cachefiles_put_kiocb(ki);
	_leave(" = %zd", ret);
	return ret;

presubmission_error:
	if (term_func)
		term_func(term_func_priv, -ENOMEM, false);
	return -ENOMEM;
}

/*
 * Clean up an operation.
 */
static void cachefiles_end_operation(struct netfs_cache_resources *cres)
{
	struct file *file = cres->cache_priv2;

	_enter("");

	if (file)
		fput(file);
	fscache_end_cookie_access(fscache_cres_cookie(cres), fscache_access_io_end);
}

static const struct netfs_cache_ops cachefiles_netfs_cache_ops = {
	//.wait_for_operation	= __fscache_wait_for_operation,
	.end_operation		= cachefiles_end_operation,
	.read			= cachefiles_read,
	.write			= cachefiles_write,
	.expand_readahead	= cachefiles_expand_readahead,
	.prepare_read		= cachefiles_prepare_read,
	.prepare_write		= cachefiles_prepare_write,
};

/*
 * Open a cache object.
 */
bool cachefiles_open_object(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache = object->cache;
	struct file *file;
	struct path path;

	path.mnt = cache->path.mnt;
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

/*
 * Open the cache file when beginning a cache operation.
 */
int cachefiles_begin_operation(struct netfs_cache_resources *cres)
{
	struct cachefiles_object *object = cachefiles_cres_object(cres);
	//struct cachefiles_cache *cache = object->cache;
	//struct path path;
	struct file *file;

	_enter("");

#if 1 // TODO - Resolve how best to do this
	spin_lock(&object->lock);
	file = get_file(object->backing_file);
	spin_unlock(&object->lock);
#else
	path.mnt = cache->mnt;
	path.dentry = object->dentry;
	file = open_with_fake_path(&path, O_RDWR | O_LARGEFILE | O_DIRECT,
				   d_backing_inode(object->dentry),
				   cache->cache_cred);
	if (IS_ERR(file))
		return PTR_ERR(file);
	if (!S_ISREG(file_inode(file)->i_mode))
		goto error_file;
	if (unlikely(!file->f_op->read_iter) ||
	    unlikely(!file->f_op->write_iter)) {
		pr_notice("Cache does not support read_iter and write_iter\n");
		goto error_file;
	}
#endif

	cres->cache_priv2 = file;
	cres->ops = &cachefiles_netfs_cache_ops;
	_leave("");
	return 0;

#if 0
error_file:
	fput(file);
	return -EIO;
#endif
}
