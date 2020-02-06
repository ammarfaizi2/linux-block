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
	loff_t			start;
	union {
		size_t		skipped;
		size_t		len;
	};
	struct cachefiles_object *object;
	netfs_io_terminated_t	term_func;
	void			*term_func_priv;
	bool			was_async;
	unsigned int		inval_counter;	/* Copy of cookie->inval_counter */
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

	if (ki->term_func) {
		if (ret >= 0) {
			if (ki->object->cookie->inval_counter == ki->inval_counter)
				ki->skipped += ret;
			else
				ret = -ESTALE;
		}

		ki->term_func(ki->term_func_priv, ret, ki->was_async);
	}

	cachefiles_put_kiocb(ki);
}

/*
 * Initiate a read from the cache.
 */
static int cachefiles_read(struct netfs_cache_resources *cres,
			   loff_t start_pos,
			   struct iov_iter *iter,
			   enum netfs_read_from_hole read_hole,
			   netfs_io_terminated_t term_func,
			   void *term_func_priv)
{
	struct cachefiles_object *object;
	struct cachefiles_kiocb *ki;
	struct file *file;
	unsigned int old_nofs;
	ssize_t ret = -ENOBUFS;
	size_t len = iov_iter_count(iter), skipped = 0;

	if (!fscache_wait_for_operation(cres, FSCACHE_WANT_READ))
		goto presubmission_error;

	fscache_count_read();
	object = cachefiles_cres_object(cres);
	file = cachefiles_cres_file(cres);

	_enter("%pD,%li,%llx,%zx/%llx",
	       file, file_inode(file)->i_ino, start_pos, len,
	       i_size_read(file_inode(file)));

	/* If the caller asked us to seek for data before doing the read, then
	 * we should do that now.  If we find a gap, we fill it with zeros.
	 */
	if (read_hole != NETFS_READ_HOLE_IGNORE) {
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
			ret = -ENODATA;
			if (read_hole == NETFS_READ_HOLE_FAIL)
				goto presubmission_error;

			iov_iter_zero(len, iter);
			skipped = len;
			ret = 0;
			goto presubmission_error;
		}

		skipped = off2 - off;
		iov_iter_zero(skipped, iter);
	}

	ret = -ENOMEM;
	ki = kzalloc(sizeof(struct cachefiles_kiocb), GFP_KERNEL);
	if (!ki)
		goto presubmission_error;

	refcount_set(&ki->ki_refcnt, 2);
	ki->iocb.ki_filp	= file;
	ki->iocb.ki_pos		= start_pos + skipped;
	ki->iocb.ki_flags	= IOCB_DIRECT;
	ki->iocb.ki_hint	= ki_hint_validate(file_write_hint(file));
	ki->iocb.ki_ioprio	= get_current_ioprio();
	ki->skipped		= skipped;
	ki->object		= object;
	ki->inval_counter	= object->cookie->inval_counter;
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
	struct cachefiles_object *object;
	struct cachefiles_kiocb *ki;
	struct inode *inode;
	struct file *file;
	unsigned int old_nofs;
	ssize_t ret = -ENOBUFS;
	size_t len = iov_iter_count(iter);

	if (!fscache_wait_for_operation(cres, FSCACHE_WANT_WRITE))
		goto presubmission_error;
	fscache_count_write();
	object = cachefiles_cres_object(cres);
	file = cachefiles_cres_file(cres);

	_enter("%pD,%li,%llx,%zx/%llx",
	       file, file_inode(file)->i_ino, start_pos, len,
	       i_size_read(file_inode(file)));

	ret = -ENOMEM;
	ki = kzalloc(sizeof(struct cachefiles_kiocb), GFP_KERNEL);
	if (!ki)
		goto presubmission_error;

	refcount_set(&ki->ki_refcnt, 2);
	ki->iocb.ki_filp	= file;
	ki->iocb.ki_pos		= start_pos;
	ki->iocb.ki_flags	= IOCB_DIRECT | IOCB_WRITE;
	ki->iocb.ki_hint	= ki_hint_validate(file_write_hint(file));
	ki->iocb.ki_ioprio	= get_current_ioprio();
	ki->object		= object;
	ki->inval_counter	= object->cookie->inval_counter;
	ki->start		= start_pos;
	ki->len			= len;
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
		term_func(term_func_priv, ret, false);
	return ret;
}

/*
 * Prepare a read operation, shortening it to a cached/uncached
 * boundary as appropriate.
 */
static enum netfs_read_source cachefiles_prepare_read(struct netfs_read_subrequest *subreq,
						      loff_t i_size)
{
	struct netfs_read_request *rreq = subreq->rreq;
	struct netfs_cache_resources *cres = &rreq->cache_resources;
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	struct fscache_cookie *cookie = fscache_cres_cookie(cres);
	const struct cred *saved_cred;
	struct file *file = cachefiles_cres_file(cres);
	enum netfs_read_source ret = NETFS_DOWNLOAD_FROM_SERVER;
	loff_t off, to;

	_enter("%zx @%llx/%llx", subreq->len, subreq->start, i_size);

	if (subreq->start >= i_size) {
		ret = NETFS_FILL_WITH_ZEROES;
		goto out_no_object;
	}

	if (test_bit(FSCACHE_COOKIE_NO_DATA_TO_READ, &cookie->flags)) {
		__set_bit(NETFS_SREQ_WRITE_TO_CACHE, &subreq->flags);
		goto out_no_object;
	}

	/* The object and the file may be being created in the background. */
	if (!file) {
		if (!fscache_wait_for_operation(cres, FSCACHE_WANT_READ))
			goto out_no_object;
		file = cachefiles_cres_file(cres);
		if (!file)
			goto out_no_object;
	}

	object = cachefiles_cres_object(cres);
	cache = object->volume->cache;
	cachefiles_begin_secure(cache, &saved_cred);

	off = vfs_llseek(file, subreq->start, SEEK_DATA);
	if (off < 0 && off >= (loff_t)-MAX_ERRNO) {
		if (off == (loff_t)-ENXIO)
			goto download_and_store;
		goto out;
	}

	if (off >= subreq->start + subreq->len)
		goto download_and_store;

	if (off > subreq->start) {
		off = round_up(off, cache->bsize);
		subreq->len = off - subreq->start;
		goto download_and_store;
	}

	to = vfs_llseek(file, subreq->start, SEEK_HOLE);
	if (to < 0 && to >= (loff_t)-MAX_ERRNO)
		goto out;

	if (to < subreq->start + subreq->len) {
		if (subreq->start + subreq->len >= i_size)
			to = round_up(to, cache->bsize);
		else
			to = round_down(to, cache->bsize);
		subreq->len = to - subreq->start;
	}

	ret = NETFS_READ_FROM_CACHE;
	goto out;

download_and_store:
	if (cachefiles_has_space(cache, 0, (subreq->len + PAGE_SIZE - 1) / PAGE_SIZE) == 0)
		__set_bit(NETFS_SREQ_WRITE_TO_CACHE, &subreq->flags);
out:
	cachefiles_end_secure(cache, saved_cred);
out_no_object:
	return ret;
}

/*
 * Prepare for a write to occur.
 */
static int cachefiles_prepare_write(struct netfs_cache_resources *cres,
				    loff_t *_start, size_t *_len, loff_t i_size)
{
	loff_t start = *_start;
	size_t len = *_len, down;

	/* Round to DIO size */
	down = start - round_down(start, PAGE_SIZE);
	*_start = start - down;
	*_len = round_up(down + len, PAGE_SIZE);
	return 0;
}

/*
 * Prepare for a write to occur from the fallback I/O API.
 */
static int cachefiles_prepare_fallback_write(struct netfs_cache_resources *cres,
					     pgoff_t index)
{
	struct cachefiles_object *object = cachefiles_cres_object(cres);
	struct cachefiles_cache *cache = object->volume->cache;

	_enter("%lx", index);

	return cachefiles_has_space(cache, 0, 1);
}

/*
 * Clean up an operation.
 */
static void cachefiles_end_operation(struct netfs_cache_resources *cres)
{
	struct file *file = cachefiles_cres_file(cres);

	if (file)
		fput(file);
	fscache_end_cookie_access(fscache_cres_cookie(cres), fscache_access_io_end);
}

static const struct netfs_cache_ops cachefiles_netfs_cache_ops = {
	.end_operation		= cachefiles_end_operation,
	.read			= cachefiles_read,
	.write			= cachefiles_write,
	.prepare_read		= cachefiles_prepare_read,
	.prepare_write		= cachefiles_prepare_write,
	.prepare_fallback_write	= cachefiles_prepare_fallback_write,
};

/*
 * Open the cache file when beginning a cache operation.
 */
bool cachefiles_begin_operation(struct netfs_cache_resources *cres,
				enum fscache_want_stage want_stage)
{
	struct cachefiles_object *object = cachefiles_cres_object(cres);

	if (!cachefiles_cres_file(cres)) {
		cres->ops = &cachefiles_netfs_cache_ops;
		if (object) {
			spin_lock(&object->lock);
			if (!cres->cache_priv2 && object->file)
				cres->cache_priv2 = get_file(object->file);
			spin_unlock(&object->lock);
		}
	}

	if (!cachefiles_cres_file(cres) && want_stage != FSCACHE_WANT_PARAMS) {
		pr_err("failed to get cres->file\n");
		return false;
	}

	return true;
}
