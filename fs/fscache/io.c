// SPDX-License-Identifier: GPL-2.0-or-later
/* Data I/O routines
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
#include <linux/module.h>
#include <linux/fscache-cache.h>
#include <linux/slab.h>
#include <linux/netfs.h>
#include <linux/uio.h>
#include "internal.h"

/*
 * Wait for a cookie to reach the specified stage.
 */
void __fscache_wait_for_operation(struct fscache_op_resources *opr,
				  enum fscache_want_stage want_stage)
{
	struct fscache_cookie *cookie = opr->object->cookie;
	enum fscache_cookie_stage stage;

again:
	stage = READ_ONCE(cookie->stage);
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want_stage);

	if (fscache_cache_is_broken(opr->object)) {
		_leave(" [broken]");
		return;
	}

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_INITIALISING:
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		wait_var_event(&cookie->stage, READ_ONCE(cookie->stage) != stage);
		goto again;

	case FSCACHE_COOKIE_STAGE_NO_DATA_YET:
	case FSCACHE_COOKIE_STAGE_ACTIVE:
		return;
	case FSCACHE_COOKIE_STAGE_INDEX:
	case FSCACHE_COOKIE_STAGE_DROPPED:
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
	default:
		_leave(" [not live]");
		return;
	}
}
EXPORT_SYMBOL(__fscache_wait_for_operation);

/*
 * Release the resources needed by an operation.
 */
void __fscache_end_operation(struct fscache_op_resources *opr)
{
	struct fscache_object *object = opr->object;

	fscache_uncount_io_operation(object->cookie);
	object->cache->ops->put_object(object, fscache_obj_put_ioreq);
}
EXPORT_SYMBOL(__fscache_end_operation);

/*
 * Begin an I/O operation on the cache, waiting till we reach the right state.
 *
 * Attaches the resources required to the operation resources record.
 */
int __fscache_begin_operation(struct fscache_cookie *cookie,
			      struct fscache_op_resources *opr,
			      enum fscache_want_stage want_stage)
{
	struct fscache_object *object;
	enum fscache_cookie_stage stage;
	long timeo;
	bool once_only = false;

again:
	spin_lock(&cookie->lock);

	stage = cookie->stage;
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want_stage);

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_INITIALISING:
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		goto wait_and_validate;

	case FSCACHE_COOKIE_STAGE_NO_DATA_YET:
		if (want_stage == FSCACHE_WANT_READ)
			goto no_data_yet;
		fallthrough;
	case FSCACHE_COOKIE_STAGE_ACTIVE:
		goto ready;
	case FSCACHE_COOKIE_STAGE_INDEX:
	case FSCACHE_COOKIE_STAGE_DROPPED:
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
		WARN(1, "Can't use cookie in stage %u\n", cookie->stage);
		goto not_live;
	default:
		goto not_live;
	}

ready:
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	if (fscache_cache_is_broken(object))
		goto not_live;

	opr->object = object;
	opr->inval_counter = object->inval_counter;
	object->cache->ops->grab_object(object, fscache_obj_get_ioreq);
	object->cache->ops->begin_operation(opr);

	fscache_count_io_operation(cookie);
	spin_unlock(&cookie->lock);
	return 0;

wait_and_validate:
	spin_unlock(&cookie->lock);
	timeo = wait_var_event_timeout(&cookie->stage,
				       READ_ONCE(cookie->stage) != stage, 20 * HZ);
	if (timeo <= 1 && !once_only) {
		pr_warn("%s: cookie stage change wait timed out: cookie->stage=%u stage=%u",
			__func__, READ_ONCE(cookie->stage), stage);
		fscache_print_cookie(cookie, 'O');
		once_only = true;
	}
	goto again;

no_data_yet:
	spin_unlock(&cookie->lock);
	opr->object = NULL;
	_leave(" = -ENODATA");
	return -ENODATA;

not_live:
	spin_unlock(&cookie->lock);
	opr->object = NULL;
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_begin_operation);

/**
 * fscache_set_page_dirty - Mark page dirty and pin a cache object for writeback
 * @page: The page being dirtied
 * @cookie: The cookie referring to the cache object
 *
 * Set the dirty flag on a page and pin an in-use cache object in memory when
 * dirtying a page so that writeback can later write to it.  This is intended
 * to be called from the filesystem's ->set_page_dirty() method.
 *
 *  Returns 1 if PG_dirty was set on the page, 0 otherwise.
 */
int fscache_set_page_dirty(struct page *page, struct fscache_cookie *cookie)
{
	struct inode *inode = page->mapping->host;
	bool need_use = false;

	_enter("");

	if (!__set_page_dirty_nobuffers(page))
		return 0;
	if (!fscache_cookie_valid(cookie))
		return 1;

	if (!(inode->i_state & I_PINNING_FSCACHE_WB)) {
		spin_lock(&inode->i_lock);
		if (!(inode->i_state & I_PINNING_FSCACHE_WB)) {
			inode->i_state |= I_PINNING_FSCACHE_WB;
			need_use = true;
		}
		spin_unlock(&inode->i_lock);

		if (need_use)
			fscache_use_cookie(cookie, true);
	}
	return 1;
}
EXPORT_SYMBOL(fscache_set_page_dirty);

/**
 * fscache_put_super - Wait for outstanding ops to complete
 * @sb: The superblock to wait on
 * @get_cookie: Function to get the cookie on an inode
 *
 * Wait for outstanding cache operations on the inodes of a superblock to
 * complete as they might be pinning an inode.  This is designed to be called
 * from ->put_super(), right before the "VFS: Busy inodes" check.
 */
void fscache_put_super(struct super_block *sb,
		       struct fscache_cookie *(*get_cookie)(struct inode *inode))
{
	struct fscache_cookie *cookie;
	struct inode *inode, *p;

	while (!list_empty(&sb->s_inodes)) {
		/* Find the first inode that we need to wait on */
		inode = NULL;
		cookie = NULL;
		spin_lock(&sb->s_inode_list_lock);
		list_for_each_entry(p, &sb->s_inodes, i_sb_list) {
			if (atomic_inc_not_zero(&p->i_count)) {
				inode = p;
				cookie = get_cookie(inode);
				if (!cookie) {
					iput(inode);
					inode = NULL;
					cookie = NULL;
					continue;
				}
				break;
			}
		}
		spin_unlock(&sb->s_inode_list_lock);

		if (inode) {
			/* n_ops is kept artificially raised to stop wakeups */
			atomic_dec(&cookie->n_ops);
			wait_var_event(&cookie->n_ops, atomic_read(&cookie->n_ops) == 0);
			atomic_inc(&cookie->n_ops);
			iput(inode);
		}

		evict_inodes(sb);
		if (!inode)
			break;
	}
}
EXPORT_SYMBOL(fscache_put_super);

/*
 * Change the size of a backing object.
 */
void __fscache_resize_cookie(struct fscache_cookie *cookie, loff_t new_size)
{
	struct fscache_op_resources opr;

	ASSERT(cookie->type != FSCACHE_COOKIE_TYPE_INDEX);

	trace_fscache_resize(cookie, new_size);
	if (fscache_begin_operation(cookie, &opr, FSCACHE_WANT_WRITE) != -ENOBUFS) {
		struct fscache_object *object = opr.object;

		fscache_stat(&fscache_n_resizes);
		set_bit(FSCACHE_OBJECT_NEEDS_UPDATE, &object->flags);

		/* We cannot defer a resize as we need to do it inside the
		 * netfs's inode lock so that we're serialised with respect to
		 * writes.
		 */
		object->cache->ops->resize_object(object, new_size);
		fscache_end_operation(&opr);
	} else {
		fscache_stat(&fscache_n_resizes_null);
	}
}
EXPORT_SYMBOL(__fscache_resize_cookie);

struct fscache_write_request {
	struct fscache_op_resources cache_resources;
	struct address_space	*mapping;
	loff_t			start;
	size_t			len;
	fscache_io_terminated_t	term_func;
	void			*term_func_priv;
};

/**
 * fscache_clear_page_bits - Clear the PG_fscache bits from a set of pages
 * @mapping: The netfs inode to use as the source
 * @start: The start position in @mapping
 * @len: The amount of data to unlock
 *
 * Clear the PG_fscache flag from a sequence of pages and wake up anyone who's
 * waiting.
 */
void __fscache_clear_page_bits(struct address_space *mapping,
			       loff_t start, size_t len)
{
	pgoff_t first = start / PAGE_SIZE;
	pgoff_t last = (start + len - 1) / PAGE_SIZE;
	struct page *page;

	if (len) {
		XA_STATE(xas, &mapping->i_pages, first);

		rcu_read_lock();
		xas_for_each(&xas, page, last) {
			unlock_page_fscache(page);
		}
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(__fscache_clear_page_bits);

/*
 * Deal with the completion of writing the data to the cache.
 */
static void fscache_wreq_done(void *priv, ssize_t transferred_or_error)
{
	struct fscache_write_request *wreq = priv;

	fscache_clear_page_bits(wreq->mapping, wreq->start, wreq->len);

	if (wreq->term_func)
		wreq->term_func(wreq->term_func_priv, transferred_or_error);
	fscache_end_operation(&wreq->cache_resources);
	kfree(wreq);
}

/**
 * fscache_write_to_cache - Save a write to the cache and clear PG_fscache
 * @cookie: The cookie representing the cache object
 * @mapping: The netfs inode to use as the source
 * @start: The start position in @mapping
 * @len: The amount of data to write back
 * @i_size: The new size of the inode
 * @term_func: The function to call upon completion
 * @term_func_priv: The private data for @term_func
 *
 * Helper function for a netfs to write dirty data from an inode into the cache
 * object that's backing it.
 *
 * @start and @len describe the range of the data.  This does not need to be
 * page-aligned, but to satisfy DIO requirements, the cache may expand it up to
 * the page boundaries on either end.  All the pages covering the range must be
 * marked with PG_fscache.
 *
 * If given, @term_func will be called upon completion and supplied with
 * @term_func_priv.  Note that the PG_fscache flags will have been cleared by
 * this point, so the netfs must retain its own pin on the mapping.
 */
void __fscache_write_to_cache(struct fscache_cookie *cookie,
			      struct address_space *mapping,
			      loff_t start, size_t len, loff_t i_size,
			      fscache_io_terminated_t term_func,
			      void *term_func_priv)
{
	struct fscache_write_request *wreq;
	struct fscache_op_resources *opr;
	struct iov_iter iter;
	int ret = -ENOBUFS;

	if (!fscache_cookie_valid(cookie) || len == 0)
		goto abandon;

	_enter("%llx,%zx", start, len);

	wreq = kzalloc(sizeof(struct fscache_write_request), GFP_NOFS);
	if (!wreq)
		goto abandon;
	wreq->mapping		= mapping;
	wreq->start		= start;
	wreq->len		= len;
	wreq->term_func		= term_func;
	wreq->term_func_priv	= term_func_priv;

	opr = &wreq->cache_resources;
	if (fscache_begin_operation(cookie, opr, FSCACHE_WANT_WRITE) < 0)
		goto abandon_free;

	ret = opr->ops->prepare_write(opr, &start, &len, i_size);
	if (ret < 0)
		goto abandon_end;

	/* TODO: Consider clearing page bits now for space the write isn't
	 * covering.  This is more complicated than it appears when THPs are
	 * taken into account.
	 */

	iov_iter_xarray(&iter, WRITE, &mapping->i_pages, start, len);
	fscache_write(opr, start, &iter, fscache_wreq_done, wreq);
	return;

abandon_end:
	return fscache_wreq_done(wreq, ret);
abandon_free:
	kfree(wreq);
abandon:
	fscache_clear_page_bits(mapping, start, len);
	if (term_func)
		term_func(term_func_priv, ret);
}
EXPORT_SYMBOL(__fscache_write_to_cache);
