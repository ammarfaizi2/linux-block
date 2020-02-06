// SPDX-License-Identifier: GPL-2.0-or-later
/* Read helper.
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/fscache-cache.h>
#include "internal.h"

static void fscache_read_from_server(struct fscache_io_request *req)
{
	req->ops->issue_op(req);
}

/*
 * Deal with the completion of writing the data to the cache.  We have to clear
 * the PG_fscache bits on the pages involved and releases the caller's ref.
 */
static void fscache_read_copy_done(struct fscache_io_request *req)
{
	struct page *page;
	pgoff_t index = req->pos >> PAGE_SHIFT;
	pgoff_t last = index + req->nr_pages - 1;

	XA_STATE(xas, &req->mapping->i_pages, index);

	_enter("%lx,%x,%llx", index, req->nr_pages, req->transferred);

	if (req->error == 0)
		fscache_stat(&fscache_n_read_helper_copy_done);
	else
		fscache_stat(&fscache_n_read_helper_copy_failed);

	/* Clear PG_fscache on the pages that were being written out. */
	rcu_read_lock();
	xas_for_each(&xas, page, last) {
		BUG_ON(xa_is_value(page));
		BUG_ON(PageCompound(page));

		unlock_page_fscache(page);
	}
	rcu_read_unlock();

	if (test_bit(FSCACHE_COOKIE_WRITING_SINGLE, &req->cookie->flags)) {
		clear_bit_unlock(FSCACHE_COOKIE_WRITING_SINGLE, &req->cookie->flags);
		wake_up_bit(&req->cookie->flags, FSCACHE_COOKIE_WRITING_SINGLE);
	}
}

/*
 * Write a completed read request to the cache.
 */
static void fscache_do_read_copy_to_cache(struct work_struct *work)
{
	struct fscache_io_request *req =
		container_of(work, struct fscache_io_request, work);
	struct iov_iter iter;

	_enter("");

	fscache_stat(&fscache_n_read_helper_copy);

	iov_iter_mapping(&iter, WRITE, req->mapping, req->pos,
			 round_up(req->len, req->dio_block_size));

	req->io_done = fscache_read_copy_done;
	fscache_write(req, &iter);
	fscache_put_io_request(req);
}

static void fscache_read_copy_to_cache(struct fscache_io_request *req)
{
	fscache_get_io_request(req);

	if (!in_softirq())
		return fscache_do_read_copy_to_cache(&req->work);

	BUG_ON(work_pending(&req->work));
	INIT_WORK(&req->work, fscache_do_read_copy_to_cache);
	if (!queue_work(fscache_op_wq, &req->work))
		BUG();
}

/*
 * Clear the unread part of the file on a short read.
 */
static void fscache_clear_unread(struct fscache_io_request *req)
{
	struct iov_iter iter;

	iov_iter_mapping(&iter, WRITE, req->mapping,
			 req->pos + req->transferred,
			 req->len - req->transferred);

	_debug("clear %zx @%llx", iov_iter_count(&iter), iter.mapping_start);

	iov_iter_zero(iov_iter_count(&iter), &iter);
}

/*
 * Handle completion of a read operation.  This may be called in softirq
 * context.
 */
static void fscache_read_done(struct fscache_io_request *req)
{
	struct page *page;
	pgoff_t start = req->pos >> PAGE_SHIFT;
	pgoff_t last = start + req->nr_pages - 1;

	XA_STATE(xas, &req->mapping->i_pages, start);

	_enter("%lx,%x,%llx,%d",
	       start, req->nr_pages, req->transferred, req->error);

	if (req->error == 0)
		fscache_stat(&fscache_n_read_helper_read_done);
	else
		fscache_stat(&fscache_n_read_helper_read_failed);

	if (req->transferred < req->len)
		fscache_clear_unread(req);

	if (!test_bit(FSCACHE_IO_DONT_UNLOCK_PAGES, &req->flags)) {
		rcu_read_lock();
		xas_for_each(&xas, page, last) {
			if (req->write_to_cache)
				SetPageFsCache(page);
			if (page == req->no_unlock_page)
				SetPageUptodate(page);
			else
				page_endio(page, false, 0);
			put_page(page);
		}
		rcu_read_unlock();
	}

	task_io_account_read(req->transferred);
	req->ops->done(req);

	if (req->write_to_cache)
		fscache_read_copy_to_cache(req);
}

/*
 * Reissue the read against the server.
 */
static void fscache_reissue_read(struct work_struct *work)
{
	struct fscache_io_request *req =
		container_of(work, struct fscache_io_request, work);

	_debug("DOWNLOAD: %llu", req->len);

	req->io_done = fscache_read_done;
	fscache_read_from_server(req);
	fscache_put_io_request(req);
}

/*
 * Handle completion of a read from cache operation.  If the read failed, we
 * need to reissue the request against the server.  We might, however, be
 * called in softirq mode and need to punt.
 */
static void fscache_file_read_maybe_reissue(struct fscache_io_request *req)
{
	_enter("%d", req->error);

	if (req->error == 0) {
		fscache_read_done(req);
	} else {
		fscache_stat(&fscache_n_read_helper_reissue);
		INIT_WORK(&req->work, fscache_reissue_read);
		fscache_get_io_request(req);
		queue_work(fscache_op_wq, &req->work);
	}
}

/*
 * Issue a read against the cache.
 */
static void fscache_read_from_cache(struct fscache_io_request *req)
{
	struct iov_iter iter;

	iov_iter_mapping(&iter, READ, req->mapping, req->pos, req->len);
	fscache_read(req, &iter);
}

/*
 * Discard the locks and page refs that we obtained on a sequence of pages.
 */
static void fscache_ignore_pages(struct address_space *mapping,
				  pgoff_t start, pgoff_t end)
{
	struct page *page;

	_enter("%lx,%lx", start, end);

	if (end > start) {
		XA_STATE(xas, &mapping->i_pages, start);

		rcu_read_lock();
		xas_for_each(&xas, page, end - 1) {
			_debug("- ignore %lx", page->index);
			BUG_ON(xa_is_value(page));
			BUG_ON(PageCompound(page));

			unlock_page(page);
			put_page(page);
		}
		rcu_read_unlock();
	}
}

#define FSCACHE_RHLP_NOTE_READ_FROM_CACHE	FSCACHE_READ_FROM_CACHE
#define FSCACHE_RHLP_NOTE_WRITE_TO_CACHE	FSCACHE_WRITE_TO_CACHE
#define FSCACHE_RHLP_NOTE_FILL_WITH_ZERO	FSCACHE_FILL_WITH_ZERO
#define FSCACHE_RHLP_NOTE_READ_FOR_WRITE	0x000100 /* Type: FSCACHE_READ_FOR_WRITE */
#define FSCACHE_RHLP_NOTE_READ_LOCKED_PAGE	0x000200 /* Type: FSCACHE_READ_LOCKED_PAGE */
#define FSCACHE_RHLP_NOTE_READ_PAGE_LIST	0x000300 /* Type: FSCACHE_READ_PAGE_LIST */
#define FSCACHE_RHLP_NOTE_LIST_NOTCONTIG	0x001000 /* Page list: not contiguous */
#define FSCACHE_RHLP_NOTE_LIST_NOMEM		0x002000 /* Page list: ENOMEM */
#define FSCACHE_RHLP_NOTE_LIST_U2D		0x004000 /* Page list: page uptodate */
#define FSCACHE_RHLP_NOTE_LIST_ERROR		0x008000 /* Page list: add error */
#define FSCACHE_RHLP_NOTE_TRAILER_ADD		0x010000 /* Trailer: Creating */
#define FSCACHE_RHLP_NOTE_TRAILER_NOMEM		0x020000 /* Trailer: ENOMEM */
#define FSCACHE_RHLP_NOTE_TRAILER_U2D		0x040000 /* Trailer: Uptodate */
#define FSCACHE_RHLP_NOTE_U2D_IN_PREFACE	0x100000 /* Uptodate page in preface */
#define FSCACHE_RHLP_NOTE_UNDERSIZED		0x200000 /* Undersized block */
#define FSCACHE_RHLP_NOTE_AFTER_EOF		0x800000 /* After EOF */

/**
 * fscache_read_helper - Helper to manage a read request
 * @req: The initialised request structure to use
 * @extent: The extent of the pages to access
 * @requested_page: Singular page to include
 * @pages: Unattached pages to include (readpages)
 * @type: FSCACHE_READ_*
 * @aop_flags: AOP_FLAG_*
 *
 * Read a sequence of pages appropriately sized for an fscache allocation
 * block.  Pages are added at both ends and to fill in the gaps as appropriate
 * to make it the right size.
 *
 * req->mapping should indicate the mapping to which the pages will be attached.
 *
 * The operations pointed to by req->ops will be used to issue or reissue a
 * read against the server in case the cache is unavailable, incomplete or
 * generates an error.  req->iter will be set up to point to the iterator
 * representing the buffer to be filled in.
 *
 * A ref on @req is consumed eventually by this function or one of its
 * eventually-dispatched callees.
 */
int fscache_read_helper(struct fscache_io_request *req,
			struct fscache_extent *extent,
			struct page **requested_page,
			struct list_head *pages,
			enum fscache_read_type type,
			unsigned int aop_flags)
{
	struct address_space *mapping = req->mapping;
	struct page *page;
	enum fscache_read_helper_trace what;
	unsigned int notes;
	pgoff_t eof, cursor, start, first_index, trailer = ULONG_MAX;
	loff_t i_size;
	int ret;

	fscache_stat(&fscache_n_read_helper);

	first_index = extent->start;
	_enter("{%lx,%lx}", first_index, extent->limit);

	ASSERTIFCMP(requested_page && *requested_page,
		    (*requested_page)->index, ==, first_index);
	ASSERTIF(type == FSCACHE_READ_LOCKED_PAGE ||
		 type == FSCACHE_READ_FOR_WRITE,
		 pages == NULL);
	ASSERTIFCMP(pages && !list_empty(pages),
		    first_index, ==, lru_to_page(pages)->index);

	i_size = i_size_read(mapping->host);
	eof = (i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	notes = fscache_shape_extent(req->cookie, extent, i_size, false);
	req->dio_block_size = extent->dio_block_size;

	start = cursor = extent->start;

	/* Add pages to the pagecache.  We keep the pages ref'd and locked
	 * until the read is complete.  We may also need to add pages to both
	 * sides of the request to make it up to the cache allocation granule
	 * alignment and size.
	 *
	 * Note that it's possible for the file size to change whilst we're
	 * doing this, but we rely on the server returning less than we asked
	 * for if the file shrank.  We also rely on this to deal with a partial
	 * page at the end of the file.
	 *
	 * If we're going to end up loading from the server and writing to the
	 * cache, we start by inserting blank pages before the first page being
	 * examined.  If we can fetch from the cache or we're not going to
	 * write to the cache, it's unnecessary.
	 */
	if (notes & FSCACHE_RHLP_NOTE_WRITE_TO_CACHE) {
		req->write_to_cache = true;
		while (cursor < first_index) {
			page = find_or_create_page(mapping, cursor,
						   readahead_gfp_mask(mapping));
			if (!page) {
				fscache_stat(&fscache_n_read_helper_stop_nomem);
				goto nomem;
			}
			if (!PageUptodate(page)) {
				req->nr_pages++; /* Add to the reading list */
				cursor++;
				continue;
			}

			/* There's an up-to-date page in the preface - just
			 * fetch the requested pages and skip saving to the
			 * cache.
			 */
			notes |= FSCACHE_RHLP_NOTE_U2D_IN_PREFACE;
			fscache_stat(&fscache_n_read_helper_stop_uptodate);
			fscache_ignore_pages(mapping, extent->start, cursor + 1);
			req->write_to_cache = false;
			start = cursor = first_index;
			req->nr_pages = 0;
			break;
		}
		page = NULL;
	}

	switch (type) {
	case FSCACHE_READ_FOR_WRITE:
		/* We're doing a prefetch for a write on a single page.  We get
		 * or create the requested page if we weren't given it and lock
		 * it.
		 */
		notes |= FSCACHE_RHLP_NOTE_READ_FOR_WRITE;
		if (*requested_page) {
			_debug("prewrite req %lx", cursor);
			page = *requested_page;
			ret = -ERESTARTSYS;
			if (lock_page_killable(page) < 0) {
				fscache_stat(&fscache_n_read_helper_stop_kill);
				goto dont;
			}
		} else {
			_debug("prewrite new %lx %lx", cursor, eof);
			page = grab_cache_page_write_begin(mapping, first_index,
							   aop_flags);
			if (!page) {
				fscache_stat(&fscache_n_read_helper_stop_nomem);
				goto nomem;
			}
			*requested_page = page;
		}
		get_page(page);
		req->no_unlock_page = page;
		req->nr_pages++;
		cursor++;
		page = NULL;
		ret = 0;
		break;

	case FSCACHE_READ_LOCKED_PAGE:
		/* We've got a single page preattached to the inode and locked.
		 * Get our own ref on it.
		 */
		_debug("locked");
		notes |= FSCACHE_RHLP_NOTE_READ_LOCKED_PAGE;
		get_page(*requested_page);
		req->nr_pages++;
		cursor++;
		ret = 0;
		break;

	case FSCACHE_READ_PAGE_LIST:
		/* We've been given a contiguous list of pages to add. */
		notes |= FSCACHE_RHLP_NOTE_READ_PAGE_LIST;
		do {
			_debug("given %lx", cursor);

			page = lru_to_page(pages);
			if (page->index != cursor) {
				notes |= FSCACHE_RHLP_NOTE_LIST_NOTCONTIG;
				fscache_stat(&fscache_n_read_helper_stop_noncontig);
				break;
			}

			list_del(&page->lru);

			ret = add_to_page_cache_lru(page, mapping, cursor,
						    readahead_gfp_mask(mapping));
			switch (ret) {
			case 0:
				/* Add to the reading list */
				req->nr_pages++;
				cursor++;
				page = NULL;
				break;

			case -EEXIST:
				put_page(page);

				_debug("conflict %lx %d", cursor, ret);
				page = find_or_create_page(mapping, cursor,
							   readahead_gfp_mask(mapping));
				if (!page) {
					notes |= FSCACHE_RHLP_NOTE_LIST_NOMEM;
					fscache_stat(&fscache_n_read_helper_stop_nomem);
					goto stop;
				}

				if (PageUptodate(page)) {
					unlock_page(page);
					put_page(page); /* Avoid overwriting */
					fscache_stat(&fscache_n_read_helper_stop_exist);
					ret = 0;
					notes |= FSCACHE_RHLP_NOTE_LIST_U2D;
					goto stop;
				}

				req->nr_pages++; /* Add to the reading list */
				cursor++;
				break;

			default:
				_debug("add fail %lx %d", cursor, ret);
				put_page(page);
				fscache_stat(&fscache_n_read_helper_stop_nomem);
				page = NULL;
				notes |= FSCACHE_RHLP_NOTE_LIST_ERROR;
				goto stop;
			}

			/* Trim the fetch to the cache granularity so we don't
			 * get a chain-failure of blocks being unable to be
			 * used because the previous uncached read spilt over.
			 */
			if ((notes & FSCACHE_RHLP_NOTE_U2D_IN_PREFACE) &&
			    cursor == extent->block_end)
				break;

		} while (!list_empty(pages) && cursor < extent->limit);
		ret = 0;
		break;

	default:
		BUG();
	}

	/* If we're going to be writing to the cache, insert pages after the
	 * requested block to make up the numbers.
	 */
	if (req->write_to_cache) {
		notes |= FSCACHE_RHLP_NOTE_TRAILER_ADD;
		trailer = cursor;
		while (cursor < extent->limit) {
			_debug("after %lx", cursor);
			page = find_or_create_page(mapping, cursor,
						   readahead_gfp_mask(mapping));
			if (!page) {
				notes |= FSCACHE_RHLP_NOTE_TRAILER_NOMEM;
				fscache_stat(&fscache_n_read_helper_stop_nomem);
				goto stop;
			}
			if (PageUptodate(page)) {
				unlock_page(page);
				put_page(page); /* Avoid overwriting */
				notes |= FSCACHE_RHLP_NOTE_TRAILER_U2D;
				fscache_stat(&fscache_n_read_helper_stop_uptodate);
				goto stop;
			}

			req->nr_pages++; /* Add to the reading list */
			cursor++;
		}
	}

stop:
	_debug("have %u", req->nr_pages);
	if (req->nr_pages == 0)
		goto dont;

	if (cursor <= first_index) {
		_debug("v.short");
		ret = -ENOMEM;
		goto dont; /* We wouldn't've included the first page */
	}

submit_anyway:
	if (cursor < extent->block_end) {
		/* The request is short of what we need to be able to cache the
		 * minimum cache block so discard the trailer.
		 */
		_debug("short");
		notes |= FSCACHE_RHLP_NOTE_UNDERSIZED;
		req->write_to_cache = false;
		if (trailer != ULONG_MAX) {
			fscache_ignore_pages(mapping, trailer, cursor);
			req->nr_pages -= cursor - trailer;
		}
	}

	req->len = req->nr_pages * PAGE_SIZE;
	req->pos = start;
	req->pos <<= PAGE_SHIFT;

	if (start >= eof) {
		notes |= FSCACHE_RHLP_NOTE_AFTER_EOF;
		what = fscache_read_helper_skip;
	} else if (notes & FSCACHE_RHLP_NOTE_FILL_WITH_ZERO) {
		what = fscache_read_helper_zero;
	} else if (notes & FSCACHE_RHLP_NOTE_READ_FROM_CACHE) {
		what = fscache_read_helper_read;
	} else {
		what = fscache_read_helper_download;
	}

	trace_fscache_read_helper(req->cookie, start, start + req->nr_pages,
				  notes, what);

	switch (what) {
	case fscache_read_helper_skip:
		/* The read is entirely beyond the end of the file, so skip the
		 * actual operation and let the done handler deal with clearing
		 * the pages.
		 */
		_debug("SKIP READ: %llu", req->len);
		fscache_stat(&fscache_n_read_helper_beyond_eof);
		fscache_read_done(req);
		break;
	case fscache_read_helper_zero:
		_debug("ZERO READ: %llu", req->len);
		fscache_stat(&fscache_n_read_helper_zero);
		fscache_read_done(req);
		break;
	case fscache_read_helper_read:
		fscache_stat(&fscache_n_read_helper_read);
		req->io_done = fscache_file_read_maybe_reissue;
		fscache_read_from_cache(req);
		break;
	case fscache_read_helper_download:
		_debug("DOWNLOAD: %llu", req->len);
		fscache_stat(&fscache_n_read_helper_download);
		req->io_done = fscache_read_done;
		fscache_read_from_server(req);
		break;
	default:
		BUG();
	}

	_leave(" = 0");
	return 0;

nomem:
	if (cursor > first_index)
		goto submit_anyway;
	fscache_ignore_pages(mapping, extent->start, cursor);
	ret = -ENOMEM;
dont:
	_leave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(fscache_read_helper);

/**
 * fscache_read_helper_single - Helper for reading single-chunk object
 * @req: The request
 * @check: Function to check the content of a download
 *
 * Helper to synchronously read a single-chunk object into the pages
 * pre-attached to a mapping.  The caller is responsible for appropriately
 * locking them to make sure they don't evaporate under us.
 *
 * If data is downloaded, then, if given, the check function will be called to
 * check the contents before we write it to the cache.
 *
 * A ref on @req is consumed eventually by this function or one of its
 * eventually-dispatched callees.
 */
int fscache_read_helper_single(struct fscache_io_request *req,
			       int (*check)(struct fscache_io_request *req))
{
	struct fscache_extent extent;
	unsigned int notes = 0;
	loff_t i_size = req->len;
	int ret = 0;

	extent.start = 0;
	extent.block_end = req->nr_pages;
	extent.limit = req->nr_pages;

	if (req->cookie) {
		notes = fscache_shape_extent(req->cookie, &extent, i_size, false);
		req->dio_block_size = extent.dio_block_size;

		_enter("c=%08x,%x", req->cookie->debug_id, notes);

		if (wait_on_bit(&req->cookie->flags, FSCACHE_COOKIE_WRITING_SINGLE,
				TASK_INTERRUPTIBLE) < 0) {
			ret = -ERESTARTSYS;
			goto out;
		}

		if (notes & FSCACHE_RHLP_NOTE_READ_FROM_CACHE) {
			struct iov_iter iter;

			trace_fscache_read_helper(req->cookie, 0, req->nr_pages,
						  notes, fscache_read_helper_single_read);

			iov_iter_mapping(&iter, READ, req->mapping, 0,
					 round_up(i_size, req->dio_block_size));
			req->io_done = NULL; /* Synchronous */
			fscache_stat(&fscache_n_read_helper_read);
			ret = fscache_read(req, &iter);
			if (ret == 0 && req->transferred >= i_size) {
				req->transferred = i_size;
				task_io_account_read(req->transferred);
				fscache_read_done(req);
				goto out;
			}

			if (ret < 0 && ret != -ENODATA)
				goto out;

			_debug("inval d %d", ret);
			__fscache_invalidate(req->cookie, i_size, 0);
		}

		if (notes & FSCACHE_RHLP_NOTE_WRITE_TO_CACHE)
			req->write_to_cache = true;
	}

	trace_fscache_read_helper(req->cookie, 0, req->nr_pages,
				  notes, fscache_read_helper_single_download);

	fscache_stat(&fscache_n_read_helper_download);
	fscache_read_from_server(req);
	ret = req->error;
	if (ret == 0) {
		task_io_account_read(req->transferred);
		if (check) {
			ret = check(req);
			if (ret < 0)
				goto out;
		}
		fscache_read_done(req);
	}

out:
	return ret;
}
EXPORT_SYMBOL(fscache_read_helper_single);
