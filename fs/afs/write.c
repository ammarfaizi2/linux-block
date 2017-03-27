/* handling of writes to regular files and writing back to the server
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/backing-dev.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include "internal.h"

static int afs_write_back_from_locked_page(struct afs_vnode *vnode,
					   struct afs_writeback *wb,
					   struct page *page);
static int afs_sync_data(struct afs_vnode *vnode, loff_t start, loff_t end,
			 enum afs_writeback_trace why);

/*
 * mark a page as having been made dirty and thus needing writeback
 */
int afs_set_page_dirty(struct page *page)
{
	_enter("");
	return __set_page_dirty_nobuffers(page);
}

/*
 * Allocate a writeback record.
 */
static struct afs_writeback *afs_alloc_writeback(struct afs_vnode *vnode,
						 struct key *key,
						 pgoff_t index,
						 unsigned int from,
						 unsigned int to)
{
	struct afs_writeback *wb;

	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (wb) {
		wb->first	= wb->last = index;
		wb->offset_first = from;
		wb->to_last	= to;
		wb->state	= AFS_WBACK_PENDING;
		wb->key		= key;
		atomic_set(&wb->usage, 1);
		INIT_LIST_HEAD(&wb->link);
		init_waitqueue_head(&wb->waitq);
		trace_afs_writeback(vnode, wb, afs_writeback_trace_alloc, 1, 1);
	}

	_leave(" = %p", wb);
	return wb;
}

/*
 * Get a reference on a writeback record.
 */
struct afs_writeback *afs_get_writeback(struct afs_vnode *vnode,
					struct afs_writeback *wb,
					enum afs_writeback_trace why)
{
	int n;

	if (wb) {
		n = atomic_inc_return(&wb->usage);
		trace_afs_writeback(vnode, wb, why, n, 1);
	}

	return wb;
}

/*
 * Discard a reference to a writeback record.
 */
void afs_put_writeback(struct afs_vnode *vnode, struct afs_writeback *wb,
		       unsigned delta)
{
	int n;

	if (wb && delta) {
		n = atomic_sub_return(delta, &wb->usage);
		trace_afs_writeback(vnode, wb, afs_writeback_trace_put, n, -delta);
		ASSERTCMP(n, >=, 0);
		if (n == 0) {
			key_put(wb->key);
			kfree(wb);
		}
	}
}

/*
 * Unlink a writeback record because the number of pages it covers has reached
 * zero.
 *
 * Must be called with the vnode->writeback_lock held.
 */
static void afs_unlink_writeback(struct afs_vnode *vnode,
				 struct afs_writeback *wb)
{
	struct afs_writeback *front;

	trace_afs_writeback(vnode, wb, afs_writeback_trace_unlink,
			    atomic_read(&wb->usage), 0);
	list_del_init(&wb->link);

	while (!list_empty(&vnode->writebacks)) {
		/* Remove and wake up any syncs that rise to the front. */
		front = list_entry(vnode->writebacks.next,
				   struct afs_writeback, link);
		_debug("front %p %u", front, front->state);
		if (front->state != AFS_WBACK_SYNCING) {
			trace_afs_writeback(vnode, front,
					    afs_writeback_trace_no_wake,
					    atomic_read(&front->usage), 0);
			break;
		}
		trace_afs_writeback(vnode, front, afs_writeback_trace_wake,
				    atomic_read(&front->usage), 0);
		list_del_init(&front->link);
		front->state = AFS_WBACK_COMPLETE;
		wake_up(&front->waitq);
		afs_put_writeback(vnode, front, 1);
	}
}

/*
 * Remove a page from a writeback record.  Returns true if we managed to clear
 * the page and false if the record is still attached because the page is
 * undergoing writeback.
 */
static bool __afs_writeback_remove_page(struct afs_vnode *vnode,
					struct afs_writeback *wb,
					struct page *page,
					unsigned *_delta)
{
	bool cleared = true;

	if (wb && !PageWriteback(page)) {
		set_page_private(page, 0);
		ASSERTCMP(wb->nr_pages, >, 0);
		wb->nr_pages--;
		if (wb->first == page->index) {
			wb->first++;
			wb->offset_first = 0;
		}
		*_delta += 1;
		if (wb->nr_pages == 0) {
			afs_unlink_writeback(vnode, wb);
			*_delta += 1;
		}
	}

	cleared = !page_private(page);
	if (cleared)
		ClearPagePrivate(page);

	return cleared;
}

bool afs_writeback_remove_page(struct afs_vnode *vnode,
			       struct afs_writeback *wb, struct page *page)
{
	unsigned delta = 0;
	bool cleared = true;

	if (PagePrivate(page)) {
		spin_lock(&vnode->writeback_lock);
		cleared = __afs_writeback_remove_page(vnode, wb, page, &delta);
		spin_unlock(&vnode->writeback_lock);
		afs_put_writeback(vnode, wb, delta);
	}

	return cleared;
}

/*
 * partly or wholly fill a page that's under preparation for writing
 */
static int afs_fill_page(struct afs_vnode *vnode, struct key *key,
			 loff_t pos, unsigned int len, struct page *page)
{
	struct afs_read *req;
	int ret;

	_enter(",,%llu", (unsigned long long)pos);

	req = kzalloc(sizeof(struct afs_read) + sizeof(struct page *),
		      GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	atomic_set(&req->usage, 1);
	req->pos = pos;
	req->len = len;
	req->nr_pages = 1;
	req->pages[0] = page;
	get_page(page);

	ret = afs_vnode_fetch_data(vnode, key, req);
	afs_put_read(req);
	if (ret < 0) {
		if (ret == -ENOENT) {
			_debug("got NOENT from server"
			       " - marking file deleted and stale");
			set_bit(AFS_VNODE_DELETED, &vnode->flags);
			ret = -ESTALE;
		}
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * Make a note that a page will require writing back.
 *
 * The writeback is used or discarded unless we return -EAGAIN, in which case
 * the page has been unlocked and we should be called again.
 */
static int afs_add_writeback(struct afs_vnode *vnode,
			     struct afs_writeback *candidate,
			     struct page *page)
{
	struct afs_writeback *wb;
	unsigned int from, to;
	pgoff_t index;

	_enter("");

	spin_lock(&vnode->writeback_lock);
	index = page->index;
	from = candidate->offset_first;
	to = candidate->to_last;

	/* See if this page is already pending a writeback under a suitable key
	 * - if so we can just join onto that one.
	 */
	wb = (struct afs_writeback *)page_private(page);
	if (wb) {
		if (wb->key == candidate->key &&
		    wb->state == AFS_WBACK_PENDING)
			goto subsume_in_current_wb;
		goto flush_conflicting_wb;
	}

	if (index > 0) {
		/* See if we can find an already pending writeback that we can
		 * append this page to.
		 */
		list_for_each_entry(wb, &vnode->writebacks, link) {
			if (wb->last == index - 1 &&
			    wb->key == candidate->key &&
			    wb->state == AFS_WBACK_PENDING)
				goto append_to_previous_wb;
		}
	}

	afs_get_writeback(vnode, candidate, afs_writeback_trace_new);
	key_get(candidate->key);
	list_add_tail(&candidate->link, &vnode->writebacks);
	candidate->nr_pages++;
	SetPagePrivate(page);
	set_page_private(page, (unsigned long)candidate);

	spin_unlock(&vnode->writeback_lock);
	_leave(" = 0 [new]");
	return 0;

subsume_in_current_wb:
	_debug("subsume");
	ASSERTRANGE(wb->first, <=, index, <=, wb->last);
	if (index == wb->first && from < wb->offset_first)
		wb->offset_first = from;
	if (index == wb->last && to > wb->to_last)
		wb->to_last = to;
	trace_afs_writeback(vnode, wb, afs_writeback_trace_subsume,
			    atomic_read(&wb->usage), 0);
	spin_unlock(&vnode->writeback_lock);
	trace_afs_writeback(vnode, candidate, afs_writeback_trace_discard, 0, 0);
	kfree(candidate);
	_leave(" = 0 [sub]");
	return 0;

append_to_previous_wb:
	_debug("append into %lx-%lx", wb->first, wb->last);
	wb->last++;
	wb->to_last = to;
	wb->nr_pages++;
	afs_get_writeback(vnode, wb, afs_writeback_trace_append);
	SetPagePrivate(page);
	set_page_private(page, (unsigned long)wb);

	spin_unlock(&vnode->writeback_lock);
	trace_afs_writeback(vnode, candidate, afs_writeback_trace_discard, 0, 0);
	kfree(candidate);
	_leave(" = 0 [app]");
	return 0;

	/* The page is currently bound to another context, so if it's dirty we
	 * need to flush it before we can use the new context.
	 */
flush_conflicting_wb:
	_debug("flush conflict");
	afs_get_writeback(vnode, wb, afs_writeback_trace_conflict);
	if (wb->state == AFS_WBACK_PENDING)
		wb->state = AFS_WBACK_CONFLICTING;
	spin_unlock(&vnode->writeback_lock);
	unlock_page(page);
	put_page(page);

	afs_sync_data(vnode,
		      ((loff_t)wb->first << PAGE_SHIFT) + wb->offset_first,
		      ((loff_t)wb->last << PAGE_SHIFT) + wb->to_last,
		      afs_writeback_trace_fsync);
	return -EAGAIN;
}

/*
 * prepare to perform part of a write to a page
 */
int afs_write_begin(struct file *file, struct address_space *mapping,
		    loff_t pos, unsigned len, unsigned flags,
		    struct page **pagep, void **fsdata)
{
	struct afs_writeback *candidate;
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct page *page;
	struct key *key = file->private_data;
	unsigned from = pos & (PAGE_SIZE - 1);
	unsigned to = from + len;
	pgoff_t index = pos >> PAGE_SHIFT;
	int ret;

	_enter("{%x:%u},{%lx},%u,%u",
	       vnode->fid.vid, vnode->fid.vnode, index, from, to);

	trace_afs_write_begin(vnode, index, from, to, flags);

	candidate = afs_alloc_writeback(vnode, key, index, from, to);
	if (!candidate)
		return -ENOMEM;

retry:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		kfree(candidate);
		return -ENOMEM;
	}

	if (!PageUptodate(page) && len != PAGE_SIZE) {
		ret = afs_fill_page(vnode, key, pos & PAGE_MASK, PAGE_SIZE, page);
		if (ret < 0) {
			unlock_page(page);
			put_page(page);
			kfree(candidate);
			_leave(" = %d [prep]", ret);
			return ret;
		}
		SetPageUptodate(page);
	}

	/* page won't leak in error case: it eventually gets cleaned off LRU */
	*pagep = page;

	ret = afs_add_writeback(vnode, candidate, page);
	if (ret == -EAGAIN)
		goto retry;
	return ret;
}

/*
 * finalise part of a write to a page
 */
int afs_write_end(struct file *file, struct address_space *mapping,
		  loff_t pos, unsigned len, unsigned copied,
		  struct page *page, void *fsdata)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct key *key = file->private_data;
	loff_t i_size, maybe_i_size;
	int ret;

	_enter("{%x:%u},{%lx}",
	       vnode->fid.vid, vnode->fid.vnode, page->index);

	maybe_i_size = pos + copied;

	i_size = i_size_read(&vnode->vfs_inode);
	if (maybe_i_size > i_size) {
		spin_lock(&vnode->writeback_lock);
		i_size = i_size_read(&vnode->vfs_inode);
		if (maybe_i_size > i_size)
			i_size_write(&vnode->vfs_inode, maybe_i_size);
		spin_unlock(&vnode->writeback_lock);
	}

	if (!PageUptodate(page)) {
		if (copied < len) {
			/* Try and load any missing data from the server.  The
			 * unmarshalling routine will take care of clearing any
			 * bits that are beyond the EOF.
			 */
			ret = afs_fill_page(vnode, key, pos + copied,
					    len - copied, page);
			if (ret < 0)
				return ret;
		}
		SetPageUptodate(page);
	}

	set_page_dirty(page);
	if (PageDirty(page))
		_debug("dirtied");
	unlock_page(page);
	put_page(page);

	return copied;
}

/*
 * kill all the pages in the given range
 */
static void afs_kill_pages(struct afs_vnode *vnode, bool error,
			   pgoff_t first, pgoff_t last)
{
	struct pagevec pv;
	unsigned count, loop;

	_enter("{%x:%u},%lx-%lx",
	       vnode->fid.vid, vnode->fid.vnode, first, last);

	pagevec_init(&pv, 0);

	do {
		_debug("kill %lx-%lx", first, last);

		count = last - first + 1;
		if (count > PAGEVEC_SIZE)
			count = PAGEVEC_SIZE;
		pv.nr = find_get_pages_contig(vnode->vfs_inode.i_mapping,
					      first, count, pv.pages);
		ASSERTCMP(pv.nr, ==, count);

		for (loop = 0; loop < count; loop++) {
			struct page *page = pv.pages[loop];
			ClearPageUptodate(page);
			if (error)
				SetPageError(page);
			if (PageWriteback(page))
				end_page_writeback(page);
			if (page->index >= first)
				first = page->index + 1;
		}

		__pagevec_release(&pv);
	} while (first < last);

	_leave("");
}

/*
 * synchronously write back the locked page and any subsequent non-locked dirty
 * pages also covered by the same writeback record
 */
static int afs_write_back_from_locked_page(struct afs_vnode *vnode,
					   struct afs_writeback *wb,
					   struct page *primary_page)
{
	struct page *pages[8], *page;
	unsigned long count;
	unsigned n, offset, to;
	pgoff_t start, first, last;
	int loop, ret;

	_enter(",%lx", primary_page->index);

	trace_afs_writeback(vnode, wb, afs_writeback_trace_write,
			    atomic_read(&wb->usage), 0);

	count = 1;
	if (test_set_page_writeback(primary_page))
		BUG();

	/* find all consecutive lockable dirty pages, stopping when we find a
	 * page that is not immediately lockable, is not dirty or is missing,
	 * or we reach the end of the range */
	start = primary_page->index;
	if (start >= wb->last)
		goto no_more;
	start++;
	do {
		_debug("more %lx [%lx]", start, count);
		n = wb->last - start + 1;
		if (n > ARRAY_SIZE(pages))
			n = ARRAY_SIZE(pages);
		n = find_get_pages_contig(vnode->vfs_inode.i_mapping,
					  start, n, pages);
		_debug("fgpc %u", n);
		if (n == 0)
			goto no_more;
		if (pages[0]->index != start) {
			do {
				put_page(pages[--n]);
			} while (n > 0);
			goto no_more;
		}

		for (loop = 0; loop < n; loop++) {
			page = pages[loop];
			if (page->index > wb->last)
				break;
			if (!trylock_page(page))
				break;
			if (!PageDirty(page) ||
			    page_private(page) != (unsigned long) wb) {
				unlock_page(page);
				break;
			}
			if (!clear_page_dirty_for_io(page))
				BUG();
			if (test_set_page_writeback(page))
				BUG();
			unlock_page(page);
			put_page(page);
		}
		count += loop;
		if (loop < n) {
			for (; loop < n; loop++)
				put_page(pages[loop]);
			goto no_more;
		}

		start += loop;
	} while (start <= wb->last && count < 65536);

no_more:
	/* we now have a contiguous set of dirty pages, each with writeback set
	 * and the dirty mark cleared; the first page is locked and must remain
	 * so, all the rest are unlocked */
	first = primary_page->index;
	last = first + count - 1;

	offset = (first == wb->first) ? wb->offset_first : 0;
	to = (last == wb->last) ? wb->to_last : PAGE_SIZE;

	_debug("write back %lx[%u..] to %lx[..%u]", first, offset, last, to);

	ret = afs_vnode_store_data(vnode, wb, first, last, offset, to);
	if (ret < 0) {
		switch (ret) {
		case -EDQUOT:
		case -ENOSPC:
			mapping_set_error(vnode->vfs_inode.i_mapping, -ENOSPC);
			break;
		case -EROFS:
		case -EIO:
		case -EREMOTEIO:
		case -EFBIG:
		case -ENOENT:
		case -ENOMEDIUM:
		case -ENXIO:
			afs_kill_pages(vnode, true, first, last);
			mapping_set_error(vnode->vfs_inode.i_mapping, -EIO);
			break;
		case -EACCES:
		case -EPERM:
		case -ENOKEY:
		case -EKEYEXPIRED:
		case -EKEYREJECTED:
		case -EKEYREVOKED:
			afs_kill_pages(vnode, false, first, last);
			break;
		default:
			break;
		}
	} else {
		ret = count;
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * write a page back to the server
 * - the caller locked the page for us
 */
int afs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
	struct afs_writeback *wb;
	int ret;

	_enter("{%lx},", page->index);

	wb = (struct afs_writeback *) page_private(page);
	ASSERT(wb != NULL);

	ret = afs_write_back_from_locked_page(vnode, wb, page);
	unlock_page(page);
	if (ret < 0) {
		_leave(" = %d", ret);
		return 0;
	}

	wbc->nr_to_write -= ret;

	_leave(" = 0");
	return 0;
}

/*
 * write a region of pages back to the server
 */
static int afs_writepages_region(struct address_space *mapping,
				 struct writeback_control *wbc,
				 pgoff_t index, pgoff_t end, pgoff_t *_next)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct afs_writeback *wb, *x;
	struct page *page;
	pgoff_t lowest;
	int ret, n;

	_enter(",,%lx,%lx,", index, end);

next_wb:
	spin_lock(&vnode->writeback_lock);

	/* Look for a data writeback that overlaps the range specified.  Note
	 * that the writeback list is ordered oldest first so that sync records
	 * float through the list as records are written back.
	 */
	lowest = end;
	wb = NULL;
	list_for_each_entry(x, &vnode->writebacks, link) {
		if (x->state != AFS_WBACK_PENDING &&
		    x->state != AFS_WBACK_CONFLICTING)
			continue;
		if (x->first > end || x->last < index)
			continue;
		if (x->first <= lowest) {
			wb = x;
			lowest = x->first;
		}
	}

	if (!wb) {
		spin_unlock(&vnode->writeback_lock);
		*_next = end;
		_leave(" = 0 [no wb %lx]", *_next);
		return 0;
	}

	_debug("found wb %lx-%lx", wb->first, wb->last);
	afs_get_writeback(vnode, wb, afs_writeback_trace_writepages);
	wb->state = AFS_WBACK_WRITING;
	spin_unlock(&vnode->writeback_lock);

	/* We could, at this point, trim non-dirty pages off of the front and
	 * back of the writeback, but this will only happen if ->writepage()
	 * interferes.  Since ->writepage() is called with the target page
	 * locked, we can't lock any earlier page without risking deadlock.
	 */

	index = wb->first;
	do {
		n = find_get_pages_tag(mapping, &index, PAGECACHE_TAG_DIRTY,
				       1, &page);
		if (!n)
			break;

		_debug("wback %lx", page->index);

		if (page->index > wb->last)
			break;

		/* at this point we hold neither mapping->tree_lock nor lock on
		 * the page itself: the page may be truncated or invalidated
		 * (changing page->mapping to NULL), or even swizzled back from
		 * swapper_space to tmpfs file mapping
		 */
		lock_page(page);

		if (page->mapping != mapping || !PageDirty(page)) {
			unlock_page(page);
			put_page(page);
			continue;
		}

		if (PageWriteback(page)) {
			unlock_page(page);
			wait_on_page_writeback(page);
			put_page(page);
			continue;
		}

		ASSERTCMP((struct afs_writeback *)page_private(page), ==, wb);

		if (!clear_page_dirty_for_io(page))
			BUG();
		ret = afs_write_back_from_locked_page(vnode, wb, page);
		unlock_page(page);
		put_page(page);
		if (ret < 0) {
			afs_put_writeback(vnode, wb, 1);
			_leave(" = %d", ret);
			return ret;
		}

		wbc->nr_to_write -= ret;

		cond_resched();
	} while (index < wb->last);

	index = wb->last + 1;
	afs_put_writeback(vnode, wb, 1);
	if (index < end && wbc->nr_to_write > 0)
		goto next_wb;

	*_next = index;
	_leave(" = 0 [%lx]", *_next);
	return 0;
}

/*
 * write some of the pending data back to the server
 */
int afs_writepages(struct address_space *mapping,
		   struct writeback_control *wbc)
{
	pgoff_t start, end, next;
	int ret;

	_enter("");

	if (wbc->range_cyclic) {
		start = mapping->writeback_index;
		end = -1;
		ret = afs_writepages_region(mapping, wbc, start, end, &next);
		if (start > 0 && wbc->nr_to_write > 0 && ret == 0)
			ret = afs_writepages_region(mapping, wbc, 0, start,
						    &next);
		mapping->writeback_index = next;
	} else if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX) {
		end = (pgoff_t)(LLONG_MAX >> PAGE_SHIFT);
		ret = afs_writepages_region(mapping, wbc, 0, end, &next);
		if (wbc->nr_to_write > 0)
			mapping->writeback_index = next;
	} else {
		start = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;
		ret = afs_writepages_region(mapping, wbc, start, end, &next);
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * completion of write to server
 */
void afs_pages_written_back(struct afs_vnode *vnode, struct afs_call *call)
{
	struct afs_writeback *wb = call->wb;
	struct pagevec pv;
	unsigned count, loop;
	pgoff_t first = call->first, last = call->last;
	unsigned delta = 0;

	_enter("{%x:%u},{%lx-%lx}",
	       vnode->fid.vid, vnode->fid.vnode, first, last);

	ASSERT(wb != NULL);

	trace_afs_writeback(vnode, wb, afs_writeback_trace_written,
			    atomic_read(&wb->usage), 0);

	pagevec_init(&pv, 0);

	do {
		_debug("done %lx-%lx", first, last);

		count = last - first + 1;
		if (count > PAGEVEC_SIZE)
			count = PAGEVEC_SIZE;
		pv.nr = find_get_pages_contig(call->mapping, first, count,
					      pv.pages);
		ASSERTCMP(pv.nr, ==, count);

		spin_lock(&vnode->writeback_lock);
		for (loop = 0; loop < count; loop++) {
			struct page *page = pv.pages[loop];
			end_page_writeback(page);
			__afs_writeback_remove_page(vnode, wb, page, &delta);
		}
		spin_unlock(&vnode->writeback_lock);
		first += count;

		__pagevec_release(&pv);
	} while (first <= last);

	afs_put_writeback(vnode, wb, delta);
	_leave("");
}

/*
 * write to an AFS file
 */
ssize_t afs_file_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(iocb->ki_filp));
	ssize_t result;
	size_t count = iov_iter_count(from);

	_enter("{%x.%u},{%zu},",
	       vnode->fid.vid, vnode->fid.vnode, count);

	if (IS_SWAPFILE(&vnode->vfs_inode)) {
		printk(KERN_INFO
		       "AFS: Attempt to write to active swap file!\n");
		return -EBUSY;
	}

	if (!count)
		return 0;

	result = generic_file_write_iter(iocb, from);

	_leave(" = %zd", result);
	return result;
}

/*
 * flush the vnode to the fileserver
 */
int afs_writeback_all(struct afs_vnode *vnode)
{
	struct address_space *mapping = vnode->vfs_inode.i_mapping;
	struct writeback_control wbc = {
		.sync_mode	= WB_SYNC_ALL,
		.nr_to_write	= LONG_MAX,
		.range_cyclic	= 1,
	};
	int ret;

	_enter("");

	ret = mapping->a_ops->writepages(mapping, &wbc);
	__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);

	_leave(" = %d", ret);
	return ret;
}

/*
 * flush any dirty pages for this process, and check for write errors.
 * - the return status from this call provides a reliable indication of
 *   whether any write errors occurred for this process.
 */
static int afs_sync_data(struct afs_vnode *vnode, loff_t start, loff_t end,
			 enum afs_writeback_trace why)
{
	struct afs_writeback *wb, *xwb;
	bool do_sync = false;
	int ret;

	_enter("{%x:%u},%d", vnode->fid.vid, vnode->fid.vnode, why);

	if (list_empty(&vnode->writebacks))
		return 0;

	/* use a writeback record as a marker in the queue - when this reaches
	 * the front of the queue, all the outstanding writes are either
	 * completed or rejected */
	wb = afs_alloc_writeback(vnode, NULL, 0, 0, PAGE_SIZE);
	if (!wb) {
		ret = -ENOMEM;
		goto out;
	}

	wb->last = -1;
	wb->state = AFS_WBACK_SYNCING;

	spin_lock(&vnode->writeback_lock);
	list_for_each_entry(xwb, &vnode->writebacks, link) {
		switch (xwb->state) {
		case AFS_WBACK_PENDING:
			xwb->state = AFS_WBACK_CONFLICTING;
			do_sync = true;
			break;
		default:
			do_sync |= (why == afs_writeback_trace_fsync);
			break;
		case AFS_WBACK_SYNCING:
			break;
		case AFS_WBACK_COMPLETE:
			kdebug("Shouldn't see completed records");
			break;
		}
	}

	if (do_sync) {
		afs_get_writeback(vnode, wb, why);
		list_add_tail(&wb->link, &vnode->writebacks);
	}
	spin_unlock(&vnode->writeback_lock);

	ret = 0;
	if (do_sync) {
		/* push all the outstanding writebacks to the server */
		//inode_lock(&vnode->vfs_inode);
		ret = afs_writeback_all(vnode);
		//inode_unlock(&vnode->vfs_inode);
		if (ret < 0)
			goto out;

		/* wait for the preceding writes to actually complete */
		ret = wait_event_interruptible(wb->waitq,
					       wb->state == AFS_WBACK_COMPLETE ||
					       vnode->writebacks.next == &wb->link);
	}

out:
	afs_put_writeback(vnode, wb, 1);
	_leave(" = %d", ret);
	return ret;
}

int afs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	return afs_sync_data(AFS_FS_I(file_inode(file)), start, end,
			     afs_writeback_trace_fsync);
}

/*
 * Flush out all outstanding writes on a file opened for writing when it is
 * closed.
 */
int afs_flush(struct file *file, fl_owner_t id)
{
	_enter("");

	if ((file->f_mode & FMODE_WRITE) == 0)
		return 0;

	return afs_sync_data(AFS_FS_I(file_inode(file)), 0, LLONG_MAX,
			     afs_writeback_trace_flush);
}

/*
 * notification that a previously read-only page is about to become writable
 * - if it returns an error, the caller will deliver a bus error signal
 */
int afs_page_mkwrite(struct vm_area_struct *vma, struct page *page)
{
	struct afs_vnode *vnode = AFS_FS_I(vma->vm_file->f_mapping->host);

	_enter("{{%x:%u}},{%lx}",
	       vnode->fid.vid, vnode->fid.vnode, page->index);

	/* wait for the page to be written to the cache before we allow it to
	 * be modified */
#ifdef CONFIG_AFS_FSCACHE
	fscache_wait_on_page_write(vnode->cache, page);
#endif

	_leave(" = 0");
	return 0;
}

/*
 * write back a dirty page
 */
int afs_launder_page(struct page *page)
{
	_enter("{%lu}", page->index);

	return 0;
}
