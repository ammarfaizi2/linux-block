/* AFS filesystem file handling
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/gfp.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/mm.h>
#include "internal.h"

static int afs_file_mmap(struct file *file, struct vm_area_struct *vma);
static int afs_readpage(struct file *file, struct page *page);
static void afs_invalidatepage(struct page *page, unsigned int offset,
			       unsigned int length);
static int afs_releasepage(struct page *page, gfp_t gfp_flags);

static int afs_readpages(struct file *filp, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages);
static ssize_t afs_direct_IO(struct kiocb *iocb, struct iov_iter *iter);

const struct file_operations afs_file_operations = {
	.open		= afs_open,
	.release	= afs_release,
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= afs_file_write,
	.mmap		= afs_file_mmap,
	.splice_read	= generic_file_splice_read,
	.fsync		= afs_fsync,
	.lock		= afs_lock,
	.flock		= afs_flock,
};

const struct inode_operations afs_file_inode_operations = {
	.getattr	= afs_getattr,
	.setattr	= afs_setattr,
	.permission	= afs_permission,
	.listxattr	= afs_listxattr,
};

const struct address_space_operations afs_fs_aops = {
	.readpage	= afs_readpage,
	.readpages	= afs_readpages,
	.set_page_dirty	= afs_set_page_dirty,
	.launder_page	= afs_launder_page,
	.releasepage	= afs_releasepage,
	.invalidatepage	= afs_invalidatepage,
	.direct_IO	= afs_direct_IO,
	.write_begin	= afs_write_begin,
	.write_end	= afs_write_end,
	.writepage	= afs_writepage,
	.writepages	= afs_writepages,
};

static const struct vm_operations_struct afs_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= afs_page_mkwrite,
};

/*
 * Discard a pin on a writeback key.
 */
void afs_put_wb_key(struct afs_wb_key *wbk)
{
	if (refcount_dec_and_test(&wbk->usage)) {
		key_put(wbk->key);
		kfree(wbk);
	}
}

/*
 * Cache key for writeback.
 */
int afs_cache_wb_key(struct afs_vnode *vnode, struct afs_file *af)
{
	struct afs_wb_key *wbk, *p;

	wbk = kzalloc(sizeof(struct afs_wb_key), GFP_KERNEL);
	if (!wbk)
		return -ENOMEM;
	refcount_set(&wbk->usage, 2);
	wbk->key = af->key;

	spin_lock(&vnode->wb_lock);
	list_for_each_entry(p, &vnode->wb_keys, vnode_link) {
		if (p->key == wbk->key)
			goto found;
	}

	key_get(wbk->key);
	list_add_tail(&wbk->vnode_link, &vnode->wb_keys);
	spin_unlock(&vnode->wb_lock);
	af->wb = wbk;
	return 0;

found:
	refcount_inc(&p->usage);
	spin_unlock(&vnode->wb_lock);
	af->wb = p;
	kfree(wbk);
	return 0;
}

/*
 * open an AFS file or directory and attach a key to it
 */
int afs_open(struct inode *inode, struct file *file)
{
	struct afs_vnode *vnode = AFS_FS_I(inode);
	struct afs_file *af;
	struct key *key;
	int ret;

	_enter("{%llx:%llu},", vnode->fid.vid, vnode->fid.vnode);

	key = afs_request_key(vnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	af = kzalloc(sizeof(*af), GFP_KERNEL);
	if (!af) {
		ret = -ENOMEM;
		goto error_key;
	}
	af->key = key;

	ret = afs_validate(vnode, key);
	if (ret < 0)
		goto error_af;

	if (file->f_mode & FMODE_WRITE) {
		ret = afs_cache_wb_key(vnode, af);
		if (ret < 0)
			goto error_af;
	}

	if (file->f_flags & O_TRUNC)
		set_bit(AFS_VNODE_NEW_CONTENT, &vnode->flags);

	file->private_data = af;
	_leave(" = 0");
	return 0;

error_af:
	kfree(af);
error_key:
	key_put(key);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * release an AFS file or directory and discard its key
 */
int afs_release(struct inode *inode, struct file *file)
{
	struct afs_vnode *vnode = AFS_FS_I(inode);
	struct afs_file *af = file->private_data;

	_enter("{%llx:%llu},", vnode->fid.vid, vnode->fid.vnode);

	if ((file->f_mode & FMODE_WRITE))
		return vfs_fsync(file, 0);

	file->private_data = NULL;
	if (af->wb)
		afs_put_wb_key(af->wb);
	key_put(af->key);
	kfree(af);
	afs_prune_wb_keys(vnode);
	_leave(" = 0");
	return 0;
}

/*
 * Clear the trailer after a short read.
 */
static void afs_clear_after_read(struct afs_vnode *vnode, struct afs_read *req)
{
	if (req->actual_len < req->len) {
		iov_iter_mapping(&req->iter, READ, vnode->vfs_inode.i_mapping,
				 req->pos + req->actual_len,
				 req->len - req->actual_len);
		iov_iter_zero(req->len - req->actual_len, &req->iter);
	}
}

/*
 * Handle successful completion of a read operation.
 */
static void afs_file_read_successful(struct afs_vnode *vnode,
				     struct afs_read *req)
{
	struct page *page;
	pgoff_t index = req->pos >> PAGE_SHIFT;
	pgoff_t last = index + req->nr_pages - 1;

	XA_STATE(xas, &vnode->vfs_inode.i_mapping->i_pages, index);

	afs_clear_after_read(vnode, req);

	rcu_read_lock();
	xas_for_each(&xas, page, last) {
#if 0 //def CONFIG_AFS_FSCACHE
		if (PageFsCache(page)) {
			xas_pause(&xas);
			rcu_read_unlock();

			if (fscache_write_page(vnode->cache, page, req->file_size,
					       GFP_KERNEL) != 0) {
				fscache_uncache_page(vnode->cache, page);
				BUG_ON(PageFsCache(page));
			}

			rcu_read_lock();
		}
#endif

		page_endio(page, false, 0);
		put_page(page);
	}
	rcu_read_unlock();

	task_io_account_read(req->len);
	req->cleanup = NULL;
}

/*
 * Dispose of our locks and refs on the pages if the read failed.
 */
static void afs_file_read_cleanup(struct afs_read *req)
{
	struct page *page;
	pgoff_t index = req->pos >> PAGE_SHIFT;
	pgoff_t last = index + req->nr_pages - 1;

	XA_STATE(xas, &req->iter.mapping->i_pages, index);

	_enter("%lu,%u,%zu", index, req->nr_pages, iov_iter_count(&req->iter));

	rcu_read_lock();
	xas_for_each(&xas, page, last) {
		BUG_ON(xa_is_value(page));
		BUG_ON(PageCompound(page));

		page_endio(page, false, req->error);
		put_page(page);
	}
	rcu_read_unlock();
}

/*
 * Dispose of a ref to a read record.
 */
void afs_put_read(struct afs_read *req)
{
	if (refcount_dec_and_test(&req->usage)) {
		if (req->cleanup)
			req->cleanup(req);
		kfree(req);
	}
}

#if 0 //def CONFIG_AFS_FSCACHE
/*
 * deal with notification that a page was read from the cache
 */
static void afs_file_readpage_read_complete(struct page *page,
					    void *data,
					    int error)
{
	_enter("%p,%p,%d", page, data, error);

	/* if the read completes with an error, we just unlock the page and let
	 * the VM reissue the readpage */
	if (!error)
		SetPageUptodate(page);
	unlock_page(page);
}
#endif

/*
 * Fetch file data from the volume.
 */
int afs_fetch_data(struct afs_vnode *vnode, struct key *key, struct afs_read *desc)
{
	struct afs_fs_cursor fc;
	int ret;

	_enter("%s{%llx:%llu.%u},%x,,,",
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key));

	ret = -ERESTARTSYS;
	if (afs_begin_vnode_operation(&fc, vnode, key)) {
		while (afs_select_fileserver(&fc)) {
			fc.cb_break = afs_calc_vnode_cb_break(vnode);
			afs_fs_fetch_data(&fc, desc);
		}

		afs_check_for_remote_deletion(&fc, fc.vnode);
		afs_vnode_commit_status(&fc, vnode, fc.cb_break);
		ret = afs_end_vnode_operation(&fc);
	}

	desc->error = ret;
	if (ret == 0) {
		afs_stat_v(vnode, n_fetches);
		atomic_long_add(desc->actual_len,
				&afs_v2net(vnode)->n_fetch_bytes);
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * read page from file, directory or symlink, given a key to use
 */
static int afs_page_filler(struct key *key, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct afs_vnode *vnode = AFS_FS_I(inode);
	struct afs_read *req;
	int ret;

	_enter("{%x},{%lu},{%lu}", key_serial(key), inode->i_ino, page->index);

	BUG_ON(!PageLocked(page));

	ret = -ESTALE;
	if (test_bit(AFS_VNODE_DELETED, &vnode->flags))
		goto error;

	/* is it cached? */
#if 0 //def CONFIG_AFS_FSCACHE
	ret = fscache_read_or_alloc_page(vnode->cache,
					 page,
					 afs_file_readpage_read_complete,
					 NULL,
					 GFP_KERNEL);
#else
	ret = -ENOBUFS;
#endif
	switch (ret) {
		/* read BIO submitted (page in cache) */
	case 0:
		break;

	case -ENODATA: /* page not yet cached */
	case -ENOBUFS: /* page will not be cached */
	default:
		req = kzalloc(sizeof(struct afs_read), GFP_KERNEL);
		if (!req)
			goto enomem;

		refcount_set(&req->usage, 1);
		req->pos		= (loff_t)page->index << PAGE_SHIFT;
		req->len		= PAGE_SIZE;
		req->nr_pages		= 1;
		req->read_successful	= afs_file_read_successful;
		req->cleanup		= afs_file_read_cleanup;

		get_page(page);
		iov_iter_mapping(&req->iter, READ, page->mapping,
				 req->pos, req->len);

		ret = afs_fetch_data(vnode, key, req);
		if (ret < 0)
			goto fetch_error;
	}

	afs_put_read(req);
	_leave(" = 0");
	return 0;

fetch_error:
	switch (ret) {
	case -EINTR:
	case -ENOMEM:
	case -ERESTARTSYS:
	case -EAGAIN:
		goto error;
	case -ENOENT:
		_debug("got NOENT from server - marking file deleted and stale");
		set_bit(AFS_VNODE_DELETED, &vnode->flags);
		ret = -ESTALE;
		/* Fall through */
	default:
		page_endio(page, false, ret);
		afs_put_read(req);
		_leave(" = %d", ret);
		return ret;
	}

enomem:
	ret = -ENOMEM;
error:
	unlock_page(page);
	_leave(" = %d", ret);
	return ret;
}

/*
 * read page from file, directory or symlink, given a file to nominate the key
 * to be used
 */
static int afs_readpage(struct file *file, struct page *page)
{
	struct key *key;
	int ret;

	if (file) {
		key = afs_file_key(file);
		ASSERT(key != NULL);
		ret = afs_page_filler(key, page);
	} else {
		struct inode *inode = page->mapping->host;
		key = afs_request_key(AFS_FS_S(inode->i_sb)->cell);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
		} else {
			ret = afs_page_filler(key, page);
			key_put(key);
		}
	}
	return ret;
}

#if 0
/*
 * Allow writing to a page to take place.  This function may not sleep.
 */
static void afs_clear_page_fscache_mark(const struct iov_iter *iter,
					struct page *page)
{
	ClearPageFsCache(page);
}

static void afs_fscache_write_done(struct fscache_cookie *cookie,
				   struct iov_iter *iter)
{
	struct afs_read *req = container_of(iter, struct afs_read, iter);

	afs_put_read(req);
}

/*
 * Write the read data to the cache.
 */
static void afs_readpages_write_to_cache(struct afs_read *req)
{
	struct afs_vnode *vnode = AFS_FS_I(req->iter.mapping->host);

	if (afs_vnode_cache(vnode)) {
		req->iter.page_done = afs_clear_page_fscache_mark;
		fscache_write(vnode->cache, &req->iter, req->pos,
			      req->file_size, GFP_KERNEL,
			      afs_fscache_write_done);
	}
}
#endif

/*
 * Read a contiguous set of pages.
 */
static int afs_readpages_one(struct file *file, struct address_space *mapping,
			     struct list_head *pages)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct afs_read *req;
	struct list_head *p;
	struct page *first, *page;
	struct key *key = afs_file_key(file);
	pgoff_t index;
	int ret, n;

	/* Count the number of contiguous pages at the front of the list.  Note
	 * that the list goes prev-wards rather than next-wards.
	 */
	first = lru_to_page(pages);
	index = first->index + 1;
	n = 1;
	for (p = first->lru.prev; p != pages; p = p->prev) {
		page = list_entry(p, struct page, lru);
		if (page->index != index)
			break;
		index++;
		n++;
	}

	req = kzalloc(sizeof(struct afs_read), GFP_NOFS);
	if (!req)
		return -ENOMEM;

	refcount_set(&req->usage, 1);
	req->read_successful = afs_file_read_successful;
	req->cleanup = afs_file_read_cleanup;
	req->pos = first->index;
	req->pos <<= PAGE_SHIFT;

	/* Add pages to the LRU until it fails.  We keep the pages ref'd and
	 * locked until the read is complete.
	 *
	 * Note that it's possible for the file size to change whilst we're
	 * doing this, but we rely on the server returning less than we asked
	 * for if the file shrank.  We also rely on this to deal with a partial
	 * page at the end of the file.
	 */
	do {
		page = lru_to_page(pages);
		list_del(&page->lru);
		index = page->index;
		if (add_to_page_cache_lru(page, mapping, index,
					  readahead_gfp_mask(mapping))) {
			put_page(page);
			break;
		}

		req->nr_pages++;
	} while (req->nr_pages < n);

	if (req->nr_pages == 0) {
		kfree(req);
		return 0;
	}

	req->len = req->nr_pages * PAGE_SIZE;
	iov_iter_mapping(&req->iter, READ, file->f_mapping, req->pos, req->len);

	ret = afs_fetch_data(vnode, key, req);
	if (ret < 0)
		goto error;

	afs_put_read(req);
	return 0;

error:
	if (ret == -ENOENT) {
		_debug("got NOENT from server - marking file deleted and stale");
		set_bit(AFS_VNODE_DELETED, &vnode->flags);
		ret = -ESTALE;
	}

	afs_put_read(req);
	return ret;
}

/*
 * read a set of pages
 */
static int afs_readpages(struct file *file, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages)
{
	struct key *key = afs_file_key(file);
	struct afs_vnode *vnode;
	int ret = 0;

	_enter("{%d},{%lu},,%d",
	       key_serial(key), mapping->host->i_ino, nr_pages);

	ASSERT(key != NULL);

	vnode = AFS_FS_I(mapping->host);
	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_leave(" = -ESTALE");
		return -ESTALE;
	}

	/* attempt to read as many of the pages as possible */
#if 0 //def CONFIG_AFS_FSCACHE
	ret = fscache_read_or_alloc_pages(vnode->cache,
					  mapping,
					  pages,
					  &nr_pages,
					  afs_file_readpage_read_complete,
					  NULL,
					  mapping_gfp_mask(mapping));
#else
	ret = -ENOBUFS;
#endif

	switch (ret) {
		/* all pages are being read from the cache */
	case 0:
		BUG_ON(!list_empty(pages));
		BUG_ON(nr_pages != 0);
		_leave(" = 0 [reading all]");
		return 0;

		/* there were pages that couldn't be read from the cache */
	case -ENODATA:
	case -ENOBUFS:
		break;

		/* other error */
	default:
		_leave(" = %d", ret);
		return ret;
	}

	while (!list_empty(pages)) {
		ret = afs_readpages_one(file, mapping, pages);
		if (ret < 0)
			break;
	}

	_leave(" = %d [netting]", ret);
	return ret;
}

/*
 * invalidate part or all of a page
 * - release a page and clean up its private data if offset is 0 (indicating
 *   the entire page)
 */
static void afs_invalidatepage(struct page *page, unsigned int offset,
			       unsigned int length)
{
	struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
	unsigned long priv;

	_enter("{%lu},%u,%u", page->index, offset, length);

	BUG_ON(!PageLocked(page));

	/* we clean up only if the entire page is being invalidated */
	if (offset == 0 && length == PAGE_SIZE) {
#if 0 //def CONFIG_AFS_FSCACHE
		if (PageFsCache(page)) {
			struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
			fscache_wait_on_page_write(vnode->cache, page);
			fscache_uncache_page(vnode->cache, page);
		}
#endif

		if (PagePrivate(page)) {
			priv = page_private(page);
			trace_afs_page_dirty(vnode, tracepoint_string("inval"),
					     page->index, priv);
			set_page_private(page, 0);
			ClearPagePrivate(page);
		}
	}

	_leave("");
}

/*
 * release a page and clean up its private state if it's not busy
 * - return true if the page can now be released, false if not
 */
static int afs_releasepage(struct page *page, gfp_t gfp_flags)
{
	struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
	unsigned long priv;

	_enter("{{%llx:%llu}[%lu],%lx},%x",
	       vnode->fid.vid, vnode->fid.vnode, page->index, page->flags,
	       gfp_flags);

	/* deny if page is being written to the cache and the caller hasn't
	 * elected to wait */
#if 0 //def CONFIG_AFS_FSCACHE
	if (!fscache_maybe_release_page(vnode->cache, page, gfp_flags)) {
		_leave(" = F [cache busy]");
		return 0;
	}
#endif

	if (PagePrivate(page)) {
		priv = page_private(page);
		trace_afs_page_dirty(vnode, tracepoint_string("rel"),
				     page->index, priv);
		set_page_private(page, 0);
		ClearPagePrivate(page);
	}

	/* indicate that the page can be released */
	_leave(" = T");
	return 1;
}

/*
 * Handle setting up a memory mapping on an AFS file.
 */
static int afs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;

	ret = generic_file_mmap(file, vma);
	if (ret == 0)
		vma->vm_ops = &afs_vm_ops;
	return ret;
}

/*
 * Direct file read operation for an AFS file.
 */
static ssize_t afs_file_direct_read(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct afs_read *req;
	struct key *key = afs_file_key(file);
	ssize_t ret;
	size_t count = iov_iter_count(iter), transferred = 0;

	if (!count)
		return 0;
	if (!is_sync_kiocb(iocb))
		return -EOPNOTSUPP;

	req = kzalloc(sizeof(struct afs_read), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	refcount_set(&req->usage, 1);
	req->pos = iocb->ki_pos;
	req->len = count;
	req->iter = *iter;

	task_io_account_read(count);


	// TODO afs_start_io_direct(inode);
	ret = afs_fetch_data(vnode, key, req);
	if (ret == 0)
		transferred = req->actual_len;
	*iter = req->iter;
	afs_put_read(req);

	// TODO afs_end_io_direct(inode);

	BUG_ON(ret == -EIOCBQUEUED); // TODO

	if (ret == 0)
		ret = transferred;

	return ret;
}

/*
 * Do direct I/O.
 */
static ssize_t afs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	VM_BUG_ON(iov_iter_count(iter) != PAGE_SIZE);

	if (iov_iter_rw(iter) == READ)
		return afs_file_direct_read(iocb, iter);
	return afs_file_direct_write(iocb, iter);
}
