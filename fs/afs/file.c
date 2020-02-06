// SPDX-License-Identifier: GPL-2.0-or-later
/* AFS filesystem file handling
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
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

	fscache_use_cookie(afs_vnode_cache(vnode), file->f_mode & FMODE_WRITE);

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
	struct afs_vnode_cache_aux aux;
	struct afs_vnode *vnode = AFS_FS_I(inode);
	struct afs_file *af = file->private_data;
	loff_t i_size;
	int ret = 0;

	_enter("{%llx:%llu},", vnode->fid.vid, vnode->fid.vnode);

	if ((file->f_mode & FMODE_WRITE))
		ret = vfs_fsync(file, 0);

	file->private_data = NULL;
	if (af->wb)
		afs_put_wb_key(af->wb);

	if ((file->f_mode & FMODE_WRITE)) {
		i_size = i_size_read(&vnode->vfs_inode);
		aux.data_version = vnode->status.data_version;
		fscache_unuse_cookie(afs_vnode_cache(vnode), &aux, &i_size);
	} else {
		fscache_unuse_cookie(afs_vnode_cache(vnode), NULL, NULL);
	}

	key_put(af->key);
	kfree(af);
	afs_prune_wb_keys(vnode);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Dispose of our locks and refs on the pages if the read failed.
 */
static void afs_file_read_cleanup(struct afs_read *req)
{
	struct afs_vnode *vnode = req->vnode;
	struct page *page;
	pgoff_t index = req->cache.pos >> PAGE_SHIFT;
	pgoff_t last = index + req->cache.nr_pages - 1;

	_enter("%lx,%x,%llx", index, req->cache.nr_pages, req->cache.len);

	if (req->cache.nr_pages > 0) {
		XA_STATE(xas, &vnode->vfs_inode.i_mapping->i_pages, index);

		rcu_read_lock();
		xas_for_each(&xas, page, last) {
			BUG_ON(xa_is_value(page));
			BUG_ON(PageCompound(page));

			if (req->cache.error)
				page_endio(page, false, req->cache.error);
			else
				unlock_page(page);
			put_page(page);
		}
		rcu_read_unlock();
	}

	if (test_bit(AFS_READ_IN_PROGRESS, &req->flags)) {
		clear_bit_unlock(AFS_READ_IN_PROGRESS, &req->flags);
		wake_up_bit(&req->flags, AFS_READ_IN_PROGRESS);
	}
}

/*
 * Allocate a new read record.
 */
struct afs_read *afs_alloc_read(gfp_t gfp)
{
	static atomic_t debug_ids;
	struct afs_read *req;

	req = kzalloc(sizeof(struct afs_read), gfp);
	if (req) {
		refcount_set(&req->usage, 1);
		req->debug_id = atomic_inc_return(&debug_ids);
		__set_bit(AFS_READ_IN_PROGRESS, &req->flags);
	}

	return req;
}

/*
 *
 */
static void __afs_put_read(struct work_struct *work)
{
	struct afs_read *req = container_of(work, struct afs_read, cache.work);

	if (req->cleanup)
		req->cleanup(req);
	fscache_free_io_request(&req->cache);
	key_put(req->key);
	kfree(req);
}

/*
 * Dispose of a ref to a read record.
 */
void afs_put_read(struct afs_read *req)
{
	if (refcount_dec_and_test(&req->usage)) {
		_debug("dead %u", req->debug_id);
		if (in_softirq()) {
			INIT_WORK(&req->cache.work, __afs_put_read);
			queue_work(afs_wq, &req->cache.work);
		} else {
			__afs_put_read(&req->cache.work);
		}
	}
}

/*
 * Fetch file data from the volume.
 */
int afs_fetch_data(struct afs_vnode *vnode, struct afs_read *req)
{
	struct afs_fs_cursor fc;
	struct afs_status_cb *scb;
	int ret;

	_enter("%s{%llx:%llu.%u},%x,,,",
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(req->key));

	scb = kzalloc(sizeof(struct afs_status_cb), GFP_KERNEL);
	if (!scb)
		return -ENOMEM;

	ret = -ERESTARTSYS;
	if (afs_begin_vnode_operation(&fc, vnode, req->key, true)) {
		afs_dataversion_t data_version = vnode->status.data_version;

		while (afs_select_fileserver(&fc)) {
			fc.cb_break = afs_calc_vnode_cb_break(vnode);
			afs_fs_fetch_data(&fc, scb, req);
		}

		afs_check_for_remote_deletion(&fc, vnode);
		afs_vnode_commit_status(&fc, vnode, fc.cb_break,
					&data_version, scb);
		ret = afs_end_vnode_operation(&fc);
	}

	req->cache.error = ret;
	if (ret == 0) {
		afs_stat_v(vnode, n_fetches);
		atomic_long_add(req->actual_len,
				&afs_v2net(vnode)->n_fetch_bytes);
	}

	kfree(scb);
	_leave(" = %d", ret);
	return ret;
}

void afs_req_issue_op(struct fscache_io_request *fsreq)
{
	struct afs_read *req = container_of(fsreq, struct afs_read, cache);
	int ret;

	iov_iter_mapping(&req->def_iter, READ, req->cache.mapping,
			 req->cache.pos, req->cache.len);
	req->iter = &req->def_iter;

	ret = afs_fetch_data(req->vnode, req);
	if (ret < 0)
		req->cache.error = ret;
}

void afs_req_done(struct fscache_io_request *fsreq)
{
	struct afs_read *req = container_of(fsreq, struct afs_read, cache);

	req->cleanup = NULL;
	if (test_bit(AFS_READ_IN_PROGRESS, &req->flags)) {
		clear_bit_unlock(AFS_READ_IN_PROGRESS, &req->flags);
		wake_up_bit(&req->flags, AFS_READ_IN_PROGRESS);
	}
}

void afs_req_get(struct fscache_io_request *fsreq)
{
	struct afs_read *req = container_of(fsreq, struct afs_read, cache);

	afs_get_read(req);
}

void afs_req_put(struct fscache_io_request *fsreq)
{
	struct afs_read *req = container_of(fsreq, struct afs_read, cache);

	afs_put_read(req);
}

const struct fscache_io_request_ops afs_req_ops = {
	.issue_op	= afs_req_issue_op,
	.done		= afs_req_done,
	.get		= afs_req_get,
	.put		= afs_req_put,
};

/*
 * read page from file, directory or symlink, given a file to nominate the key
 * to be used
 */
static int afs_readpage(struct file *file, struct page *page)
{
	struct fscache_extent extent;
	struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
	struct afs_read *req;
	struct key *key;
	int ret = -ENOMEM;

	_enter(",%lx", page->index);

	if (file) {
		key = key_get(afs_file_key(file));
		ASSERT(key != NULL);
	} else {
		key = afs_request_key(vnode->volume->cell);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
			goto out;
		}
	}

	req = afs_alloc_read(GFP_NOFS);
	if (!req)
		goto out_key;

	fscache_init_io_request(&req->cache, afs_vnode_cache(vnode), &afs_req_ops);
	req->vnode = vnode;
	req->key = key;
	req->cleanup = afs_file_read_cleanup;
	req->cache.mapping = page->mapping;

	extent.start = page->index;
	extent.block_end = page->index + 1;
	extent.limit = ULONG_MAX;

	ret = fscache_read_helper(&req->cache, &extent, &page, NULL,
				  FSCACHE_READ_LOCKED_PAGE, 0);
	afs_put_read(req);
	return ret;

out_key:
	key_put(key);
out:
	return ret;
}

/*
 * Determine the extent of contiguous pages at the front of the list.
 * Note that the list goes prev-wards rather than next-wards.
 *
 * We also determine the last page we can include in a transaction -  we stop
 * if there's a non-contiguity in the page list, but we include the gap.
 */
static void afs_count_contig(struct list_head *pages,
			     struct fscache_extent *extent)
{
	struct list_head *p;
	struct page *first = lru_to_page(pages), *page;

	extent->start = first->index;
	extent->block_end = first->index + 1;
	extent->limit = ULONG_MAX;

	for (p = first->lru.prev; p != pages; p = p->prev) {
		page = list_entry(p, struct page, lru);
		if (page->index != extent->block_end) {
			extent->limit = page->index;
			break;
		}
		extent->block_end = page->index + 1;
	}

	_leave(" [%lx,%lx,%lx]",
	       extent->start, extent->block_end, extent->limit);
}

/*
 * read a set of pages
 */
static int afs_readpages(struct file *file, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages)
{
	struct fscache_extent extent;
	struct afs_vnode *vnode;
	struct afs_read *req;
	int ret = 0;

	_enter(",{%lu},,%x", mapping->host->i_ino, nr_pages);

	vnode = AFS_FS_I(mapping->host);
	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_leave(" = -ESTALE");
		return -ESTALE;
	}

	while (!list_empty(pages)) {
		/* Determine the size of the next contiguous run of pages and
		 * find out what size of download will be required to pad it
		 * out to a whole number of cache blocks.
		 */
		afs_count_contig(pages, &extent);
		req = afs_alloc_read(GFP_NOFS);
		if (!req)
			return -ENOMEM;

		fscache_init_io_request(&req->cache, afs_vnode_cache(vnode),
					&afs_req_ops);
		req->vnode	= AFS_FS_I(mapping->host);
		req->key	= key_get(afs_file_key(file));
		req->cleanup	= afs_file_read_cleanup;
		req->cache.mapping = mapping;

		ret = fscache_read_helper(&req->cache, &extent, NULL, pages,
					  FSCACHE_READ_PAGE_LIST, 0);
		afs_put_read(req);
		if (ret < 0)
			break;
	}

	_leave(" = %d [netting]", ret);
	return ret;
}

/*
 * Prefetch data into the cache prior to writing, returning the requested page
 * to the caller, with the lock held, upon completion of the write.
 */
struct page *afs_prefetch_for_write(struct file *file,
				    struct address_space *mapping,
				    pgoff_t index,
				    unsigned int aop_flags)
{
	struct fscache_extent extent;
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct afs_read *req;
	struct page *page;
	int ret = 0;

	_enter("{%lu},%lx", mapping->host->i_ino, index);

	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_leave(" = -ESTALE");
		return ERR_PTR(-ESTALE);
	}

	page = pagecache_get_page(mapping, index, FGP_WRITE, 0);
	if (page) {
		if (PageUptodate(page)) {
			lock_page(page);
			if (PageUptodate(page))
				goto have_page;
			unlock_page(page);
		}
	}

	extent.start = index;
	extent.block_end = index + 1;
	extent.limit = ULONG_MAX;

	req = afs_alloc_read(GFP_NOFS);
	if (!req)
		return ERR_PTR(-ENOMEM);

	fscache_init_io_request(&req->cache, afs_vnode_cache(vnode), &afs_req_ops);
	req->vnode	= AFS_FS_I(mapping->host);
	req->key	= key_get(afs_file_key(file));
	req->cleanup	= afs_file_read_cleanup;
	req->cache.mapping = mapping;

	ret = fscache_read_helper(&req->cache, &extent, &page, NULL,
				  FSCACHE_READ_FOR_WRITE, aop_flags);
	if (ret == 0)
		/* Synchronicity required */
		ret = wait_on_bit(&req->flags, AFS_READ_IN_PROGRESS, TASK_KILLABLE);

	afs_put_read(req);

	if (ret < 0) {
		if (page)
			put_page(page);
		return ERR_PTR(ret);
	}

have_page:
	wait_for_stable_page(page);
	return page;
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
#ifdef CONFIG_AFS_FSCACHE
		if (PageFsCache(page))
			wait_on_page_fscache(page);
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
#ifdef CONFIG_AFS_FSCACHE
	if (PageFsCache(page)) {
		if (!(gfp_flags & __GFP_DIRECT_RECLAIM) || !(gfp_flags & __GFP_FS))
			return false;
		wait_on_page_fscache(page);
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
