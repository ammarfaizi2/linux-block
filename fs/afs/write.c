// SPDX-License-Identifier: GPL-2.0-or-later
/* handling of writes to regular files and writing back to the server
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/backing-dev.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/netfs.h>
#include <linux/fscache.h>
#include <crypto/skcipher.h>
#include <trace/events/netfs.h>
#include "internal.h"

static void afs_write_to_cache(struct afs_vnode *vnode, loff_t start, size_t len,
			       loff_t i_size);

/*
 * Mark a page as having been made dirty and thus needing writeback.  We also
 * need to pin the cache object to write back to.
 */
int afs_set_page_dirty(struct page *page)
{
	return fscache_set_page_dirty(page, afs_vnode_cache(AFS_FS_I(page->mapping->host)));
}

/*
 * kill all the pages in the given range
 */
static void afs_kill_pages(struct address_space *mapping,
			   loff_t start, loff_t len)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct pagevec pv;
	unsigned int loop, psize;

	_enter("{%llx:%llu},%llx @%llx",
	       vnode->fid.vid, vnode->fid.vnode, len, start);

	pagevec_init(&pv);

	do {
		_debug("kill %llx @%llx", len, start);

		pv.nr = find_get_pages_contig(mapping, start / PAGE_SIZE,
					      PAGEVEC_SIZE, pv.pages);
		if (pv.nr == 0)
			break;

		for (loop = 0; loop < pv.nr; loop++) {
			struct page *page = pv.pages[loop];

			if (page->index * PAGE_SIZE >= start + len)
				break;

			psize = thp_size(page);
			start += psize;
			len -= psize;
			ClearPageUptodate(page);
			end_page_writeback(page);
			lock_page(page);
			generic_error_remove_page(mapping, page);
			unlock_page(page);
		}

		__pagevec_release(&pv);
	} while (len > 0);

	_leave("");
}

/*
 * Redirty all the pages in a given range.
 */
static void afs_redirty_pages(struct writeback_control *wbc,
			      struct address_space *mapping,
			      loff_t start, loff_t len)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct pagevec pv;
	unsigned int loop, psize;

	_enter("{%llx:%llu},%llx @%llx",
	       vnode->fid.vid, vnode->fid.vnode, len, start);

	pagevec_init(&pv);

	do {
		_debug("redirty %llx @%llx", len, start);

		pv.nr = find_get_pages_contig(mapping, start / PAGE_SIZE,
					      PAGEVEC_SIZE, pv.pages);
		if (pv.nr == 0)
			break;

		for (loop = 0; loop < pv.nr; loop++) {
			struct page *page = pv.pages[loop];

			if (page->index * PAGE_SIZE >= start + len)
				break;

			psize = thp_size(page);
			start += psize;
			len -= psize;
			redirty_page_for_writepage(wbc, page);
			end_page_writeback(page);
		}

		__pagevec_release(&pv);
	} while (len > 0);

	_leave("");
}

/*
 * completion of write to server
 */
static void afs_pages_written_back(struct afs_vnode *vnode, loff_t start, unsigned int len)
{
	_enter("{%llx:%llu},{%x @%llx}",
	       vnode->fid.vid, vnode->fid.vnode, len, start);

	afs_prune_wb_keys(vnode);
	_leave("");
}

/*
 * Find a key to use for the writeback.  We cached the keys used to author the
 * writes on the vnode.  *_wbk will contain the last writeback key used or NULL
 * and we need to start from there if it's set.
 */
static int afs_get_writeback_key(struct afs_vnode *vnode,
				 struct afs_wb_key **_wbk)
{
	struct afs_wb_key *wbk = NULL;
	struct list_head *p;
	int ret = -ENOKEY, ret2;

	spin_lock(&vnode->wb_lock);
	if (*_wbk)
		p = (*_wbk)->vnode_link.next;
	else
		p = vnode->wb_keys.next;

	while (p != &vnode->wb_keys) {
		wbk = list_entry(p, struct afs_wb_key, vnode_link);
		_debug("wbk %u", key_serial(wbk->key));
		ret2 = key_validate(wbk->key);
		if (ret2 == 0) {
			refcount_inc(&wbk->usage);
			_debug("USE WB KEY %u", key_serial(wbk->key));
			break;
		}

		wbk = NULL;
		if (ret == -ENOKEY)
			ret = ret2;
		p = p->next;
	}

	spin_unlock(&vnode->wb_lock);
	if (*_wbk)
		afs_put_wb_key(*_wbk);
	*_wbk = wbk;
	return 0;
}

static void afs_store_data_success(struct afs_operation *op)
{
	struct afs_vnode *vnode = op->file[0].vnode;

	op->ctime = op->file[0].scb.status.mtime_client;
	afs_vnode_commit_status(op, &op->file[0]);
	if (op->error == 0) {
		if (!op->store.laundering)
			afs_pages_written_back(vnode, op->store.pos, op->store.size);
		afs_stat_v(vnode, n_stores);
		atomic_long_add(op->store.size, &afs_v2net(vnode)->n_store_bytes);
	}
}

static const struct afs_operation_ops afs_store_data_operation = {
	.issue_afs_rpc	= afs_fs_store_data,
	.issue_yfs_rpc	= yfs_fs_store_data,
	.success	= afs_store_data_success,
};

/*
 * write to a file
 */
static int afs_store_data(struct afs_vnode *vnode, struct iov_iter *iter, loff_t pos,
			  bool laundering)
{
	struct afs_operation *op;
	struct afs_wb_key *wbk = NULL;
	loff_t size = iov_iter_count(iter), i_size;
	int ret = -ENOKEY;

	_enter("%s{%llx:%llu.%u},%llx,%llx",
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       size, pos);

	ret = afs_get_writeback_key(vnode, &wbk);
	if (ret) {
		_leave(" = %d [no keys]", ret);
		return ret;
	}

	op = afs_alloc_operation(wbk->key, vnode->volume);
	if (IS_ERR(op)) {
		afs_put_wb_key(wbk);
		return -ENOMEM;
	}

	i_size = i_size_read(&vnode->vfs_inode);

	afs_op_set_vnode(op, 0, vnode);
	op->file[0].dv_delta = 1;
	op->file[0].modification = true;
	op->store.write_iter = iter;
	op->store.pos = pos;
	op->store.size = size;
	op->store.i_size = max(pos + size, i_size);
	op->store.laundering = laundering;
	op->mtime = vnode->vfs_inode.i_mtime;
	op->flags |= AFS_OPERATION_SET_MTIME | AFS_OPERATION_UNINTR;
	op->ops = &afs_store_data_operation;

try_next_key:
	afs_begin_vnode_operation(op);
	afs_wait_for_operation(op);

	switch (op->error) {
	case -EACCES:
	case -EPERM:
	case -ENOKEY:
	case -EKEYEXPIRED:
	case -EKEYREJECTED:
	case -EKEYREVOKED:
		_debug("next");

		ret = afs_get_writeback_key(vnode, &wbk);
		if (ret == 0) {
			key_put(op->key);
			op->key = key_get(wbk->key);
			goto try_next_key;
		}
		break;
	}

	afs_put_wb_key(wbk);
	_leave(" = %d", op->error);
	return afs_put_operation(op);
}

static void afs_upload_to_server(struct netfs_write_stream *stream,
				 struct netfs_write_request *wreq)
{
	struct afs_vnode *vnode = AFS_FS_I(wreq->inode);
	ssize_t ret;

	kenter("%u", stream->index);

	trace_netfs_wstr(stream, netfs_write_stream_submit);
	ret = afs_store_data(vnode, &wreq->source, wreq->start, false);
	netfs_write_stream_completed(stream, ret, false);
}

static void afs_upload_to_server_worker(struct work_struct *work)
{
	struct netfs_write_stream *stream = container_of(work, struct netfs_write_stream, work);
	struct netfs_write_request *wreq = netfs_stream_to_wreq(stream);

	afs_upload_to_server(stream, wreq);
	netfs_put_write_request(wreq, false, netfs_wreq_trace_put_stream_work);
}

/*
 * Add write streams to a write request.  We need to add a single stream for
 * the server we're writing to.
 */
void afs_add_write_streams(struct netfs_write_request *wreq)
{
	kenter("");
	netfs_set_up_write_stream(wreq, NETFS_UPLOAD_TO_SERVER,
				  afs_upload_to_server_worker);
}

/*
 * Encrypt part of a write for fscrypt.
 */
bool afs_encrypt_block(struct netfs_write_request *wreq, loff_t pos, size_t len,
		       struct scatterlist *source_sg, unsigned int n_source,
		       struct scatterlist *dest_sg, unsigned int n_dest)
{
	struct crypto_sync_skcipher *ci;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	u8 session_key[8], iv[8];
	int ret;

	kenter("%llx", pos);

	ci = crypto_alloc_sync_skcipher("pcbc(fcrypt)", 0, 0);
	if (IS_ERR(ci)) {
		_debug("no cipher");
		ret = PTR_ERR(ci);
		goto error;
	}
	tfm= &ci->base;

	ret = crypto_sync_skcipher_setkey(ci, session_key, sizeof(session_key));
	if (ret < 0)
		goto error_ci;

	ret = -ENOMEM;
	req = skcipher_request_alloc(tfm, GFP_NOFS);
	if (!req)
		goto error_ci;

	memset(iv, 0, sizeof(iv));
	skcipher_request_set_sync_tfm(req, ci);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, source_sg, dest_sg, len, iv);
	ret = crypto_skcipher_encrypt(req);

	skcipher_request_free(req);
error_ci:
	crypto_free_sync_skcipher(ci);
error:
	if (ret < 0)
		wreq->error = ret;
	kleave(" = %d", ret);
	return ret == 0;
}

/*
 * Extend the region to be written back to include subsequent contiguously
 * dirty pages if possible, but don't sleep while doing so.
 *
 * If this page holds new content, then we can include filler zeros in the
 * writeback.
 */
static void afs_extend_writeback(struct address_space *mapping,
				 struct afs_vnode *vnode,
				 long *_count,
				 loff_t start,
				 loff_t max_len,
				 bool new_content,
				 unsigned int *_len)
{
	struct pagevec pvec;
	struct page *page;
	unsigned long priv;
	unsigned int psize, filler = 0;
	unsigned int f, t;
	loff_t len = *_len;
	pgoff_t index = (start + len) / PAGE_SIZE;
	bool stop = true;
	unsigned int i;

	XA_STATE(xas, &mapping->i_pages, index);
	pagevec_init(&pvec);

	do {
		/* Firstly, we gather up a batch of contiguous dirty pages
		 * under the RCU read lock - but we can't clear the dirty flags
		 * there if any of those pages are mapped.
		 */
		rcu_read_lock();

		xas_for_each(&xas, page, ULONG_MAX) {
			stop = true;
			if (xas_retry(&xas, page))
				continue;
			if (xa_is_value(page))
				break;
			if (page->index != index)
				break;

			if (!page_cache_get_speculative(page)) {
				xas_reset(&xas);
				continue;
			}

			/* Has the page moved or been split? */
			if (unlikely(page != xas_reload(&xas)))
				break;

			if (!trylock_page(page))
				break;
			if (!PageDirty(page) || PageWriteback(page) ||
			    PageFsCache(page)) {
				unlock_page(page);
				break;
			}

			psize = thp_size(page);
			priv = page_private(page);
			f = afs_page_dirty_from(page, priv);
			t = afs_page_dirty_to(page, priv);
			if (f != 0 && !new_content) {
				unlock_page(page);
				break;
			}

			len += filler + t;
			filler = psize - t;
			if (len >= max_len || *_count <= 0)
				stop = true;
			else if (t == psize || new_content)
				stop = false;

			index += thp_nr_pages(page);
			if (!pagevec_add(&pvec, page))
				break;
			if (stop)
				break;
		}

		if (!stop)
			xas_pause(&xas);
		rcu_read_unlock();

		/* Now, if we obtained any pages, we can shift them to being
		 * writable and mark them for caching.
		 */
		if (!pagevec_count(&pvec))
			break;

		for (i = 0; i < pagevec_count(&pvec); i++) {
			page = pvec.pages[i];
			trace_afs_page_dirty(vnode, tracepoint_string("store+"), page);

			if (!clear_page_dirty_for_io(page))
				BUG();
			if (test_set_page_writeback(page))
				BUG();
			set_page_fscache(page);

			*_count -= thp_nr_pages(page);
			unlock_page(page);
		}

		pagevec_release(&pvec);
		cond_resched();
	} while (!stop);

	*_len = len;
}

/*
 * Synchronously write back the locked page and any subsequent non-locked dirty
 * pages.
 */
static ssize_t afs_write_back_from_locked_page(struct address_space *mapping,
					       struct writeback_control *wbc,
					       struct page *page,
					       loff_t start, loff_t end)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct iov_iter iter;
	unsigned long priv;
	unsigned int offset, to, len, max_len;
	loff_t i_size = i_size_read(&vnode->vfs_inode);
	bool new_content = test_bit(NETFS_ICTX_NEW_CONTENT, &vnode->netfs_ctx.flags);
	long count = wbc->nr_to_write;
	int ret;

	_enter(",%lx,%llx-%llx", page->index, start, end);

	if (test_set_page_writeback(page))
		BUG();
	set_page_fscache(page);

	count -= thp_nr_pages(page);

	/* Find all consecutive lockable dirty pages that have contiguous
	 * written regions, stopping when we find a page that is not
	 * immediately lockable, is not dirty or is missing, or we reach the
	 * end of the range.
	 */
	priv = page_private(page);
	offset = afs_page_dirty_from(page, priv);
	to = afs_page_dirty_to(page, priv);
	trace_afs_page_dirty(vnode, tracepoint_string("store"), page);

	len = to - offset;
	start += offset;
	if (start < i_size) {
		/* Trim the write to the EOF; the extra data is ignored.  Also
		 * put an upper limit on the size of a single storedata op.
		 */
		max_len = 65536 * 4096;
		max_len = min_t(unsigned long long, max_len, end - start + 1);
		max_len = min_t(unsigned long long, max_len, i_size - start);

		if (len < max_len &&
		    (to == thp_size(page) || new_content))
			afs_extend_writeback(mapping, vnode, &count,
					     start, max_len, new_content, &len);
		len = min_t(loff_t, len, max_len);
	}

	/* We now have a contiguous set of dirty pages, each with writeback
	 * set; the first page is still locked at this point, but all the rest
	 * have been unlocked.
	 */
	unlock_page(page);

	if (start < i_size) {
		_debug("write back %x @%llx [%llx]", len, start, i_size);

		/* Speculatively write to the cache.  We have to fix this up
		 * later if the store fails.
		 */
		afs_write_to_cache(vnode, start, len, i_size);

		iov_iter_xarray(&iter, WRITE, &mapping->i_pages, start, len);
		ret = afs_store_data(vnode, &iter, start, false);
	} else {
		_debug("write discard %x @%llx [%llx]", len, start, i_size);

		/* The dirty region was entirely beyond the EOF. */
		fscache_clear_page_bits(mapping, start, len);
		afs_pages_written_back(vnode, start, len);
		ret = 0;
	}

	switch (ret) {
	case 0:
		wbc->nr_to_write = count;
		ret = len;
		break;

	default:
		pr_notice("kAFS: Unexpected error from FS.StoreData %d\n", ret);
		fallthrough;
	case -EACCES:
	case -EPERM:
	case -ENOKEY:
	case -EKEYEXPIRED:
	case -EKEYREJECTED:
	case -EKEYREVOKED:
		afs_redirty_pages(wbc, mapping, start, len);
		mapping_set_error(mapping, ret);
		break;

	case -EDQUOT:
	case -ENOSPC:
		afs_redirty_pages(wbc, mapping, start, len);
		mapping_set_error(mapping, -ENOSPC);
		break;

	case -EROFS:
	case -EIO:
	case -EREMOTEIO:
	case -EFBIG:
	case -ENOENT:
	case -ENOMEDIUM:
	case -ENXIO:
		trace_afs_file_error(vnode, ret, afs_file_error_writeback_fail);
		afs_kill_pages(mapping, start, len);
		mapping_set_error(mapping, ret);
		break;
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
	ssize_t ret;
	loff_t start;

	_enter("{%lx},", page->index);

#ifdef CONFIG_AFS_FSCACHE
	wait_on_page_fscache(page);
#endif

	start = page->index * PAGE_SIZE;
	ret = afs_write_back_from_locked_page(page->mapping, wbc, page,
					      start, LLONG_MAX - start);
	if (ret < 0) {
		_leave(" = %zd", ret);
		return ret;
	}

	_leave(" = 0");
	return 0;
}

/*
 * flush any dirty pages for this process, and check for write errors.
 * - the return status from this call provides a reliable indication of
 *   whether any write errors occurred for this process.
 */
int afs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file_inode(file);
	struct afs_vnode *vnode = AFS_FS_I(inode);

	_enter("{%llx:%llu},{n=%pD},%d",
	       vnode->fid.vid, vnode->fid.vnode, file,
	       datasync);

	return file_write_and_wait_range(file, start, end);
}

/*
 * notification that a previously read-only page is about to become writable
 * - if it returns an error, the caller will deliver a bus error signal
 */
vm_fault_t afs_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = thp_head(vmf->page);
	struct file *file = vmf->vma->vm_file;
	struct inode *inode = file_inode(file);
	struct afs_vnode *vnode = AFS_FS_I(inode);
	unsigned long priv;
	vm_fault_t ret = VM_FAULT_RETRY;

	_enter("{{%llx:%llu}},{%lx}", vnode->fid.vid, vnode->fid.vnode, page->index);

	sb_start_pagefault(inode->i_sb);

	/* Wait for the page to be written to the cache before we allow it to
	 * be modified.  We then assume the entire page will need writing back.
	 */
#ifdef CONFIG_AFS_FSCACHE
	if (PageFsCache(page) &&
	    wait_on_page_fscache_killable(page) < 0)
		goto out;
#endif

	if (wait_on_page_writeback_killable(page))
		goto out;

	if (lock_page_killable(page) < 0)
		goto out;

	/* We mustn't change page->private until writeback is complete as that
	 * details the portion of the page we need to write back and we might
	 * need to redirty the page if there's a problem.
	 */
	if (wait_on_page_writeback_killable(page) < 0) {
		unlock_page(page);
		goto out;
	}

	priv = afs_page_dirty(page, 0, thp_size(page));
	priv = afs_page_dirty_mmapped(priv);
	if (PagePrivate(page)) {
		set_page_private(page, priv);
		trace_afs_page_dirty(vnode, tracepoint_string("mkwrite+"), page);
	} else {
		attach_page_private(page, (void *)priv);
		trace_afs_page_dirty(vnode, tracepoint_string("mkwrite"), page);
	}
	file_update_time(file);

	ret = VM_FAULT_LOCKED;
out:
	sb_end_pagefault(inode->i_sb);
	return ret;
}

/*
 * Prune the keys cached for writeback.  The caller must hold vnode->wb_lock.
 */
void afs_prune_wb_keys(struct afs_vnode *vnode)
{
	LIST_HEAD(graveyard);
	struct afs_wb_key *wbk, *tmp;

	/* Discard unused keys */
	spin_lock(&vnode->wb_lock);

	if (!mapping_tagged(&vnode->vfs_inode.i_data, PAGECACHE_TAG_WRITEBACK) &&
	    !mapping_tagged(&vnode->vfs_inode.i_data, PAGECACHE_TAG_DIRTY)) {
		list_for_each_entry_safe(wbk, tmp, &vnode->wb_keys, vnode_link) {
			if (refcount_read(&wbk->usage) == 1)
				list_move(&wbk->vnode_link, &graveyard);
		}
	}

	spin_unlock(&vnode->wb_lock);

	while (!list_empty(&graveyard)) {
		wbk = list_entry(graveyard.next, struct afs_wb_key, vnode_link);
		list_del(&wbk->vnode_link);
		afs_put_wb_key(wbk);
	}
}

/*
 * Clean up a page during invalidation.
 */
int afs_launder_page(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct iov_iter iter;
	struct bio_vec bv[1];
	unsigned long priv;
	unsigned int f, t;
	int ret = 0;

	_enter("{%lx}", page->index);

	priv = page_private(page);
	if (clear_page_dirty_for_io(page)) {
		f = 0;
		t = thp_size(page);
		if (PagePrivate(page)) {
			f = afs_page_dirty_from(page, priv);
			t = afs_page_dirty_to(page, priv);
		}

		bv[0].bv_page = page;
		bv[0].bv_offset = f;
		bv[0].bv_len = t - f;
		iov_iter_bvec(&iter, WRITE, bv, 1, bv[0].bv_len);

		trace_afs_page_dirty(vnode, tracepoint_string("launder"), page);
		ret = afs_store_data(vnode, &iter, (loff_t)page->index * PAGE_SIZE,
				     true);
	}

	trace_afs_page_dirty(vnode, tracepoint_string("laundered"), page);
	detach_page_private(page);
	wait_on_page_fscache(page);
	return ret;
}

/*
 * Deal with the completion of writing the data to the cache.
 */
static void afs_write_to_cache_done(void *priv, ssize_t transferred_or_error,
				    bool was_async)
{
	struct afs_vnode *vnode = priv;

	if (IS_ERR_VALUE(transferred_or_error) &&
	    transferred_or_error != -ENOBUFS)
		afs_invalidate_cache(vnode, 0);
}

/*
 * Save the write to the cache also.
 */
static void afs_write_to_cache(struct afs_vnode *vnode,
			       loff_t start, size_t len, loff_t i_size)
{
	fscache_write_to_cache(afs_vnode_cache(vnode),
			       vnode->vfs_inode.i_mapping, start, len, i_size,
			       afs_write_to_cache_done, vnode);
}

static void afs_dio_store_data_success(struct afs_operation *op)
{
	struct afs_vnode *vnode = op->file[0].vnode;

	op->ctime = op->file[0].scb.status.mtime_client;
	afs_vnode_commit_status(op, &op->file[0]);
	if (op->error == 0) {
		afs_stat_v(vnode, n_stores);
		atomic_long_add(op->store.size, &afs_v2net(vnode)->n_store_bytes);
	}
}

static const struct afs_operation_ops afs_dio_store_data_operation = {
	.issue_afs_rpc	= afs_fs_store_data,
	.issue_yfs_rpc	= yfs_fs_store_data,
	.success	= afs_dio_store_data_success,
};

/*
 * Direct file write operation for an AFS file.
 *
 * TODO: To support AIO, the pages in the iterator have to be copied and
 * refs taken on them.  Then -EIOCBQUEUED needs to be returned.
 * iocb->ki_complete must then be called upon completion of the operation.
 */
ssize_t afs_file_direct_write(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct afs_operation *op;
	loff_t size = iov_iter_count(iter), i_size;
	ssize_t ret;

	_enter("%s{%llx:%llu.%u},%llx,%llx",
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       size, iocb->ki_pos);

	op = afs_alloc_operation(afs_file_key(file), vnode->volume);
	if (IS_ERR(op))
		return -ENOMEM;

	i_size = i_size_read(&vnode->vfs_inode);

	afs_op_set_vnode(op, 0, vnode);
	op->file[0].dv_delta	= 1;
	op->file[0].set_size	= true;
	op->store.write_iter	= iter;
	op->store.pos		= iocb->ki_pos;
	op->store.size		= size;
	op->store.i_size	= max(iocb->ki_pos + size, i_size);
	op->ops			= &afs_dio_store_data_operation;

	//if (!is_sync_kiocb(iocb)) {

	ret = afs_do_sync_operation(op);
	if (ret == 0)
		ret = size;

	afs_invalidate_cache(vnode, FSCACHE_INVAL_DIO_WRITE);

	//if (iocb->ki_complete)
	//	iocb->ki_complete(iocb, ret, 0); // only if ret == -EIOCBQUEUED

	_leave(" = %zd", ret);
	return ret;
}
