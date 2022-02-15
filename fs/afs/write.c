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
#include <trace/events/netfs.h>
#include "internal.h"

#ifdef CONFIG_AFS_FSCACHE
/*
 * Mark a page as having been made dirty and thus needing writeback.  We also
 * need to pin the cache object to write back to.
 */
bool afs_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	return fscache_dirty_folio(mapping, folio,
				afs_vnode_cache(AFS_FS_I(mapping->host)));
}
#endif

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
	loff_t size = iov_iter_count(iter);
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

	afs_op_set_vnode(op, 0, vnode);
	op->file[0].dv_delta = 1;
	op->file[0].modification = true;
	op->store.write_iter = iter;
	op->store.pos = pos;
	op->store.size = size;
	op->store.i_size = max(pos + size, vnode->netfs.remote_i_size);
	op->store.laundering = laundering;
	op->mtime = vnode->netfs.inode.i_mtime;
	op->flags |= AFS_OPERATION_UNINTR;
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

static void afs_upload_to_server(struct netfs_io_subrequest *subreq)
{
	struct afs_vnode *vnode = AFS_FS_I(subreq->rreq->inode);
	ssize_t ret;

	_enter("%x[%x]", subreq->rreq->debug_id, subreq->debug_index);

	trace_netfs_sreq(subreq, netfs_sreq_trace_submit);
	ret = afs_store_data(vnode, &subreq->iter, subreq->start, false);
	netfs_write_subrequest_terminated(subreq, ret < 0 ? ret : subreq->len,
					  false);
}

static void afs_upload_to_server_worker(struct work_struct *work)
{
	struct netfs_io_subrequest *subreq =
		container_of(work, struct netfs_io_subrequest, work);

	afs_upload_to_server(subreq);
}

/*
 * Set up write requests for a writeback slice.  We need to add a write request
 * for each write we want to make.
 */
void afs_create_write_requests(struct netfs_io_request *wreq)
{
	struct netfs_io_subrequest *subreq;
	struct netfs_dirty_region *region;

	list_for_each_entry(region, &wreq->regions, dirty_link) {
		if (region->type == NETFS_COPY_TO_CACHE)
			continue;
		subreq = netfs_create_write_request(wreq, NETFS_UPLOAD_TO_SERVER,
						    region->from,
						    region->to - region->from,
						    afs_upload_to_server_worker);
		if (subreq)
			netfs_queue_write_request(subreq);
	}
}

/*
 * flush any dirty pages for this process, and check for write errors.
 * - the return status from this call provides a reliable indication of
 *   whether any write errors occurred for this process.
 */
int afs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct afs_file *af = file->private_data;
	int ret;

	_enter("{%llx:%llu},{n=%pD},%d",
	       vnode->fid.vid, vnode->fid.vnode, file,
	       datasync);

	ret = afs_validate(vnode, af->key);
	if (ret < 0)
		return ret;

	return file_write_and_wait_range(file, start, end);
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

	if (!mapping_tagged(&vnode->netfs.inode.i_data, PAGECACHE_TAG_WRITEBACK) &&
	    !mapping_tagged(&vnode->netfs.inode.i_data, PAGECACHE_TAG_DIRTY)) {
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
int afs_launder_folio(struct folio *folio)
{
	struct afs_vnode *vnode = AFS_FS_I(folio_inode(folio));
	struct iov_iter iter;
	struct bio_vec bv[1];
	loff_t i_size, pos;
	size_t len;
	int ret = 0;

	_enter("{%lx}", folio->index);

	if (folio_clear_dirty_for_io(folio)) {
		i_size = i_size_read(&vnode->netfs.inode);
		len = folio_size(folio);
		pos = folio_pos(folio);
		if (pos >= i_size)
			goto out;
		if (i_size - pos < len)
			len = i_size - pos;

		bv[0].bv_page = &folio->page;
		bv[0].bv_offset = 0;
		bv[0].bv_len = len;
		iov_iter_bvec(&iter, WRITE, bv, 1, len);

		ret = afs_store_data(vnode, &iter, pos, true);
	}

out:
	folio_wait_fscache(folio);
	return ret;
}
