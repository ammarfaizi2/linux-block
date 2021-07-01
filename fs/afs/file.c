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
#include <linux/netfs.h>
#include "internal.h"

static int afs_file_mmap(struct file *file, struct vm_area_struct *vma);
static int afs_symlink_readpage(struct file *file, struct page *page);

const struct file_operations afs_file_operations = {
	.open		= afs_open,
	.release	= afs_release,
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= netfs_file_write_iter,
	.mmap		= afs_file_mmap,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fsync		= afs_fsync,
	.lock		= afs_lock,
	.flock		= afs_flock,
};

const struct inode_operations afs_file_inode_operations = {
	.getattr	= afs_getattr,
	.setattr	= afs_setattr,
	.permission	= afs_permission,
};

const struct address_space_operations afs_file_aops = {
	.readpage	= netfs_readpage,
	.readahead	= netfs_readahead,
	.set_page_dirty	= afs_set_page_dirty,
	.launder_page	= afs_launder_page,
	.releasepage	= netfs_releasepage,
	.invalidatepage	= netfs_invalidatepage,
	.writepage	= afs_writepage,
	.writepages	= netfs_writepages,
};

const struct address_space_operations afs_symlink_aops = {
	.readpage	= afs_symlink_readpage,
	.releasepage	= netfs_releasepage,
	.invalidatepage	= netfs_invalidatepage,
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
	if (wbk && refcount_dec_and_test(&wbk->usage)) {
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
		set_bit(NETFS_ICTX_NEW_CONTENT,
			&netfs_i_context(&vnode->vfs_inode)->flags);

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
	int ret = 0;

	_enter("{%llx:%llu},", vnode->fid.vid, vnode->fid.vnode);

	if ((file->f_mode & FMODE_WRITE))
		ret = vfs_fsync(file, 0);

	file->private_data = NULL;
	if (af->wb)
		afs_put_wb_key(af->wb);
	key_put(af->key);
	kfree(af);
	afs_prune_wb_keys(vnode);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Allocate a new read record.
 */
struct afs_read *afs_alloc_read(gfp_t gfp)
{
	struct afs_read *req;

	req = kzalloc(sizeof(struct afs_read), gfp);
	if (req)
		refcount_set(&req->usage, 1);

	return req;
}

/*
 * Dispose of a ref to a read record.
 */
void afs_put_read(struct afs_read *req)
{
	if (refcount_dec_and_test(&req->usage)) {
		if (req->cleanup)
			req->cleanup(req);
		key_put(req->key);
		kfree(req);
	}
}

static void afs_fetch_data_notify(struct afs_operation *op)
{
	struct afs_read *req = op->fetch.req;
	struct netfs_read_subrequest *subreq = req->subreq;
	int error = op->error;

	if (error == -ECONNABORTED)
		error = afs_abort_to_error(op->ac.abort_code);
	req->error = error;

	if (subreq) {
		__set_bit(NETFS_SREQ_CLEAR_TAIL, &subreq->flags);
		netfs_subreq_terminated(subreq, error ?: req->actual_len, false);
		req->subreq = NULL;
	} else if (req->done) {
		req->done(req);
	}
}

static void afs_fetch_data_success(struct afs_operation *op)
{
	struct afs_vnode *vnode = op->file[0].vnode;

	_enter("op=%08x", op->debug_id);
	afs_vnode_commit_status(op, &op->file[0]);
	afs_stat_v(vnode, n_fetches);
	atomic_long_add(op->fetch.req->actual_len, &op->net->n_fetch_bytes);
	afs_fetch_data_notify(op);
}

static void afs_fetch_data_put(struct afs_operation *op)
{
	op->fetch.req->error = op->error;
	afs_put_read(op->fetch.req);
}

static const struct afs_operation_ops afs_fetch_data_operation = {
	.issue_afs_rpc	= afs_fs_fetch_data,
	.issue_yfs_rpc	= yfs_fs_fetch_data,
	.success	= afs_fetch_data_success,
	.aborted	= afs_check_for_remote_deletion,
	.failed		= afs_fetch_data_notify,
	.put		= afs_fetch_data_put,
};

/*
 * Fetch file data from the volume.
 */
int afs_fetch_data(struct afs_vnode *vnode, struct afs_read *req)
{
	struct afs_operation *op;

	_enter("%s{%llx:%llu.%u},%x,,,",
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(req->key));

	op = afs_alloc_operation(req->key, vnode->volume);
	if (IS_ERR(op)) {
		if (req->subreq)
			netfs_subreq_terminated(req->subreq, PTR_ERR(op), false);
		return PTR_ERR(op);
	}

	afs_op_set_vnode(op, 0, vnode);

	op->fetch.req	= afs_get_read(req);
	op->ops		= &afs_fetch_data_operation;
	return afs_do_sync_operation(op);
}

static void afs_req_issue_op(struct netfs_read_subrequest *subreq)
{
	struct afs_vnode *vnode = AFS_FS_I(subreq->rreq->inode);
	struct afs_read *fsreq;

	fsreq = afs_alloc_read(GFP_NOFS);
	if (!fsreq)
		return netfs_subreq_terminated(subreq, -ENOMEM, false);

	fsreq->subreq	= subreq;
	fsreq->pos	= subreq->start + subreq->transferred;
	fsreq->len	= subreq->len   - subreq->transferred;
	fsreq->key	= subreq->rreq->netfs_priv;
	fsreq->vnode	= vnode;
	fsreq->iter	= &subreq->iter;

	afs_fetch_data(fsreq->vnode, fsreq);
}

static int afs_symlink_readpage(struct file *file, struct page *page)
{
	struct afs_vnode *vnode = AFS_FS_I(page_mapping(page)->host);
	struct afs_read *fsreq;
	struct folio *folio = page_folio(page);
	int ret;

	fsreq = afs_alloc_read(GFP_NOFS);
	if (!fsreq)
		return -ENOMEM;

	fsreq->pos	= folio_file_pos(folio);
	fsreq->len	= folio_size(folio);
	fsreq->vnode	= vnode;
	fsreq->iter	= &fsreq->def_iter;
	iov_iter_xarray(&fsreq->def_iter, READ, &page->mapping->i_pages,
			fsreq->pos, fsreq->len);

	ret = afs_fetch_data(fsreq->vnode, fsreq);
	page_endio(&folio->page, false, ret);
	return ret;
}

static void afs_init_rreq(struct netfs_read_request *rreq, struct file *file)
{
	rreq->netfs_priv = key_get(afs_file_key(file));
}

static int afs_begin_cache_operation(struct netfs_read_request *rreq)
{
	struct afs_vnode *vnode = AFS_FS_I(rreq->inode);

	return fscache_begin_read_operation(rreq, afs_vnode_cache(vnode));
}

static int afs_check_write_begin(struct file *file, loff_t pos, unsigned len,
				 struct folio *folio, void **_fsdata)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));

	return test_bit(AFS_VNODE_DELETED, &vnode->flags) ? -ESTALE : 0;
}

static void afs_priv_cleanup(struct address_space *mapping, void *netfs_priv)
{
	key_put(netfs_priv);
}

static void afs_init_dirty_region(struct netfs_dirty_region *region, struct file *file)
{
	region->netfs_priv = key_get(afs_file_key(file));
}

static void afs_split_dirty_region(struct netfs_dirty_region *region)
{
	key_get(region->netfs_priv);
}

static void afs_free_dirty_region(struct netfs_dirty_region *region)
{
	key_put(region->netfs_priv);
}

static void afs_init_wreq(struct netfs_write_request *wreq)
{
	//wreq->netfs_priv = key_get(afs_file_key(file));
}

static void afs_update_i_size(struct file *file, loff_t new_i_size)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	loff_t i_size;

	write_seqlock(&vnode->cb_lock);
	i_size = i_size_read(&vnode->vfs_inode);
	if (new_i_size > i_size)
		i_size_write(&vnode->vfs_inode, new_i_size);
	write_sequnlock(&vnode->cb_lock);
	fscache_update_cookie(afs_vnode_cache(vnode), NULL);
}

const struct netfs_request_ops afs_req_ops = {
	.init_rreq		= afs_init_rreq,
	.begin_cache_operation	= afs_begin_cache_operation,
	.check_write_begin	= afs_check_write_begin,
	.issue_op		= afs_req_issue_op,
	.cleanup		= afs_priv_cleanup,
	.init_dirty_region	= afs_init_dirty_region,
	.split_dirty_region	= afs_split_dirty_region,
	.free_dirty_region	= afs_free_dirty_region,
	.update_i_size		= afs_update_i_size,
	.init_wreq		= afs_init_wreq,
	.create_write_operations = afs_create_write_operations,
	.encrypt_block		= afs_encrypt_block,
};

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
