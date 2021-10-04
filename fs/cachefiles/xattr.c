// SPDX-License-Identifier: GPL-2.0-or-later
/* CacheFiles extended attribute management
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/quotaops.h>
#include <linux/xattr.h>
#include <linux/slab.h>
#include "internal.h"

#define CACHEFILES_COOKIE_TYPE_DATA 1

struct cachefiles_xattr {
	__be64	object_size;	/* Actual size of the object */
	__be64	zero_point;	/* Size after which server has no data not written by us */
	__u8	type;		/* Type of object */
	__u8	content;	/* Content presence (enum cachefiles_content) */
	__u8	data[];		/* netfs coherency data */
} __packed;

static const char cachefiles_xattr_cache[] =
	XATTR_USER_PREFIX "CacheFiles.cache";

/*
 * set the state xattr on a cache file
 */
int cachefiles_set_object_xattr(struct cachefiles_object *object)
{
	struct cachefiles_xattr *buf;
	struct dentry *dentry;
	struct file *file = object->file;
	unsigned int len = object->cookie->aux_len;
	int ret;

	if (!file)
		return -ESTALE;
	dentry = file->f_path.dentry;

	_enter("%x,#%d", object->debug_id, len);

	buf = kmalloc(sizeof(struct cachefiles_xattr) + len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->object_size	= cpu_to_be64(object->cookie->object_size);
	buf->zero_point		= 0;
	buf->type		= CACHEFILES_COOKIE_TYPE_DATA;
	buf->content		= object->content_info;
	if (len > 0)
		memcpy(buf->data, fscache_get_aux(object->cookie), len);

	ret = vfs_setxattr(&init_user_ns, dentry, cachefiles_xattr_cache,
			   buf, sizeof(struct cachefiles_xattr) + len, 0);
	if (ret < 0) {
		trace_cachefiles_coherency(object, file_inode(file)->i_ino,
					   buf->content,
					   cachefiles_coherency_set_fail);
		if (ret != -ENOMEM)
			cachefiles_io_error_obj(
				object,
				"Failed to set xattr with error %d", ret);
	} else {
		trace_cachefiles_coherency(object, file_inode(file)->i_ino,
					   buf->content,
					   cachefiles_coherency_set_ok);
	}

	kfree(buf);
	_leave(" = %d", ret);
	return ret;
}

/*
 * check the consistency between the backing cache and the FS-Cache cookie
 */
int cachefiles_check_auxdata(struct cachefiles_object *object, struct file *file)
{
	struct cachefiles_xattr *buf;
	struct dentry *dentry = file->f_path.dentry;
	unsigned int len = object->cookie->aux_len, tlen;
	const void *p = fscache_get_aux(object->cookie);
	enum cachefiles_coherency_trace why;
	ssize_t xlen;
	int ret = -ESTALE;

	tlen = sizeof(struct cachefiles_xattr) + len;
	buf = kmalloc(tlen, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	xlen = vfs_getxattr(&init_user_ns, dentry, cachefiles_xattr_cache, buf, tlen);
	if (xlen != tlen) {
		if (xlen == -EIO)
			cachefiles_io_error_obj(
				object,
				"Failed to read aux with error %zd", xlen);
		why = cachefiles_coherency_check_xattr;
	} else if (buf->type != CACHEFILES_COOKIE_TYPE_DATA) {
		why = cachefiles_coherency_check_type;
	} else if (memcmp(buf->data, p, len) != 0) {
		why = cachefiles_coherency_check_aux;
	} else if (be64_to_cpu(buf->object_size) != object->cookie->object_size) {
		why = cachefiles_coherency_check_objsize;
	} else if (buf->content == CACHEFILES_CONTENT_DIRTY) {
		// TODO: Begin conflict resolution
		pr_warn("Dirty object in cache\n");
		why = cachefiles_coherency_check_dirty;
	} else {
		why = cachefiles_coherency_check_ok;
		ret = 0;
	}

	trace_cachefiles_coherency(object, file_inode(file)->i_ino,
				   buf->content, why);
	kfree(buf);
	return ret;
}

/*
 * remove the object's xattr to mark it stale
 */
int cachefiles_remove_object_xattr(struct cachefiles_cache *cache,
				   struct dentry *dentry)
{
	int ret;

	ret = vfs_removexattr(&init_user_ns, dentry, cachefiles_xattr_cache);
	if (ret < 0) {
		if (ret == -ENOENT || ret == -ENODATA)
			ret = 0;
		else if (ret != -ENOMEM)
			cachefiles_io_error(cache,
					    "Can't remove xattr from %lu"
					    " (error %d)",
					    d_backing_inode(dentry)->i_ino, -ret);
	}

	_leave(" = %d", ret);
	return ret;
}
