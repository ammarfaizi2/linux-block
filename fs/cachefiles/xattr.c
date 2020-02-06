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
 * check the type label on an object
 * - done using xattrs
 */
int cachefiles_check_object_type(struct cachefiles_object *object)
{
	struct dentry *dentry = object->dentry;
	char type[3], xtype[3];
	int ret;

	ASSERT(dentry);
	ASSERT(d_backing_inode(dentry));

	if (!object->fscache.cookie)
		strcpy(type, "C3");
	else
		snprintf(type, 3, "%02x", object->fscache.cookie->type);

	_enter("%x{%s}", object->fscache.debug_id, type);

	/* attempt to install a type label directly */
	ret = vfs_setxattr(dentry, cachefiles_xattr_cache, type, 2,
			   XATTR_CREATE);
	if (ret == 0) {
		_debug("SET"); /* we succeeded */
		goto error;
	}

	if (ret != -EEXIST) {
		pr_err("Can't set xattr on %pd [%lu] (err %d)\n",
		       dentry, d_backing_inode(dentry)->i_ino,
		       -ret);
		goto error;
	}

	/* read the current type label */
	ret = vfs_getxattr(dentry, cachefiles_xattr_cache, xtype, 3);
	if (ret < 0) {
		if (ret == -ERANGE)
			goto bad_type_length;

		pr_err("Can't read xattr on %pd [%lu] (err %d)\n",
		       dentry, d_backing_inode(dentry)->i_ino,
		       -ret);
		goto error;
	}

	/* check the type is what we're expecting */
	if (ret != 2)
		goto bad_type_length;

	if (xtype[0] != type[0] || xtype[1] != type[1])
		goto bad_type;

	ret = 0;

error:
	_leave(" = %d", ret);
	return ret;

bad_type_length:
	pr_err("Cache object %lu type xattr length incorrect\n",
	       d_backing_inode(dentry)->i_ino);
	ret = -EIO;
	goto error;

bad_type:
	xtype[2] = 0;
	pr_err("Cache object %pd [%lu] type %s not %s\n",
	       dentry, d_backing_inode(dentry)->i_ino,
	       xtype, type);
	ret = -EIO;
	goto error;
}

/*
 * set the state xattr on a cache file
 */
int cachefiles_set_object_xattr(struct cachefiles_object *object)
{
	struct cachefiles_xattr *buf;
	struct dentry *dentry = object->dentry;
	unsigned int len = object->fscache.cookie->aux_len;
	int ret;

	if (!dentry)
		return -ESTALE;

	_enter("%x,#%d", object->fscache.debug_id, len);

	buf = kmalloc(sizeof(struct cachefiles_xattr) + len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->object_size	= cpu_to_be64(object->fscache.cookie->object_size);
	buf->zero_point		= cpu_to_be64(object->fscache.cookie->zero_point);
	buf->type		= object->fscache.cookie->type;
	buf->content		= object->content_info;
	if (test_bit(FSCACHE_OBJECT_LOCAL_WRITE, &object->fscache.flags))
		buf->content	= CACHEFILES_CONTENT_DIRTY;
	if (len > 0)
		memcpy(buf->data, fscache_get_aux(object->fscache.cookie), len);

	ret = vfs_setxattr(dentry, cachefiles_xattr_cache,
			   buf, sizeof(struct cachefiles_xattr) + len, 0);
	if (ret < 0) {
		trace_cachefiles_coherency(object, d_inode(dentry)->i_ino,
					   buf->content,
					   cachefiles_coherency_set_fail);
		if (ret != -ENOMEM)
			cachefiles_io_error_obj(
				object,
				"Failed to set xattr with error %d", ret);
	} else {
		trace_cachefiles_coherency(object, d_inode(dentry)->i_ino,
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
int cachefiles_check_auxdata(struct cachefiles_object *object)
{
	struct cachefiles_xattr *buf;
	struct dentry *dentry = object->dentry;
	unsigned int len = object->fscache.cookie->aux_len, tlen;
	const void *p = fscache_get_aux(object->fscache.cookie);
	enum cachefiles_coherency_trace why;
	ssize_t xlen;
	int ret = -ESTALE;

	ASSERT(dentry);
	ASSERT(d_backing_inode(dentry));

	tlen = sizeof(struct cachefiles_xattr) + len;
	buf = kmalloc(tlen, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	xlen = vfs_getxattr(dentry, cachefiles_xattr_cache, buf, tlen);
	if (xlen != tlen) {
		if (xlen == -EIO)
			cachefiles_io_error_obj(
				object,
				"Failed to read aux with error %zd", xlen);
		why = cachefiles_coherency_check_xattr;
	} else if (buf->type != object->fscache.cookie->type) {
		why = cachefiles_coherency_check_type;
	} else if (buf->content >= nr__cachefiles_content) {
		why = cachefiles_coherency_check_content;
	} else if (memcmp(buf->data, p, len) != 0) {
		why = cachefiles_coherency_check_aux;
	} else if (be64_to_cpu(buf->object_size) != object->fscache.cookie->object_size) {
		why = cachefiles_coherency_check_objsize;
	} else if (buf->content == CACHEFILES_CONTENT_DIRTY) {
		// TODO: Begin conflict resolution
		pr_warn("Dirty object in cache\n");
		why = cachefiles_coherency_check_dirty;
	} else {
		object->fscache.cookie->zero_point = be64_to_cpu(buf->zero_point);
		object->content_info = buf->content;
		why = cachefiles_coherency_check_ok;
		ret = 0;
	}

	trace_cachefiles_coherency(object, d_inode(dentry)->i_ino,
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

	ret = vfs_removexattr(dentry, cachefiles_xattr_cache);
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

/*
 * Stick a marker on the cache object to indicate that it's dirty.
 */
int cachefiles_prepare_to_write(struct fscache_object *_object)
{
	int ret;
	const struct cred *saved_cred;
	struct cachefiles_object *object =
		container_of(_object, struct cachefiles_object, fscache);
	struct cachefiles_cache *cache =
		container_of(_object->cache, struct cachefiles_cache, cache);

	_enter("c=%08x", object->fscache.cookie->debug_id);

	cachefiles_begin_secure(cache, &saved_cred);
	ret = cachefiles_set_object_xattr(object);
	cachefiles_end_secure(cache, saved_cred);

	return ret;
}
