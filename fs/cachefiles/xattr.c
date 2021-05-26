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
	uint8_t				type;
	uint8_t				data[];
} __packed;

static const char cachefiles_xattr_cache[] =
	XATTR_USER_PREFIX "CacheFiles.cache";

/*
 * set the state xattr on a cache file
 */
int cachefiles_set_object_xattr(struct cachefiles_object *object,
				unsigned int xattr_flags)
{
	struct cachefiles_xattr *buf;
	struct dentry *dentry = object->dentry;
	unsigned int len = object->cookie->aux_len;
	int ret;

	if (!dentry)
		return -ESTALE;

	_enter("%x,#%d", object->debug_id, len);

	buf = kmalloc(sizeof(struct cachefiles_xattr) + len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->type = object->cookie->type;
	if (len > 0)
		memcpy(buf->data, fscache_get_aux(object->cookie), len);

	clear_bit(FSCACHE_COOKIE_AUX_UPDATED, &object->cookie->flags);
	ret = vfs_setxattr(&init_user_ns, dentry, cachefiles_xattr_cache,
			   buf, sizeof(struct cachefiles_xattr) + len,
			   xattr_flags);
	kfree(buf);
	if (ret < 0 && ret != -ENOMEM)
		cachefiles_io_error_obj(
			object,
			"Failed to set xattr with error %d", ret);

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
	unsigned int len = object->cookie->aux_len, tlen;
	const void *p = fscache_get_aux(object->cookie);
	ssize_t ret;

	ASSERT(dentry);
	ASSERT(d_backing_inode(dentry));

	tlen = sizeof(struct cachefiles_xattr) + len;
	buf = kmalloc(tlen, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = vfs_getxattr(&init_user_ns, dentry, cachefiles_xattr_cache, buf, tlen);
	if (ret == tlen &&
	    buf->type == object->cookie->type &&
	    memcmp(buf->data, p, len) == 0)
		ret = 0;
	else
		ret = -ESTALE;

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
