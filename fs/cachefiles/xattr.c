/* CacheFiles extended attribute management
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

//#define __KDEBUG
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/quotaops.h>
#include <linux/xattr.h>
#include <linux/slab.h>
#include "internal.h"

static const char cachefiles_xattr_cache[] =
	XATTR_USER_PREFIX "CacheFiles.cache";
static const char cachefiles_xattr_cull_index[] =
	XATTR_USER_PREFIX "CacheFiles.cull_index";
static const char cachefiles_xattr_atime_base[] =
	XATTR_USER_PREFIX "CacheFiles.atime_base";

/*
 * check the type label on the root object
 * - done using xattrs
 */
int cachefiles_check_root_object_type(struct cachefiles_object *object)
{
	struct dentry *dentry = object->dentry;
	char type[3], xtype[3];
	int ret;

	ASSERT(dentry);
	ASSERT(dentry->d_inode);

	if (!object->fscache.cookie)
		strcpy(type, "C3");
	else
		snprintf(type, 3, "%02x", object->fscache.cookie->def->type);

	_enter("%p{%s}", object, type);

	/* attempt to install a type label directly */
	ret = vfs_setxattr(dentry, cachefiles_xattr_cache, type, 2,
			   XATTR_CREATE);
	if (ret == 0) {
		_debug("SET"); /* we succeeded */
		goto error;
	}

	if (ret != -EEXIST) {
		pr_err("Can't set xattr on %pd [%lu] (err %d)\n",
		       dentry, dentry->d_inode->i_ino,
		       -ret);
		goto error;
	}

	/* read the current type label */
	ret = vfs_getxattr(dentry, cachefiles_xattr_cache, xtype, 3);
	if (ret < 0) {
		if (ret == -ERANGE)
			goto bad_type_length;

		pr_err("Can't read xattr on %pd [%lu] (err %d)\n",
		       dentry, dentry->d_inode->i_ino,
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
	       dentry->d_inode->i_ino);
	ret = -EIO;
	goto error;

bad_type:
	xtype[2] = 0;
	pr_err("Cache object %pd [%lu] type %s not %s\n",
	       dentry, dentry->d_inode->i_ino,
	       xtype, type);
	ret = -EIO;
	goto error;
}

/*
 * set the state xattr on a cache file
 */
int cachefiles_set_object_xattr(struct cachefiles_object *object,
				struct cachefiles_xattr *auxdata)
{
	struct dentry *dentry = object->dentry;
	int ret;

	ASSERT(dentry);

	_enter("%p,#%d", object, auxdata->len);

	/* attempt to install the cache metadata directly */
	_debug("SET #%u [cs=%d]",
	       auxdata->len, le32_to_cpu(auxdata->cull_slot));

	ret = vfs_setxattr(dentry, cachefiles_xattr_cache,
			   &auxdata->cull_slot, auxdata->len, 0);
	if (ret < 0 && ret != -ENOMEM)
		cachefiles_io_error_obj(
			object, "Failed to set xattr with error %d", ret);

	_leave(" = %d", ret);
	return ret;
}

/*
 * update the state xattr on a cache file
 */
int cachefiles_update_object_xattr(struct cachefiles_object *object,
				   struct cachefiles_xattr *auxdata)
{
	struct dentry *dentry = object->dentry;
	int ret;

	ASSERT(dentry);

	_enter("%p,#%d", object, auxdata->len);

	/* attempt to install the cache metadata directly */
	_debug("UPD #%u [cs=%u]",
	       auxdata->len, le32_to_cpu(auxdata->cull_slot));

	ret = vfs_setxattr(dentry, cachefiles_xattr_cache,
			   &auxdata->cull_slot, auxdata->len,
			   XATTR_REPLACE);
	if (ret < 0 && ret != -ENOMEM)
		cachefiles_io_error_obj(
			object,
			"Failed to update xattr with error %d", ret);

	_leave(" = %d", ret);
	return ret;
}

/*
 * check the consistency between the backing cache and the FS-Cache cookie
 */
int cachefiles_check_auxdata(struct cachefiles_object *object)
{
	struct cachefiles_xattr *auxbuf;
	enum fscache_checkaux validity;
	struct dentry *dentry = object->dentry;
	ssize_t xlen;
	int ret;

	ASSERT(dentry);
	ASSERT(dentry->d_inode);
	ASSERT(object->fscache.cookie->def->check_aux);

	auxbuf = kmalloc(sizeof(struct cachefiles_xattr) + 512, GFP_KERNEL);
	if (!auxbuf)
		return -ENOMEM;

	xlen = vfs_getxattr(dentry, cachefiles_xattr_cache,
			    &auxbuf->type, 512 + 1);
	ret = -ESTALE;
	if (xlen < 1 ||
	    auxbuf->type != object->fscache.cookie->def->type)
		goto error;

	xlen--;
	validity = fscache_check_aux(&object->fscache, &auxbuf->data, xlen);
	if (validity != FSCACHE_CHECKAUX_OKAY)
		goto error;

	ret = 0;
error:
	kfree(auxbuf);
	return ret;
}

/*
 * check the state xattr on a cache file
 * - return -ESTALE if the object should be deleted
 */
int cachefiles_check_object_xattr(struct cachefiles_object *object,
				  struct cachefiles_xattr *auxdata)
{
	struct cachefiles_xattr *auxbuf;
	struct dentry *dentry = object->dentry;
	int ret;

	_enter("%p,#%d", object, auxdata->len);

	ASSERT(dentry);
	ASSERT(dentry->d_inode);

	auxbuf = kmalloc(sizeof(struct cachefiles_xattr) + 512, cachefiles_gfp);
	if (!auxbuf) {
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	/* read the current cull slot number and type label */
	ret = vfs_getxattr(dentry, cachefiles_xattr_cache,
			   &auxbuf->cull_slot, 512 + 5);
	if (ret < 0) {
		if (ret == -ENODATA)
			goto stale; /* no attribute - power went off
				     * mid-cull? */

		if (ret == -ERANGE)
			goto bad_type_length;

		cachefiles_io_error_obj(object,
					"Can't read xattr on %lu (err %d)",
					dentry->d_inode->i_ino, -ret);
		goto error;
	}

	/* check the on-disk object */
	if (ret < 5)
		goto bad_type_length;

	if (auxbuf->type != auxdata->type)
		goto stale;

	auxbuf->len = ret;

	/* consult the netfs */
	if (object->fscache.cookie->def->check_aux) {
		enum fscache_checkaux result;
		unsigned int dlen;

		dlen = auxbuf->len - 5;

		_debug("checkaux %s #%u",
		       object->fscache.cookie->def->name, dlen);

		result = fscache_check_aux(&object->fscache,
					   &auxbuf->data, dlen);

		switch (result) {
			/* entry okay as is */
		case FSCACHE_CHECKAUX_OKAY:
			goto okay;

			/* entry requires update */
		case FSCACHE_CHECKAUX_NEEDS_UPDATE:
			break;

			/* entry requires deletion */
		case FSCACHE_CHECKAUX_OBSOLETE:
			goto stale;

		default:
			BUG();
		}

		/* update the current label */
		ret = vfs_setxattr(dentry, cachefiles_xattr_cache,
				   &auxdata->type, auxdata->len,
				   XATTR_REPLACE);
		if (ret < 0) {
			cachefiles_io_error_obj(object,
						"Can't update xattr on %lu"
						" (error %d)",
						dentry->d_inode->i_ino, -ret);
			goto error;
		}
	}

okay:
	auxdata->cull_slot = auxbuf->cull_slot;
	ret = 0;

error:
	kfree(auxbuf);
	_leave(" = %d", ret);
	return ret;

bad_type_length:
	pr_err("Cache object %lu xattr length incorrect\n",
	       dentry->d_inode->i_ino);
	ret = -EIO;
	goto error;

stale:
	ret = -ESTALE;
	goto error;
}

/*
 * read the slot number from a file
 */
unsigned cachefiles_read_cull_slot(struct cachefiles_cache *cache,
				   struct dentry *dentry)
{
	__le32 slot;
	int ret;

	_enter("");

	/* read the current cull slot number and type label */
	ret = vfs_getxattr(dentry, cachefiles_xattr_cache, &slot, 4);
	if (ret < 4) {
		_leave(" = no cull slot");
		return CACHEFILES_NO_CULL_SLOT;
	}

	_leave(" = %d", le32_to_cpu(slot));
	return le32_to_cpu(slot);
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
					    dentry->d_inode->i_ino, -ret);
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * check the label on the culling index
 * - done using xattrs
 */
int cachefiles_check_cull_index(struct cachefiles_cache *cache)
{
	struct dentry *dentry = cache->cull_index->f_path.dentry;
	char label[3], xlabel[3];
	int ret;

	ASSERT(dentry);
	ASSERT(dentry->d_inode);

	snprintf(label, 3, "%02x", cache->cx_entsize);

	_enter("{%s}", label);

	/* attempt to install a label directly */
	ret = vfs_setxattr(dentry, cachefiles_xattr_cull_index, label, 2,
			   XATTR_CREATE);
	if (ret == 0) {
		_debug("SET"); /* we succeeded */
		goto error;
	}

	if (ret != -EEXIST) {
		pr_err("Can't set xattr on %*.*s [%lu] (err %d)",
		       dentry->d_name.len, dentry->d_name.len,
		       dentry->d_name.name, dentry->d_inode->i_ino,
		       -ret);
		goto error;
	}

	/* read the current label */
	ret = vfs_getxattr(dentry, cachefiles_xattr_cull_index, xlabel, 3);
	if (ret < 0) {
		if (ret == -ERANGE)
			goto bad_label_length;

		pr_err("Can't read xattr on %*.*s [%lu] (err %d)",
		       dentry->d_name.len, dentry->d_name.len,
		       dentry->d_name.name, dentry->d_inode->i_ino,
		       -ret);
		goto error;
	}

	/* check the type is what we're expecting */
	if (ret != 2)
		goto bad_label_length;

	if (xlabel[0] != label[0] || xlabel[1] != label[1])
		goto bad_label;

	ret = 0;

error:
	_leave(" = %d", ret);
	return ret;

bad_label_length:
	pr_err("Cache cull index xattr length incorrect");
	ret = -EIO;
	goto error;

bad_label:
	xlabel[2] = 0;
	pr_err("Cache cull index xattr specifies entry size of 0x%s not 0x%s",
	       xlabel, label);
	ret = -EIO;
	goto error;
}

/*
 * get/set the atime base from the cull_atimes file
 * - done using xattrs
 */
int cachefiles_get_set_atime_base(struct cachefiles_cache *cache)
{
	struct dentry *dentry = cache->cull_atimes->f_path.dentry;
	char label[16 + 1], *end;
	int ret;

	ASSERT(dentry);
	ASSERT(dentry->d_inode);

	cache->atime_base = get_seconds();
	sprintf(label, "%016lx", cache->atime_base);

	_enter("{%s}", label);

	/* attempt to install a label directly */
	ret = vfs_setxattr(dentry, cachefiles_xattr_atime_base, label, 16,
			   XATTR_CREATE);
	if (ret == 0) {
		_debug("SET"); /* we succeeded */
		goto error;
	}

	if (ret != -EEXIST) {
		pr_err("Can't set xattr on %*.*s [%lu] (err %d)",
		       dentry->d_name.len, dentry->d_name.len,
		       dentry->d_name.name, dentry->d_inode->i_ino,
		       -ret);
		goto error;
	}

	/* read the current label */
	ret = vfs_getxattr(dentry, cachefiles_xattr_atime_base, label, 17);
	if (ret < 0) {
		if (ret == -ERANGE)
			goto bad_label_length;

		pr_err("Can't read xattr on %*.*s [%lu] (err %d)",
		       dentry->d_name.len, dentry->d_name.len,
		       dentry->d_name.name, dentry->d_inode->i_ino,
		       -ret);
		goto error;
	}

	/* attempt to parse the atime base */
	if (ret != 16)
		goto bad_label_length;

	cache->atime_base = simple_strtoull(label, &end, 16);
	if (end - label != 16 || *end != '\0') {
		pr_err("Failed to parse xattr on %*.*s [%lu]",
		       dentry->d_name.len, dentry->d_name.len,
		       dentry->d_name.name, dentry->d_inode->i_ino);
		ret = -EIO;
		goto error;
	}

	ret = 0;

error:
	_leave(" = %d [%lx]", ret, cache->atime_base);
	return ret;

bad_label_length:
	pr_err("Cache atime_base xattr length incorrect");
	ret = -EIO;
	goto error;
}

/**
 * force update a slot to be the one specified.
 * caller is responsible for locking cache->xattr_mutex.
 *
 * @return 0 on success, a negated errno value otherwise.
 */
int cachefiles_reset_slot(struct dentry *dentry, unsigned slot)
{
	struct cachefiles_xattr *xbuf;
	int ret = 0;
	ssize_t len;

	_enter("%p, %u", dentry, slot);

	xbuf = kmalloc(sizeof(struct cachefiles_xattr) + 512, cachefiles_gfp);
	if (!xbuf) {
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	len = vfs_getxattr(dentry, cachefiles_xattr_cache, &xbuf->cull_slot,
			   512 + sizeof(struct cachefiles_xattr));
	if (len < 0) {
		kerror("Failed to read xattrs on %s", dentry->d_name.name);
		ret = len;
		goto error;
	}
	xbuf->cull_slot = slot;

	ret = vfs_setxattr(dentry, cachefiles_xattr_cache, &xbuf->cull_slot, len,
			   XATTR_REPLACE);
	if (ret) {
		kerror("Failed to replace xattrs on %s", dentry->d_name.name);
		if (ret == ENOMEM)
			ret = -ENOMEM;
		else
			ret = -EIO;
		goto error;
	}

error:
	kfree(xbuf);
	return ret;
}
