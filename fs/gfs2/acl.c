/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/gfs2_ondisk.h>

#include "gfs2.h"
#include "incore.h"
#include "acl.h"
#include "xattr.h"
#include "glock.h"
#include "inode.h"
#include "meta_io.h"
#include "trans.h"
#include "util.h"

static const char *gfs2_acl_name(int type)
{
	switch (type) {
	case ACL_TYPE_ACCESS:
		return XATTR_POSIX_ACL_ACCESS;
	case ACL_TYPE_DEFAULT:
		return XATTR_POSIX_ACL_DEFAULT;
	}
	return NULL;
}

struct posix_acl *gfs2_get_acl(struct inode *inode, int type)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	bool locked = gfs2_glock_is_locked_by_me(ip->i_gl);
	struct posix_acl *acl = NULL;
	int ret;

	if (!locked) {
		ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					 &gh);
		if (unlikely(ret))
			return ERR_PTR(ret);
	}
	if (ip->i_eattr) {
		const char *name = gfs2_acl_name(type);
		char *data;

		ret = gfs2_xattr_acl_get(ip, name, &data);
		if (ret <= 0) {
			acl = ERR_PTR(ret);
		} else {
			acl = posix_acl_from_xattr(&init_user_ns, data, ret);
			kfree(data);
		}
	}
	if (!locked)
		gfs2_glock_dq_uninit(&gh);
	return acl;
}

int __gfs2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int error;
	int len;
	char *data;
	const char *name = gfs2_acl_name(type);

	BUG_ON(name == NULL);

	if (acl && acl->a_count > GFS2_ACL_MAX_ENTRIES(GFS2_SB(inode)))
		return -E2BIG;

	if (type == ACL_TYPE_ACCESS) {
		umode_t mode = inode->i_mode;

		error = posix_acl_equiv_mode(acl, &mode);
		if (error < 0)
			return error;

		if (error == 0)
			acl = NULL;

		if (mode != inode->i_mode) {
			inode->i_mode = mode;
			mark_inode_dirty(inode);
		}
	}

	if (acl) {
		len = posix_acl_to_xattr(&init_user_ns, acl, NULL, 0);
		if (len == 0)
			return 0;
		data = kmalloc(len, GFP_NOFS);
		if (data == NULL)
			return -ENOMEM;
		error = posix_acl_to_xattr(&init_user_ns, acl, data, len);
		if (error < 0)
			goto out;
	} else {
		data = NULL;
		len = 0;
	}

	error = __gfs2_xattr_set(inode, name, data, len, 0, GFS2_EATYPE_SYS);
	if (error)
		goto out;
	set_cached_acl(inode, type, acl);
out:
	kfree(data);
	return error;
}

int gfs2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	if (ret == 0) {
		ret = __gfs2_set_acl(inode, acl, type);
		gfs2_glock_dq_uninit(&gh);
	}
	return ret;
}
