/*
 * Copyright (c) 2006, 2007 QLogic Corporation. All rights reserved.
 * Copyright (c) 2006 PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>

#include "ipath_kernel.h"

#define IPATHFS_MAGIC 0x726a77

struct infinipath_stats ipath_stats;
EXPORT_SYMBOL(ipath_stats);
static ssize_t atomic_stats_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, &ipath_stats,
				       sizeof ipath_stats);
}

static const struct file_operations atomic_stats_ops = {
	.read = atomic_stats_read,
	.llseek = default_llseek,
};


static int ipathfs_fill_super(struct super_block *sb, void *data,
			      int silent)
{
	static struct tree_descr files[] = {
		[2] = {"atomic_stats", &atomic_stats_ops, S_IRUGO},
		{""},
	};

	return simple_fill_super(sb, IPATHFS_MAGIC, files);
}

static struct dentry *ipathfs_mount(struct file_system_type *fs_type,
			int flags, const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, ipathfs_fill_super);
}

static struct file_system_type ipathfs_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"ipathfs",
	.mount =	ipathfs_mount,
	.kill_sb =	kill_litter_super,
};

static struct vfsmount *mnt;
static int count;

struct dentry *ipathfs_pin(void)
{
	int err = simple_pin_fs(&ipathfs_fs_type, &mnt, &count);
	return err ? ERR_PTR(err) : mnt->mnt_root;
}
EXPORT_SYMBOL(ipathfs_pin);

void ipathfs_unpin(void)
{
	simple_release_fs(&mnt, &count);
}
EXPORT_SYMBOL(ipathfs_unpin);

static int __init ipath_init_ipathfs(void)
{
	return register_filesystem(&ipathfs_fs_type);
}

static void __exit ipath_exit_ipathfs(void)
{
	unregister_filesystem(&ipathfs_fs_type);
}
module_init(ipath_init_ipathfs)
module_exit(ipath_exit_ipathfs)
