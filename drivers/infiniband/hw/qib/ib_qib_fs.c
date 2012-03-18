/*
 * Copyright (c) 2006, 2007, 2008, 2009 QLogic Corporation. All rights reserved.
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
#include "qib.h"

#define QIBFS_MAGIC 0x726a77

struct qlogic_ib_stats qib_stats;
EXPORT_SYMBOL(qib_stats);

static ssize_t driver_stats_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, &qib_stats,
				       sizeof qib_stats);
}

/*
 * driver stats field names, one line per stat, single string.  Used by
 * programs like ipathstats to print the stats in a way which works for
 * different versions of drivers, without changing program source.
 * if qlogic_ib_stats changes, this needs to change.  Names need to be
 * 12 chars or less (w/o newline), for proper display by ipathstats utility.
 */
static const char qib_statnames[] =
	"KernIntr\n"
	"ErrorIntr\n"
	"Tx_Errs\n"
	"Rcv_Errs\n"
	"H/W_Errs\n"
	"NoPIOBufs\n"
	"CtxtsOpen\n"
	"RcvLen_Errs\n"
	"EgrBufFull\n"
	"EgrHdrFull\n"
	;

static ssize_t driver_names_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, qib_statnames,
		sizeof qib_statnames - 1); /* no null */
}

static const struct file_operations driver_ops[] = {
	{ .read = driver_stats_read, .llseek = generic_file_llseek, },
	{ .read = driver_names_read, .llseek = generic_file_llseek, },
};

/*
 * This fills everything in when the fs is mounted, to handle umount/mount
 * after device init.  The direct add_cntr_files() call handles adding
 * them from the init code, when the fs is already mounted.
 */
static int qibfs_fill_super(struct super_block *sb, void *data, int silent)
{
	static struct tree_descr files[] = {
		[2] = {"driver_stats", &driver_ops[0], S_IRUGO},
		[3] = {"driver_stats_names", &driver_ops[1], S_IRUGO},
		{""},
	};

	return simple_fill_super(sb, QIBFS_MAGIC, files);
}

static struct dentry *qibfs_mount(struct file_system_type *fs_type, int flags,
			const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, qibfs_fill_super);
}

static struct file_system_type qibfs_fs_type = {
	.owner =        THIS_MODULE,
	.name =         "ipathfs",
	.mount =        qibfs_mount,
	.kill_sb =      kill_litter_super,
};

static struct vfsmount *mnt;
static int count;

int qibfs_pin(void)
{
	return simple_pin_fs(&qibfs_fs_type, &mnt, &count);
}
EXPORT_SYMBOL(qibfs_pin);

void qibfs_unpin(void)
{
	simple_release_fs(&mnt, &count);
}
EXPORT_SYMBOL(qibfs_unpin);

struct dentry *qibfs_root(void)
{
	BUG_ON(!count);
	return mnt->mnt_root;
}
EXPORT_SYMBOL(qibfs_root);

static int __init qib_init_qibfs(void)
{
	return register_filesystem(&qibfs_fs_type);
}

static void __exit qib_exit_qibfs(void)
{
	unregister_filesystem(&qibfs_fs_type);
}
module_init(qib_init_qibfs);
module_exit(qib_exit_qibfs);
