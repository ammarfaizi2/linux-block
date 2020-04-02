/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_LOOPFS_FS_H
#define _LINUX_LOOPFS_FS_H

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/magic.h>

struct loop_device;

#ifdef CONFIG_BLK_DEV_LOOPFS

extern inline struct super_block *loopfs_i_sb(const struct inode *inode)
{
	if (inode && inode->i_sb->s_magic == LOOPFS_SUPER_MAGIC)
		return inode->i_sb;

	return NULL;
}
static inline bool loopfs_same_instance(const struct inode *first,
					const struct inode *second)
{
	return loopfs_i_sb(first) == loopfs_i_sb(second);
}
extern int loopfs_loop_device_create(struct loop_device *lo,
				     struct inode *ref_inode, dev_t device_nr);
extern void loopfs_loop_device_remove(struct loop_device *lo);

extern void loopfs_remove_locked(struct loop_device *lo);
extern int loopfs_rundown_locked(struct loop_device *lo);

#endif

#endif /* _LINUX_LOOPFS_FS_H */
