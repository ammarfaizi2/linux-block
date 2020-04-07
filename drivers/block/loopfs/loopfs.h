/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_LOOPFS_FS_H
#define _LINUX_LOOPFS_FS_H

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/user_namespace.h>

struct loop_device;

#ifdef CONFIG_BLK_DEV_LOOPFS

#define LOOPFS_FLAGS_INACTIVE (1 << 0)

struct lo_loopfs {
	struct loopfs_info *sbi;
	struct ucounts *lo_ucount;
	struct inode *lo_inode;
	int lo_flags;
};

extern struct super_block *loopfs_i_sb(const struct inode *inode);
extern bool loopfs_device(const struct loop_device *lo);
extern struct user_namespace *loopfs_ns(const struct loop_device *lo);
extern bool loopfs_access(const struct inode *first, struct loop_device *lo);
extern int loopfs_add(struct loop_device *lo, struct inode *ref_inode,
		      dev_t device_nr);
extern void loopfs_remove(struct loop_device *lo);
extern bool loopfs_wants_remove(const struct loop_device *lo);
extern void loopfs_evict_locked(struct loop_device *lo);
extern int loopfs_rundown_locked(struct loop_device *lo);
extern void loopfs_init(struct gendisk *disk, struct inode *inode);

#endif

#endif /* _LINUX_LOOPFS_FS_H */
