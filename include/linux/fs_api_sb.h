/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_API_SB_H
#define _LINUX_FS_API_SB_H

#include <linux/fs_api.h>

/*
 * Snapshotting support.
 */

/*
 * These are internal functions, please use sb_start_{write,pagefault,intwrite}
 * instead.
 */
static inline void __sb_end_write(struct super_block *sb, int level)
{
	percpu_up_read(sb->s_writers.rw_sem + level-1);
}

static inline void __sb_start_write(struct super_block *sb, int level)
{
	percpu_down_read(sb->s_writers.rw_sem + level - 1);
}

static inline bool __sb_start_write_trylock(struct super_block *sb, int level)
{
	return percpu_down_read_trylock(sb->s_writers.rw_sem + level - 1);
}

#define __sb_writers_acquired(sb, lev)	\
	percpu_rwsem_acquire(&(sb)->s_writers.rw_sem[(lev)-1], 1, _THIS_IP_)
#define __sb_writers_release(sb, lev)	\
	percpu_rwsem_release(&(sb)->s_writers.rw_sem[(lev)-1], 1, _THIS_IP_)

/**
 * sb_end_write - drop write access to a superblock
 * @sb: the super we wrote to
 *
 * Decrement number of writers to the filesystem. Wake up possible waiters
 * wanting to freeze the filesystem.
 */
static inline void sb_end_write(struct super_block *sb)
{
	__sb_end_write(sb, SB_FREEZE_WRITE);
}

/**
 * sb_end_pagefault - drop write access to a superblock from a page fault
 * @sb: the super we wrote to
 *
 * Decrement number of processes handling write page fault to the filesystem.
 * Wake up possible waiters wanting to freeze the filesystem.
 */
static inline void sb_end_pagefault(struct super_block *sb)
{
	__sb_end_write(sb, SB_FREEZE_PAGEFAULT);
}

/**
 * sb_end_intwrite - drop write access to a superblock for internal fs purposes
 * @sb: the super we wrote to
 *
 * Decrement fs-internal number of writers to the filesystem.  Wake up possible
 * waiters wanting to freeze the filesystem.
 */
static inline void sb_end_intwrite(struct super_block *sb)
{
	__sb_end_write(sb, SB_FREEZE_FS);
}

/**
 * sb_start_write - get write access to a superblock
 * @sb: the super we write to
 *
 * When a process wants to write data or metadata to a file system (i.e. dirty
 * a page or an inode), it should embed the operation in a sb_start_write() -
 * sb_end_write() pair to get exclusion against file system freezing. This
 * function increments number of writers preventing freezing. If the file
 * system is already frozen, the function waits until the file system is
 * thawed.
 *
 * Since freeze protection behaves as a lock, users have to preserve
 * ordering of freeze protection and other filesystem locks. Generally,
 * freeze protection should be the outermost lock. In particular, we have:
 *
 * sb_start_write
 *   -> i_mutex			(write path, truncate, directory ops, ...)
 *   -> s_umount		(freeze_super, thaw_super)
 */
static inline void sb_start_write(struct super_block *sb)
{
	__sb_start_write(sb, SB_FREEZE_WRITE);
}

static inline bool sb_start_write_trylock(struct super_block *sb)
{
	return __sb_start_write_trylock(sb, SB_FREEZE_WRITE);
}

/**
 * sb_start_pagefault - get write access to a superblock from a page fault
 * @sb: the super we write to
 *
 * When a process starts handling write page fault, it should embed the
 * operation into sb_start_pagefault() - sb_end_pagefault() pair to get
 * exclusion against file system freezing. This is needed since the page fault
 * is going to dirty a page. This function increments number of running page
 * faults preventing freezing. If the file system is already frozen, the
 * function waits until the file system is thawed.
 *
 * Since page fault freeze protection behaves as a lock, users have to preserve
 * ordering of freeze protection and other filesystem locks. It is advised to
 * put sb_start_pagefault() close to mmap_lock in lock ordering. Page fault
 * handling code implies lock dependency:
 *
 * mmap_lock
 *   -> sb_start_pagefault
 */
static inline void sb_start_pagefault(struct super_block *sb)
{
	__sb_start_write(sb, SB_FREEZE_PAGEFAULT);
}

/**
 * sb_start_intwrite - get write access to a superblock for internal fs purposes
 * @sb: the super we write to
 *
 * This is the third level of protection against filesystem freezing. It is
 * free for use by a filesystem. The only requirement is that it must rank
 * below sb_start_pagefault.
 *
 * For example filesystem can call sb_start_intwrite() when starting a
 * transaction which somewhat eases handling of freezing for internal sources
 * of filesystem changes (internal fs threads, discarding preallocation on file
 * close, etc.).
 */
static inline void sb_start_intwrite(struct super_block *sb)
{
	__sb_start_write(sb, SB_FREEZE_FS);
}

static inline bool sb_start_intwrite_trylock(struct super_block *sb)
{
	return __sb_start_write_trylock(sb, SB_FREEZE_FS);
}

static inline void file_start_write(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode))
		return;
	sb_start_write(file_inode(file)->i_sb);
}

static inline bool file_start_write_trylock(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode))
		return true;
	return sb_start_write_trylock(file_inode(file)->i_sb);
}

static inline void file_end_write(struct file *file)
{
	if (!S_ISREG(file_inode(file)->i_mode))
		return;
	__sb_end_write(file_inode(file)->i_sb, SB_FREEZE_WRITE);
}

#endif /* _LINUX_FS_API_SB_H */
