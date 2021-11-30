/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_API_DIO_H
#define _LINUX_FS_API_DIO_H

#include <linux/fs_api.h>

#include <linux/wait_bit.h>

#ifdef CONFIG_BLOCK
typedef void (dio_submit_t)(struct bio *bio, struct inode *inode,
			    loff_t file_offset);

enum {
	/* need locking between buffered and direct access */
	DIO_LOCKING	= 0x01,

	/* filesystem does not support filling holes */
	DIO_SKIP_HOLES	= 0x02,
};

ssize_t __blockdev_direct_IO(struct kiocb *iocb, struct inode *inode,
			     struct block_device *bdev, struct iov_iter *iter,
			     get_block_t get_block,
			     dio_iodone_t end_io, dio_submit_t submit_io,
			     int flags);

static inline ssize_t blockdev_direct_IO(struct kiocb *iocb,
					 struct inode *inode,
					 struct iov_iter *iter,
					 get_block_t get_block)
{
	return __blockdev_direct_IO(iocb, inode, inode->i_sb->s_bdev, iter,
			get_block, NULL, NULL, DIO_LOCKING | DIO_SKIP_HOLES);
}
#endif

void inode_dio_wait(struct inode *inode);

/**
 * inode_dio_begin - signal start of a direct I/O requests
 * @inode: inode the direct I/O happens on
 *
 * This is called once we've finished processing a direct I/O request,
 * and is used to wake up callers waiting for direct I/O to be quiesced.
 */
static inline void inode_dio_begin(struct inode *inode)
{
	atomic_inc(&inode->i_dio_count);
}

/**
 * inode_dio_end - signal finish of a direct I/O requests
 * @inode: inode the direct I/O happens on
 *
 * This is called once we've finished processing a direct I/O request,
 * and is used to wake up callers waiting for direct I/O to be quiesced.
 */
static inline void inode_dio_end(struct inode *inode)
{
	if (atomic_dec_and_test(&inode->i_dio_count))
		wake_up_bit(&inode->i_state, __I_DIO_WAKEUP);
}

/*
 * Warn about a page cache invalidation failure diring a direct I/O write.
 */
void dio_warn_stale_pagecache(struct file *filp);

/*
 * Flush file data before changing attributes.  Caller must hold any locks
 * required to prevent further writes to this file until we're done setting
 * flags.
 */
static inline int inode_drain_writes(struct inode *inode)
{
	inode_dio_wait(inode);
	return filemap_write_and_wait(inode->i_mapping);
}

#endif /* _LINUX_FS_API_DIO_H */
