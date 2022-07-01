// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016 Trond Myklebust
 * Copyright (c) 2022 Jeff Layton
 *
 * I/O and data path helper functionality.
 *
 * Shamelessly copied from fs/nfs/io.c
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/rwsem.h>
#include <linux/fs.h>
#include <linux/netfs.h>

/* Call with exclusively locked inode->i_rwsem */
static void netfs_block_o_direct(struct inode *inode)
{
	struct netfs_inode *ni = netfs_inode(inode);

	if (test_bit(NETFS_ICTX_ODIRECT, &ni->flags)) {
		clear_bit(NETFS_ICTX_ODIRECT, &ni->flags);
		inode_dio_wait(inode);
	}
}

/**
 * netfs_start_io_read - declare the file is being used for buffered reads
 * @inode: file inode
 *
 * Declare that a buffered read operation is about to start, and ensure that we
 * block all direct I/O.  On exit, the function ensures that the
 * NETFS_ICTX_ODIRECT flag is unset, and holds a shared lock on inode->i_rwsem
 * to ensure that the flag cannot be changed.  In practice, this means that
 * buffered read operations are allowed to execute in parallel, thanks to the
 * shared lock, whereas direct I/O operations need to wait to grab an exclusive
 * lock in order to set NETFS_ICTX_ODIRECT.  Note that buffered writes and
 * truncates both take a write lock on inode->i_rwsem, meaning that those are
 * serialised w.r.t. the reads.
 */
void netfs_start_io_read(struct inode *inode)
{
	struct netfs_inode *ni = netfs_inode(inode);

	/* Be an optimist! */
	inode_lock_shared(inode);
	if (!test_bit(NETFS_ICTX_ODIRECT, &ni->flags))
		return;
	inode_unlock_shared(inode);

	/* Slow path.... */
	inode_lock(inode);
	netfs_block_o_direct(inode);
	downgrade_write(&inode->i_rwsem);
}
EXPORT_SYMBOL(netfs_start_io_read);

/**
 * netfs_end_io_read - declare that the buffered read operation is done
 * @inode: file inode
 *
 * Declare that a buffered read operation is done, and release the shared
 * lock on inode->i_rwsem.
 */
void
netfs_end_io_read(struct inode *inode)
{
	inode_unlock_shared(inode);
}
EXPORT_SYMBOL(netfs_end_io_read);

/**
 * netfs_start_io_write - declare the file is being used for buffered writes
 * @inode: file inode
 *
 * Declare that a buffered read operation is about to start, and ensure
 * that we block all direct I/O.
 */
void
netfs_start_io_write(struct inode *inode)
{
	inode_lock(inode);
	netfs_block_o_direct(inode);
}
EXPORT_SYMBOL(netfs_start_io_write);

/**
 * netfs_end_io_write - declare that the buffered write operation is done
 * @inode: file inode
 *
 * Declare that a buffered write operation is done, and release the
 * lock on inode->i_rwsem.
 */
void
netfs_end_io_write(struct inode *inode)
{
	inode_unlock(inode);
}
EXPORT_SYMBOL(netfs_end_io_write);

/* Call with exclusively locked inode->i_rwsem */
static void netfs_block_buffered(struct inode *inode)
{
	struct netfs_inode *ni = netfs_inode(inode);

	if (!test_bit(NETFS_ICTX_ODIRECT, &ni->flags)) {
		set_bit(NETFS_ICTX_ODIRECT, &ni->flags);
		filemap_write_and_wait(inode->i_mapping);
	}
}

/**
 * netfs_start_io_direct - declare the file is being used for direct i/o
 * @inode: file inode
 *
 * Declare that a direct I/O operation is about to start, and ensure that we
 * block all buffered I/O.  On exit, the function ensures that the
 * NETFS_ICTX_ODIRECT flag is set, and holds a shared lock on inode->i_rwsem to
 * ensure that the flag cannot be changed.  In practice, this means that direct
 * I/O operations are allowed to execute in parallel, thanks to the shared
 * lock, whereas buffered I/O operations need to wait to grab an exclusive lock
 * in order to clear NETFS_ICTX_ODIRECT.  Note that buffered writes and
 * truncates both take a write lock on inode->i_rwsem, meaning that those are
 * serialised w.r.t. O_DIRECT.
 */
void
netfs_start_io_direct(struct inode *inode)
{
	struct netfs_inode *ni = netfs_inode(inode);

	/* Be an optimist! */
	inode_lock_shared(inode);
	if (test_bit(NETFS_ICTX_ODIRECT, &ni->flags))
		return;
	inode_unlock_shared(inode);

	/* Slow path.... */
	inode_lock(inode);
	netfs_block_buffered(inode);
	downgrade_write(&inode->i_rwsem);
}
EXPORT_SYMBOL(netfs_start_io_direct);

/**
 * netfs_end_io_direct - declare that the direct i/o operation is done
 * @inode: file inode
 *
 * Declare that a direct I/O operation is done, and release the shared
 * lock on inode->i_rwsem.
 */
void
netfs_end_io_direct(struct inode *inode)
{
	inode_unlock_shared(inode);
}
EXPORT_SYMBOL(netfs_end_io_direct);
