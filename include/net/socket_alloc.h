/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _SOCKET_ALLOC_H
#define _SOCKET_ALLOC_H

#include <net/sock.h>
#include <linux/fs.h>
#include <linux/net.h>

struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

#endif	/* _SOCKET_ALLOC_H */
