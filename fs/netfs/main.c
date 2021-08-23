// SPDX-License-Identifier: GPL-2.0-or-later
/* Network filesystem library.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * Check the inode context parameters are sane.
 */
int netfs_sanity_check_ictx(struct address_space *mapping)
{
	struct netfs_i_context *ctx = netfs_i_context(mapping->host);

	BUG_ON(!ctx->wsize);

	return 0;
}
