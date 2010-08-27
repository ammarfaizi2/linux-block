 /*
 * VFS-based union mounts for Linux
 *
 * Copyright (C) 2004-2007 IBM Corporation, IBM Deutschland Entwicklung GmbH.
 * Copyright (C) 2007-2009 Novell Inc.
 * Copyright (C) 2009-2010 Red Hat, Inc.
 *
 *   Author(s): Jan Blunck (j.blunck@tu-harburg.de)
 *              Valerie Aurora <vaurora@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <linux/bootmem.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>

#include "union.h"

/**
 * union_alloc - allocate a union stack
 *
 * @path: path of topmost directory
 *
 * Allocate a union_stack large enough to contain the maximum number
 * of layers in this union mount.
 */

static struct union_stack *union_alloc(struct path *topmost)
{
	unsigned int layers = topmost->dentry->d_sb->s_union_count;
	BUG_ON(!S_ISDIR(topmost->dentry->d_inode->i_mode));

	return kzalloc(sizeof(struct path) * layers, GFP_KERNEL);
}
