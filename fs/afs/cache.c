// SPDX-License-Identifier: GPL-2.0-or-later
/* AFS caching stuff
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/sched.h>
#include "internal.h"

struct fscache_netfs afs_cache_netfs = {
	.name			= "afs",
	.version		= 2,
};

struct fscache_cookie_def afs_cell_cache_index_def = {
	.name		= "AFS.cell",
	.type		= FSCACHE_COOKIE_TYPE_INDEX,
};

struct fscache_cookie_def afs_volume_cache_index_def = {
	.name		= "AFS.volume",
	.type		= FSCACHE_COOKIE_TYPE_INDEX,
};

struct fscache_cookie_def afs_vnode_cache_index_def = {
	.name		= "AFS.vnode",
	.type		= FSCACHE_COOKIE_TYPE_DATAFILE,
};
