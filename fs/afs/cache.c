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
