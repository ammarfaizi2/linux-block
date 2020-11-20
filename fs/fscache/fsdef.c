// SPDX-License-Identifier: GPL-2.0-or-later
/* Filesystem index definition
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/module.h>
#include "internal.h"

/*
 * The root index is owned by FS-Cache itself.
 *
 * When a netfs requests caching facilities, FS-Cache will, if one doesn't
 * already exist, create an entry in the root index with the key being the name
 * of the netfs ("AFS" for example), and the auxiliary data holding the index
 * structure version supplied by the netfs:
 *
 *				     FSDEF
 *				       |
 *				 +-----------+
 *				 |           |
 *				NFS         AFS
 *			       [v=1]       [v=1]
 *
 * If an entry with the appropriate name does already exist, the version is
 * compared.  If the version is different, the entire subtree from that entry
 * will be discarded and a new entry created.
 *
 * The new entry will be an index, and a cookie referring to it will be passed
 * to the netfs.  This is then the root handle by which the netfs accesses the
 * cache.  It can create whatever objects it likes in that index, including
 * further indices.
 */
struct fscache_cookie fscache_fsdef_index = {
	.debug_id	= 1,
	.usage		= ATOMIC_INIT(1),
	.n_active	= ATOMIC_INIT(1),
	.lock		= __SPIN_LOCK_UNLOCKED(fscache_fsdef_index.lock),
	.backing_objects = HLIST_HEAD_INIT,
	.type_name	= ".fscach",
	.type		= FSCACHE_COOKIE_TYPE_INDEX,
};
EXPORT_SYMBOL(fscache_fsdef_index);
