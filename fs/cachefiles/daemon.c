// SPDX-License-Identifier: GPL-2.0-or-later
/* Daemon interface
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/fs_struct.h>
#include "internal.h"

/*
 * see if we have space for a number of pages and/or a number of files in the
 * cache
 */
int cachefiles_has_space(struct cachefiles_cache *cache,
			 unsigned fnr, unsigned bnr)
{
	struct kstatfs stats;
	int ret;

	struct path path = {
		.mnt	= cache->mnt,
		.dentry	= cache->store,
	};

	//_enter("{%llu,%llu,%llu,%llu,%llu,%llu},%u,%u",
	//       (unsigned long long) cache->frun,
	//       (unsigned long long) cache->fcull,
	//       (unsigned long long) cache->fstop,
	//       (unsigned long long) cache->brun,
	//       (unsigned long long) cache->bcull,
	//       (unsigned long long) cache->bstop,
	//       fnr, bnr);

	/* find out how many pages of blockdev are available */
	memset(&stats, 0, sizeof(stats));

	ret = vfs_statfs(&path, &stats);
	if (ret < 0) {
		trace_cachefiles_vfs_error(NULL, d_inode(cache->store), ret,
					   cachefiles_trace_statfs_error);
		if (ret == -EIO)
			cachefiles_io_error(cache, "statfs failed");
		_leave(" = %d", ret);
		return ret;
	}

	stats.f_bavail >>= cache->bshift;

	//_debug("avail %llu,%llu",
	//       (unsigned long long) stats.f_ffree,
	//       (unsigned long long) stats.f_bavail);

	/* see if there is sufficient space */
	if (stats.f_ffree > fnr)
		stats.f_ffree -= fnr;
	else
		stats.f_ffree = 0;

	if (stats.f_bavail > bnr)
		stats.f_bavail -= bnr;
	else
		stats.f_bavail = 0;

	ret = -ENOBUFS;
	if (stats.f_ffree < cache->fstop ||
	    stats.f_bavail < cache->bstop)
		goto begin_cull;

	ret = 0;
	if (stats.f_ffree < cache->fcull ||
	    stats.f_bavail < cache->bcull)
		goto begin_cull;

	if (test_bit(CACHEFILES_CULLING, &cache->flags) &&
	    stats.f_ffree >= cache->frun &&
	    stats.f_bavail >= cache->brun &&
	    test_and_clear_bit(CACHEFILES_CULLING, &cache->flags)
	    ) {
		_debug("cease culling");
		cachefiles_state_changed(cache);
	}

	//_leave(" = 0");
	return 0;

begin_cull:
	if (!test_and_set_bit(CACHEFILES_CULLING, &cache->flags)) {
		_debug("### CULL CACHE ###");
		cachefiles_state_changed(cache);
	}

	_leave(" = %d", ret);
	return ret;
}
