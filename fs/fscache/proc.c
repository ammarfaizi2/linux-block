// SPDX-License-Identifier: GPL-2.0-or-later
/* FS-Cache statistics viewing interface
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "internal.h"

/*
 * initialise the /proc/fs/fscache/ directory
 */
int __init fscache_proc_caching_init(void)
{
	if (!proc_create_seq("fs/fscache/cookies", S_IFREG | 0444, NULL,
			     &fscache_cookies_seq_ops))
		return -ENOMEM;

#ifdef CONFIG_FSCACHE_HISTOGRAM
	if (!proc_create_seq("fs/fscache/histogram", S_IFREG | 0444, NULL,
			 &fscache_histogram_ops))
		return -ENOMEM;
#endif

#ifdef CONFIG_FSCACHE_OBJECT_LIST
	if (!proc_create("fs/fscache/objects", S_IFREG | 0444, NULL,
			 &fscache_objlist_proc_ops))
		return -ENOMEM;
#endif

	return 0;
}
