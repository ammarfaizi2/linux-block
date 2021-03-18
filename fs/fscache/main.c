// SPDX-License-Identifier: GPL-2.0-or-later
/* General filesystem local caching manager
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/module.h>
#include <linux/init.h>
#define CREATE_TRACE_POINTS
#include "internal.h"

MODULE_DESCRIPTION("FS Cache Manager");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

unsigned fscache_debug;
module_param_named(debug, fscache_debug, uint,
		   S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(fscache_debug,
		 "FS-Cache debugging mask");

EXPORT_TRACEPOINT_SYMBOL(fscache_access);

/*
 * initialise the fs caching module
 */
static int __init fscache_init(void)
{
	int ret;

	ret = fscache_init_dispatchers();
	if (ret < 0)
		goto error_dispatchers;

	ret = fscache_proc_init();
	if (ret < 0)
		goto error_proc;

	fscache_cookie_jar = kmem_cache_create("fscache_cookie_jar",
					       sizeof(struct fscache_cookie),
					       0, 0, NULL);
	if (!fscache_cookie_jar) {
		pr_notice("Failed to allocate a cookie jar\n");
		ret = -ENOMEM;
		goto error_cookie_jar;
	}

	pr_notice("Loaded\n");
	return 0;

error_cookie_jar:
	fscache_kill_dispatchers();
error_dispatchers:
	fscache_proc_cleanup();
error_proc:
	return ret;
}

fs_initcall(fscache_init);

/*
 * clean up on module removal
 */
static void __exit fscache_exit(void)
{
	_enter("");

	kmem_cache_destroy(fscache_cookie_jar);
	fscache_proc_cleanup();
	fscache_kill_dispatchers();
	pr_notice("Unloaded\n");
}

module_exit(fscache_exit);
