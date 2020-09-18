// SPDX-License-Identifier: GPL-2.0-or-later
/* General filesystem local caching manager
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include "internal.h"

MODULE_DESCRIPTION("FS Cache Manager");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

unsigned fscache_debug;
module_param_named(debug, fscache_debug, uint,
		   S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(fscache_debug,
		 "FS-Cache debugging mask");

/*
 * Initialise the module
 */
static int __init fscache_init(void)
{
	int ret;

	if (!proc_mkdir("fs/fscache", NULL))
		return -ENOMEM;

	ret = fscache_proc_stats_init();
	if (ret < 0)
		goto error;

	ret = fscache_init_caching();
	if (ret < 0)
		goto error;

	pr_notice("Loaded\n");
	return 0;

error:
	remove_proc_subtree("fs/fscache", NULL);
	return ret;
}
fs_initcall(fscache_init);

/*
 * clean up on module removal
 */
static void __exit fscache_exit(void)
{
	_enter("");

	remove_proc_subtree("fs/fscache", NULL);
	fscache_exit_caching();
	pr_notice("Unloaded\n");
}

module_exit(fscache_exit);
