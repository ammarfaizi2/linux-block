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
#include <linux/seq_file.h>
#define CREATE_TRACE_POINTS
#include "internal.h"

struct kobject *fscache_root;
struct workqueue_struct *fscache_op_wq;

/* these values serve as lower bounds, will be adjusted in fscache_init() */
static unsigned fscache_object_max_active = 4;
static unsigned fscache_op_max_active = 2;

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *fscache_sysctl_header;

static int fscache_max_active_sysctl(struct ctl_table *table, int write,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct workqueue_struct **wqp = table->extra1;
	unsigned int *datap = table->data;
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0)
		workqueue_set_max_active(*wqp, *datap);
	return ret;
}

static struct ctl_table fscache_sysctls[] = {
	{
		.procname	= "operation_max_active",
		.data		= &fscache_op_max_active,
		.maxlen		= sizeof(unsigned),
		.mode		= 0644,
		.proc_handler	= fscache_max_active_sysctl,
		.extra1		= &fscache_op_wq,
	},
	{}
};

static struct ctl_table fscache_sysctls_root[] = {
	{
		.procname	= "fscache",
		.mode		= 0555,
		.child		= fscache_sysctls,
	},
	{}
};
#endif

/*
 * Initialise the caching code.
 */
int __init fscache_init_caching(void)
{
	int ret;

	fscache_op_max_active =
		clamp_val(fscache_object_max_active / 2,
			  fscache_op_max_active, WQ_UNBOUND_MAX_ACTIVE);

	ret = -ENOMEM;
	fscache_op_wq = alloc_workqueue("fscache_operation", WQ_UNBOUND,
					fscache_op_max_active);
	if (!fscache_op_wq)
		goto error_op_wq;

	ret = fscache_init_dispatchers();
	if (ret < 0)
		goto error_dispatchers;

	ret = fscache_proc_caching_init();
	if (ret < 0)
		goto error_proc;

#ifdef CONFIG_SYSCTL
	ret = -ENOMEM;
	fscache_sysctl_header = register_sysctl_table(fscache_sysctls_root);
	if (!fscache_sysctl_header)
		goto error_sysctl;
#endif

	fscache_cookie_jar = kmem_cache_create("fscache_cookie_jar",
					       sizeof(struct fscache_cookie),
					       0, 0, NULL);
	if (!fscache_cookie_jar) {
		pr_notice("Failed to allocate a cookie jar\n");
		ret = -ENOMEM;
		goto error_cookie_jar;
	}

	fscache_root = kobject_create_and_add("fscache", kernel_kobj);
	if (!fscache_root)
		goto error_kobj;

	return 0;

error_kobj:
	kmem_cache_destroy(fscache_cookie_jar);
error_cookie_jar:
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(fscache_sysctl_header);
error_sysctl:
#endif
	fscache_kill_dispatchers();
error_dispatchers:
error_proc:
	destroy_workqueue(fscache_op_wq);
error_op_wq:
	return ret;
}

/*
 * clean up on module removal
 */
void __exit fscache_exit_caching(void)
{
	_enter("");

	kobject_put(fscache_root);
	kmem_cache_destroy(fscache_cookie_jar);
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(fscache_sysctl_header);
#endif
	fscache_kill_dispatchers();
	destroy_workqueue(fscache_op_wq);
}
