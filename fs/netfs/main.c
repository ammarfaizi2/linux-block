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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
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

#ifdef CONFIG_PROC_FS
LIST_HEAD(netfs_regions);
LIST_HEAD(netfs_wreqs);
DEFINE_SPINLOCK(netfs_regions_lock);

static const char netfs_proc_region_states[] = "PRADFC";
static const char *netfs_proc_region_types[] = {
	[NETFS_REGION_ORDINARY]		= "ORD ",
	[NETFS_REGION_DIO]		= "DIOW",
	[NETFS_REGION_DSYNC]		= "DSYN",
	[NETFS_REGION_CACHE_COPY]	= "CCPY",
};

/*
 * Generate a list of regions in /proc/fs/netfs/regions
 */
static int netfs_regions_seq_show(struct seq_file *m, void *v)
{
	struct netfs_dirty_region *region;

	if (v == &netfs_regions) {
		seq_puts(m,
			 "REGION   REF TYPE S FL DEV   INODE    DIRTY, BOUNDS, RESV\n"
			 "======== === ==== = == ===== ======== ==============================\n"
			 );
		return 0;
	}

	region = list_entry(v, struct netfs_dirty_region, proc_link);
	seq_printf(m,
		   "%08x %3d %s %c %2lx %02x:%02x %8x %04llx-%04llx %04llx-%04llx %04llx-%04llx\n",
		   region->debug_id,
		   refcount_read(&region->ref),
		   netfs_proc_region_types[region->type],
		   netfs_proc_region_states[region->state],
		   region->flags,
		   0, 0, 0,
		   region->dirty.start, region->dirty.end,
		   region->bounds.start, region->bounds.end,
		   region->reserved.start, region->reserved.end);
	return 0;
}

static void *netfs_regions_seq_start(struct seq_file *m, loff_t *_pos)
	__acquires(rcu)
{
	rcu_read_lock();
	return seq_list_start_head(&netfs_regions, *_pos);
}

static void *netfs_regions_seq_next(struct seq_file *m, void *v, loff_t *_pos)
{
	return seq_list_next(v, &netfs_regions, _pos);
}

static void netfs_regions_seq_stop(struct seq_file *m, void *v)
	__releases(rcu)
{
	rcu_read_unlock();
}

const struct seq_operations netfs_regions_seq_ops = {
	.start  = netfs_regions_seq_start,
	.next   = netfs_regions_seq_next,
	.stop   = netfs_regions_seq_stop,
	.show   = netfs_regions_seq_show,
};

/*
 * Generate a list of wreqs in /proc/fs/netfs/wreqs
 */
static int netfs_wreqs_seq_show(struct seq_file *m, void *v)
{
	struct netfs_write_request *wreq;
	struct netfs_dirty_region *r;
	char sep = ' ';

	if (v == &netfs_wreqs) {
		seq_puts(m,
			 "WREQ     REF FL ERR  OPS COVERAGE  REGIONS\n"
			 "======== === == ==== === ========= =======\n"
			 );
		return 0;
	}

	wreq = list_entry(v, struct netfs_write_request, proc_link);
	seq_printf(m,
		   "%08x %3d %2lx %4d %d/%u %04llx-%04llx",
		   wreq->debug_id,
		   refcount_read(&wreq->usage),
		   wreq->flags,
		   wreq->error,
		   atomic_read(&wreq->outstanding), wreq->n_ops,
		   wreq->coverage.start, wreq->coverage.end);

	read_lock(&wreq->regions_lock);
	list_for_each_entry(r, &wreq->regions, flush_link) {
		seq_printf(m, "%c%x", sep, r->debug_id);
		sep = ',';
	}
	read_unlock(&wreq->regions_lock);
	seq_putc(m, '\n');
	return 0;
}

static void *netfs_wreqs_seq_start(struct seq_file *m, loff_t *_pos)
	__acquires(rcu)
{
	rcu_read_lock();
	return seq_list_start_head(&netfs_wreqs, *_pos);
}

static void *netfs_wreqs_seq_next(struct seq_file *m, void *v, loff_t *_pos)
{
	return seq_list_next(v, &netfs_wreqs, _pos);
}

static void netfs_wreqs_seq_stop(struct seq_file *m, void *v)
	__releases(rcu)
{
	rcu_read_unlock();
}

const struct seq_operations netfs_wreqs_seq_ops = {
	.start  = netfs_wreqs_seq_start,
	.next   = netfs_wreqs_seq_next,
	.stop   = netfs_wreqs_seq_stop,
	.show   = netfs_wreqs_seq_show,
};
#endif /* CONFIG_PROC_FS */

static int __init netfs_init(void)
{
	if (!proc_mkdir("fs/netfs", NULL))
		goto error;

	if (!proc_create_seq("fs/netfs/regions", S_IFREG | 0444, NULL,
			     &netfs_regions_seq_ops))
		goto error_proc;

	if (!proc_create_seq("fs/netfs/wreqs", S_IFREG | 0444, NULL,
			     &netfs_wreqs_seq_ops))
		goto error_proc;

	return 0;

error_proc:
	remove_proc_entry("fs/netfs", NULL);
error:
	return -ENOMEM;
}
fs_initcall(netfs_init);

static void __exit netfs_exit(void)
{
	remove_proc_entry("fs/netfs", NULL);
}
module_exit(netfs_exit);
