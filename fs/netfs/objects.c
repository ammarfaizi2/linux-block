// SPDX-License-Identifier: GPL-2.0-only
/* Object lifetime handling and tracing.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include "internal.h"

/**
 * netfs_new_flush_group - Create a new write flush group
 * @inode: The inode for which this is a flush group.
 * @netfs_priv: Netfs private data to include in the new group
 *
 * Create a new flush group and add it to the tail of the inode's group list.
 * Flush groups are used to control the order in which dirty data is written
 * back to the server.
 *
 * The caller must hold ctx->lock.
 */
struct netfs_flush_group *netfs_new_flush_group(struct inode *inode, void *netfs_priv)
{
	struct netfs_flush_group *group;
	struct netfs_i_context *ctx = netfs_i_context(inode);

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (group) {
		group->netfs_priv = netfs_priv;
		INIT_LIST_HEAD(&group->region_list);
		refcount_set(&group->ref, 1);
		netfs_stat(&netfs_n_wh_flush_group);
		spin_lock(&ctx->lock);
		group->i_size = i_size_read(inode);
		list_add_tail(&group->group_link, &ctx->flush_groups);
		spin_unlock(&ctx->lock);
	}
	return group;
}
EXPORT_SYMBOL(netfs_new_flush_group);

struct netfs_flush_group *netfs_get_flush_group(struct netfs_flush_group *group)
{
	refcount_inc(&group->ref);
	return group;
}

void netfs_put_flush_group(struct netfs_i_context *ctx,
			   struct netfs_flush_group *group)
{
	if (group && refcount_dec_and_test(&group->ref)) {
		netfs_stat_d(&netfs_n_wh_flush_group);
		if (ctx->ops->free_flush_group)
			ctx->ops->free_flush_group(ctx, group);
		kfree(group);
	}
}

struct netfs_dirty_region *netfs_alloc_dirty_region(void)
{
	struct netfs_dirty_region *region;

	region = kzalloc(sizeof(struct netfs_dirty_region), GFP_KERNEL);
	if (region)
		netfs_stat(&netfs_n_wh_region);
	return region;
}

struct netfs_dirty_region *netfs_get_dirty_region(struct netfs_i_context *ctx,
						  struct netfs_dirty_region *region,
						  enum netfs_region_trace what)
{
	int ref;

	__refcount_inc(&region->ref, &ref);
	trace_netfs_ref_region(region->debug_id, ref + 1, what);
	return region;
}

void netfs_free_dirty_region(struct netfs_i_context *ctx,
			     struct netfs_dirty_region *region)
{
	if (region) {
		trace_netfs_ref_region(region->debug_id, 0, netfs_region_trace_free);
		if (ctx->ops->free_dirty_region)
			ctx->ops->free_dirty_region(region);
		netfs_put_flush_group(ctx, region->group);
		netfs_stat_d(&netfs_n_wh_region);
		kfree(region);
	}
}

void netfs_put_dirty_region(struct netfs_i_context *ctx,
			    struct netfs_dirty_region *region,
			    enum netfs_region_trace what)
{
	bool dead;
	int ref;

	if (!region)
		return;
	dead = __refcount_dec_and_test(&region->ref, &ref);
	trace_netfs_ref_region(region->debug_id, ref - 1, what);
	if (dead) {
		if (!list_empty(&region->active_link) ||
		    !list_empty(&region->dirty_link)) {
			spin_lock(&ctx->lock);
			list_del_init(&region->active_link);
			list_del_init(&region->dirty_link);
			spin_unlock(&ctx->lock);
		}
		netfs_free_dirty_region(ctx, region);
	}
}
