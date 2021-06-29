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

struct netfs_write_request *netfs_alloc_write_request(struct address_space *mapping,
						      bool is_dio)
{
	static atomic_t debug_ids;
	struct inode *inode = mapping->host;
	struct netfs_i_context *ctx = netfs_i_context(inode);
	struct netfs_write_request *wreq;
	bool cached = !is_dio && netfs_is_cache_enabled(ctx);

	wreq = kzalloc(sizeof(struct netfs_write_request), GFP_KERNEL);
	if (wreq) {
		wreq->mapping	= mapping;
		wreq->inode	= inode;
		wreq->netfs_ops	= ctx->ops;
		wreq->debug_id	= atomic_inc_return(&debug_ids);
		if (cached)
			__set_bit(NETFS_WREQ_WRITE_TO_CACHE, &wreq->flags);
		xa_init(&wreq->buffer);
		INIT_WORK(&wreq->work, netfs_writeback_worker);
		INIT_LIST_HEAD(&wreq->regions);
		rwlock_init(&wreq->regions_lock);
		refcount_set(&wreq->usage, 1);
		ctx->ops->init_wreq(wreq);
		netfs_stat(&netfs_n_wh_wreq);
		trace_netfs_ref_wreq(wreq->debug_id, 1, netfs_wreq_trace_new);
	}

	return wreq;
}

void netfs_get_write_request(struct netfs_write_request *wreq,
			     enum netfs_wreq_trace what)
{
	int ref;

	__refcount_inc(&wreq->usage, &ref);
	trace_netfs_ref_wreq(wreq->debug_id, ref + 1, what);
}

void netfs_free_write_request(struct work_struct *work)
{
	struct netfs_write_request *wreq =
		container_of(work, struct netfs_write_request, work);
	struct netfs_dirty_region *region;
	struct netfs_i_context *ctx = netfs_i_context(wreq->inode);
	struct folio *folio;
	pgoff_t index;

	if (wreq->netfs_priv)
		wreq->netfs_ops->cleanup(wreq->mapping, wreq->netfs_priv);
	trace_netfs_ref_wreq(wreq->debug_id, 0, netfs_wreq_trace_free);
	if (wreq->cache_resources.ops)
		wreq->cache_resources.ops->end_operation(&wreq->cache_resources);
	write_lock(&wreq->regions_lock);
	while ((region = list_first_entry_or_null(
			&wreq->regions, struct netfs_dirty_region, flush_link))) {
		list_del_init(&region->flush_link);
		netfs_put_dirty_region(ctx, region, netfs_region_trace_put_wreq);
	}
	write_unlock(&wreq->regions_lock);
	xa_for_each(&wreq->buffer, index, folio) {
		folio_put(folio);
	}
	xa_destroy(&wreq->buffer);
	kfree(wreq);
	netfs_stat_d(&netfs_n_wh_wreq);
}

/**
 * netfs_put_write_request - Drop a reference on a write request descriptor.
 * @wreq: The write request to drop
 * @was_async: True if being called in a non-sleeping context
 * @what: Reason code, to be displayed in trace line
 *
 * Drop a reference on a write request and schedule it for destruction after
 * the last ref is gone.
 */
void netfs_put_write_request(struct netfs_write_request *wreq,
			     bool was_async, enum netfs_wreq_trace what)
{
	unsigned int debug_id;
	bool dead;
	int ref;

	if (wreq) {
		debug_id = wreq->debug_id;
		dead = __refcount_dec_and_test(&wreq->usage, &ref);
		trace_netfs_ref_wreq(debug_id, ref - 1, what);
		if (dead) {
			if (was_async) {
				wreq->work.func = netfs_free_write_request;
				if (!queue_work(system_unbound_wq, &wreq->work))
					BUG();
			} else {
				netfs_free_write_request(&wreq->work);
			}
		}
	}
}
EXPORT_SYMBOL(netfs_put_write_request);
