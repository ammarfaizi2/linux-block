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

/*
 * Deduct the write credits to be used by this operation from the credits
 * available.  This is used to throttle the generation of write requests.
 */
void netfs_deduct_write_credit(struct netfs_dirty_region *region, size_t credits)
{
	region->credit = credits;
	atomic_long_sub(credits, &netfs_write_credit);
}

/*
 * Return the write credits that were used by this operation to the available
 * credits counter.  This is used to throttle the generation of write requests.
 */
static void netfs_return_write_credit(struct netfs_dirty_region *region)
{
	long c;

	c = atomic_long_add_return(region->credit, &netfs_write_credit);
	if (c > 0 && (long)(c - region->credit) <= 0)
		wake_up_var(&netfs_write_credit);
}

/*
 * Wait for sufficient credit to become available, thereby throttling the
 * creation of write requests.
 */
int netfs_wait_for_credit(struct writeback_control *wbc)
{
	if (atomic_long_read(&netfs_write_credit) <= 0) {
		if (wbc->sync_mode == WB_SYNC_NONE)
			return -EBUSY;
		return wait_var_event_killable(&netfs_write_credit,
					       atomic_long_read(&netfs_write_credit) > 0);
	}

	return 0;
}

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
	if (region) {
		INIT_LIST_HEAD(&region->proc_link);
		netfs_stat(&netfs_n_wh_region);
	}
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
		if (!list_empty(&region->proc_link))
			netfs_proc_del_region(region);
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
		netfs_return_write_credit(region);
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
		INIT_LIST_HEAD(&wreq->operations);
		rwlock_init(&wreq->regions_lock);
		refcount_set(&wreq->usage, 1);
		atomic_set(&wreq->outstanding, 1);
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

/**
 * netfs_put_write_operation - Drop a ref to a write operation
 * @op: The operation to drop a ref on
 * @was_async: True if being called in a non-sleeping context
 * @what: The trace tag to note.
 *
 * Drop a reference on a write operation and schedule it for destruction after
 * the last ref is gone.
 */
void netfs_put_write_operation(struct netfs_write_operation *op,
			       bool was_async, enum netfs_wreq_trace what)
{
	struct netfs_write_request *wreq = op->wreq;

	if (refcount_dec_and_test(&op->ref)) {
		trace_netfs_wrop(op, netfs_write_op_free);
		if (wreq->netfs_ops->free_write_operation)
			wreq->netfs_ops->free_write_operation(op);
		netfs_put_write_request(op->wreq, was_async, what);
		kfree(op);
	}
}
EXPORT_SYMBOL(netfs_put_write_operation);

/**
 * netfs_create_write_operation - Create a write operation.
 * @wreq: The write request this is storing from.
 * @dest: The destination type
 * @worker: The worker function to handle the write(s)
 *
 * Allocate a write operation, set it up and add it to the list on a write
 * request.
 */
struct netfs_write_operation *netfs_create_write_operation(struct netfs_write_request *wreq,
							   enum netfs_write_dest dest,
							   loff_t start, size_t len,
							   work_func_t worker)
{
	struct netfs_write_operation *op;
	struct xarray *buffer;

	op = kzalloc(sizeof(struct netfs_write_operation), GFP_KERNEL);
	if (op) {
		op->wreq	= wreq;
		op->dest	= dest;
		op->start	= start;
		op->len		= len;
		op->debug_index	= wreq->n_ops++;
		INIT_WORK(&op->work, worker);
		refcount_set(&op->ref, 2);

		switch (op->dest) {
		case NETFS_UPLOAD_TO_SERVER:
			netfs_stat(&netfs_n_wh_upload);
			break;
		case NETFS_WRITE_TO_CACHE:
			netfs_stat(&netfs_n_wh_write);
			break;
		default:
			BUG();
		}

		buffer = &wreq->mapping->i_pages;
		if (test_bit(NETFS_WREQ_BUFFERED, &wreq->flags))
			buffer = &wreq->buffer;
		iov_iter_xarray(&op->source, WRITE, buffer,
				wreq->coverage.start,
				wreq->coverage.end - wreq->coverage.start);

		netfs_get_write_request(wreq, netfs_wreq_trace_get_for_op);
		atomic_inc(&wreq->outstanding);
		list_add_tail(&op->wreq_link, &wreq->operations);
		trace_netfs_wrop(op, netfs_write_op_new);
	}

	return op;
}
EXPORT_SYMBOL(netfs_create_write_operation);

/**
 * netfs_get_write_operation - Get a ref to a write operation
 * @op: The operation to get a ref on
 * @what: The trace tag to note.
 *
 * Get a reference on a write operation.
 */
void netfs_get_write_operation(struct netfs_write_operation *op,
			       enum netfs_wreq_trace what)
{
	refcount_inc(&op->ref);
}
EXPORT_SYMBOL(netfs_get_write_operation);
