// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem high-level write support.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * Allocate a bunch of pages and add them into the xarray buffer starting at
 * the given index.
 */
static int netfs_alloc_buffer(struct xarray *xa, pgoff_t index, unsigned int nr_pages)
{
	struct page *page;
	unsigned int n;
	int ret;
	LIST_HEAD(list);

	kenter("");

	n = alloc_pages_bulk_list(GFP_NOIO, nr_pages, &list);
	if (n < nr_pages) {
		ret = -ENOMEM;
	}

	while ((page = list_first_entry_or_null(&list, struct page, lru))) {
		list_del(&page->lru);
		ret = xa_insert(xa, index++, page, GFP_NOIO);
		if (ret < 0)
			break;
	}

	while ((page = list_first_entry_or_null(&list, struct page, lru))) {
		list_del(&page->lru);
		__free_page(page);
	}
	return ret;
}

/*
 * Populate a scatterlist from pages in an xarray.
 */
static int netfs_xarray_to_sglist(struct xarray *xa, loff_t pos, size_t len,
				  struct scatterlist *sg, unsigned int n_sg)
{
	struct scatterlist *p = sg;
	struct page *head = NULL;
	size_t seg, offset, skip = 0;
	loff_t start = pos;
	pgoff_t index = start >> PAGE_SHIFT;
	int j;

	XA_STATE(xas, xa, index);

	sg_init_table(sg, n_sg);

	rcu_read_lock();

	xas_for_each(&xas, head, ULONG_MAX) {
		kdebug("LOAD %lx %px", head->index, head);
		if (xas_retry(&xas, head))
			continue;
		if (WARN_ON(xa_is_value(head)) || WARN_ON(PageHuge(head)))
			break;
		for (j = (head->index < index) ? index - head->index : 0;
		     j < thp_nr_pages(head); j++
		     ) {
			offset = (pos + skip) & ~PAGE_MASK;
			seg = min(len, PAGE_SIZE - offset);

			kdebug("[%zx] %lx %zx @%zx", p - sg, (head + j)->index, seg, offset);
			sg_set_page(p++, head + j, seg, offset);

			len -= seg;
			skip += seg;
			if (len == 0)
				break;
		}
		if (len == 0)
			break;
	}

	rcu_read_unlock();
	if (len > 0) {
		WARN_ON(len > 0);
		return -EIO;
	}

	sg_mark_end(p - 1);
	kleave(" = %zd", p - sg);
	return p - sg;
}

/*
 * Perform content encryption on the data to be written before we write it to
 * the server and the cache.
 */
static bool netfs_prepare_encrypt(struct netfs_write_request *wreq)
{
	struct netfs_i_context *ctx = netfs_i_context(wreq->inode);
	struct scatterlist source_sg[16], dest_sg[16];
	unsigned int bsize = 1 << ctx->crypto_bsize, n_source, n_dest;
	loff_t pos;
	size_t n;
	int ret;

	ret = netfs_alloc_buffer(&wreq->buffer, wreq->first, wreq->last - wreq->first + 1);
	if (ret < 0)
		goto error;

	pos = round_down(wreq->start, bsize);
	n = round_up(wreq->start + wreq->len, bsize) - pos;
	for (; n > 0; n -= bsize, pos += bsize) {
		ret = netfs_xarray_to_sglist(&wreq->mapping->i_pages, pos, bsize,
					     source_sg, ARRAY_SIZE(source_sg));
		if (ret < 0)
			goto error;
		n_source = ret;

		ret = netfs_xarray_to_sglist(&wreq->buffer, pos, bsize,
					     dest_sg, ARRAY_SIZE(dest_sg));
		if (ret < 0)
			goto error;
		n_dest = ret;

		ret = ctx->ops->encrypt_block(wreq, pos, bsize,
					      source_sg, n_source, dest_sg, n_dest);
		if (ret < 0)
			goto error;
	}

	iov_iter_xarray(&wreq->source, WRITE, &wreq->buffer, wreq->start, wreq->len);
	kleave(" = t");
	return true;

error:
	wreq->error = ret;
	kleave(" = f [%d]", ret);
	return false;
}

/*
 * Prepare a write request for writing.  All the pages in the bounding box have
 * had a ref taken on them and those covering the dirty region have been marked
 * as being written back and their dirty bits provisionally cleared.
 */
bool netfs_prepare_wreq(struct netfs_write_request *wreq)
{
	struct netfs_i_context *ctx = netfs_i_context(wreq->inode);

	if (test_bit(NETFS_ICTX_ENCRYPTED, &ctx->flags))
		return netfs_prepare_encrypt(wreq);
	return true;
}
