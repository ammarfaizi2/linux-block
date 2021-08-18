// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem content encryption support.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
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

	n = alloc_pages_bulk_list(GFP_NOIO, nr_pages, &list);
	if (n < nr_pages) {
		ret = -ENOMEM;
	}

	while ((page = list_first_entry_or_null(&list, struct page, lru))) {
		list_del(&page->lru);
		page->index = index;
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
 * Populate a scatterlist from folios in an xarray.
 */
static int netfs_xarray_to_sglist(struct xarray *xa, loff_t pos, size_t len,
				  struct scatterlist *sg, unsigned int n_sg)
{
	struct scatterlist *p = sg;
	struct folio *folio = NULL;
	size_t seg, offset, skip = 0;
	loff_t start = pos;
	pgoff_t index = start >> PAGE_SHIFT;
	int j;

	XA_STATE(xas, xa, index);

	sg_init_table(sg, n_sg);

	rcu_read_lock();

	xas_for_each(&xas, folio, ULONG_MAX) {
		if (xas_retry(&xas, folio))
			continue;
		if (WARN_ON(xa_is_value(folio)) || WARN_ON(folio_test_hugetlb(folio)))
			break;
		for (j = (folio_index(folio) < index) ? index - folio_index(folio) : 0;
		     j < folio_nr_pages(folio); j++
		     ) {
			struct page *subpage = folio_file_page(folio, j);

			offset = (pos + skip) & ~PAGE_MASK;
			seg = min(len, PAGE_SIZE - offset);

			sg_set_page(p++, subpage, seg, offset);

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
		kdebug("*** Insufficient source (%zx)", len);
		//WARN_ON(len > 0);
		return -EIO;
	}

	sg_mark_end(p - 1);
	return p - sg;
}

/*
 * Prepare a write request for writing.  All the pages in the bounding box have
 * had a ref taken on them and those covering the dirty region have been marked
 * as being written back and their dirty bits provisionally cleared.
 */
bool netfs_wreq_encrypt(struct netfs_write_request *wreq)
{
	struct netfs_i_context *ctx = netfs_i_context(wreq->inode);
	struct scatterlist source_sg[16], dest_sg[16];
	unsigned int n_source, n_dest;
	size_t n, chunk, bsize = 1UL << ctx->crypto_bshift;
	loff_t pos;
	int ret;

	ret = netfs_alloc_buffer(&wreq->buffer, wreq->first, wreq->last - wreq->first + 1);
	if (ret < 0)
		goto error;

	_debug("ENCRYPT %llx-%llx", wreq->coverage.start, wreq->coverage.end);

	pos = round_down(wreq->coverage.start, bsize);
	n = wreq->coverage.end - pos;
	for (; n > 0; n -= chunk, pos += chunk) {
		chunk = min(n, bsize);
		ret = netfs_xarray_to_sglist(&wreq->mapping->i_pages, pos, chunk,
					     source_sg, ARRAY_SIZE(source_sg));
		if (ret < 0)
			goto error;
		n_source = ret;

		ret = netfs_xarray_to_sglist(&wreq->buffer, pos, chunk,
					     dest_sg, ARRAY_SIZE(dest_sg));
		if (ret < 0)
			goto error;
		n_dest = ret;

		ret = ctx->ops->encrypt_block(wreq, pos, chunk,
					      source_sg, n_source, dest_sg, n_dest);
		if (ret < 0)
			goto error;
	}

	__set_bit(NETFS_WREQ_BUFFERED, &wreq->flags);
	return true;

error:
	wreq->error = ret;
	return false;
}

/*
 * Decrypt the result of a read request.
 */
void netfs_rreq_decrypt(struct netfs_read_request *rreq)
{
	struct netfs_i_context *ctx = netfs_i_context(rreq->inode);
	struct scatterlist sg[16];
	unsigned int n_sg;
	size_t n, chunk, bsize = 1UL << ctx->crypto_bshift;
	loff_t pos;
	int ret;

	_debug("DECRYPT %llx-%llx", rreq->start, rreq->start + rreq->len);

	pos = rreq->start;
	n = rreq->len;
	for (; n > 0; n -= chunk, pos += chunk) {
		chunk = min(n, bsize);
		ret = netfs_xarray_to_sglist(&rreq->mapping->i_pages, pos, chunk,
					     sg, ARRAY_SIZE(sg));
		if (ret < 0)
			goto error;
		n_sg = ret;

		ret = ctx->ops->decrypt_block(rreq, pos, chunk, sg, n_sg, sg, n_sg);
		if (ret < 0)
			goto error;
	}

	return;

error:
	rreq->error = ret;
	set_bit(NETFS_RREQ_FAILED, &rreq->flags);
	return;
}
