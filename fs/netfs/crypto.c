// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem content encryption support.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
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
int netfs_alloc_buffer(struct xarray *xa, pgoff_t index, unsigned int nr_pages)
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
			seg = min_t(size_t, len, PAGE_SIZE - offset);

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

struct netfs_iter_to_sglist_info {
	struct scatterlist	*p;
	int			n_sg;
};

static ssize_t netfs_iter_to_sglist_scanner(struct iov_iter *i, const void *p,
					    size_t len, size_t off, void *priv)
{
	struct netfs_iter_to_sglist_info *info = priv;
	struct page *page = virt_to_page(p);

	if (info->n_sg <= 0)
		return -ENOBUFS;
	sg_set_page(info->p++, page, len, off);
	info->n_sg--;
	return 0;
}

/*
 * Populate a scatterlist from the next bufferage of an I/O iterator.
 */
static int netfs_iter_to_sglist(struct iov_iter *iter, size_t len,
				struct scatterlist *sg, unsigned int n_sg)
{
	struct netfs_iter_to_sglist_info info = { sg, n_sg };

	_enter("%zx/%zx", len, iov_iter_count(iter));

	sg_init_table(sg, n_sg);
	iov_iter_scan(iter, len, netfs_iter_to_sglist_scanner, &info);
	sg_mark_end(info.p - 1);
	return info.p - sg;
}

/*
 * Prepare a write request for writing.  We encrypt from wreq->buffer to
 * wreq->buffer2.
 */
bool netfs_encrypt(struct netfs_io_request *wreq)
{
	struct netfs_inode *ctx = netfs_inode(wreq->inode);
	struct scatterlist source_sg[16], dest_sg[16];
	unsigned int n_source, n_dest;
	size_t n, chunk, bsize = 1UL << ctx->crypto_bshift;
	loff_t pos;
	int ret;

	_enter("");

	trace_netfs_rreq(wreq, netfs_rreq_trace_encrypt);

	pos = wreq->start;
	n = wreq->len;
	_debug("ENCRYPT %llx-%llx", pos, pos + n - 1);

	for (; n > 0; n -= chunk, pos += chunk) {
		chunk = min(n, bsize);

		switch (wreq->buffering) {
		case NETFS_ENC_BUFFER_TO_BOUNCE:
			ret = netfs_xarray_to_sglist(&wreq->buffer, pos, chunk,
						     source_sg, ARRAY_SIZE(source_sg));
			break;
		case NETFS_ENC_DIRECT_TO_BOUNCE:
			ret = netfs_iter_to_sglist(&wreq->direct_iter, chunk,
						   dest_sg, ARRAY_SIZE(dest_sg));
			break;
		case NETFS_COPY_ENC_BOUNCE:
			ret = netfs_xarray_to_sglist(&wreq->bounce, pos, chunk,
						     source_sg, ARRAY_SIZE(source_sg));
			break;
		default:
			BUG();
		}
		if (ret < 0)
			goto error;
		n_source = ret;

		switch (wreq->buffering) {
		case NETFS_ENC_BUFFER_TO_BOUNCE:
		case NETFS_ENC_DIRECT_TO_BOUNCE:
			ret = netfs_xarray_to_sglist(&wreq->bounce, pos, chunk,
						     dest_sg, ARRAY_SIZE(dest_sg));
			break;
		case NETFS_COPY_ENC_BOUNCE:
			memcpy(dest_sg, source_sg, sizeof(dest_sg));
			ret = n_source;
			break;
		default:
			BUG();
		}
		if (ret < 0)
			goto error;
		n_dest = ret;

		ret = ctx->ops->encrypt_block(wreq, pos, chunk,
					      source_sg, n_source, dest_sg, n_dest);
		if (ret < 0)
			goto error_failed;
	}

	return true;

error_failed:
	trace_netfs_failure(wreq, NULL, ret, netfs_fail_encryption);
error:
	wreq->error = ret;
	return false;
}
