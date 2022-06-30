// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022, Oracle and/or its affiliates.
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/iova_bitmap.h>

static unsigned long iova_bitmap_iova_to_index(struct iova_bitmap_iter *iter,
					       unsigned long iova_length)
{
	unsigned long pgsize = 1 << iter->dirty.pgshift;

	return DIV_ROUND_UP(iova_length, BITS_PER_TYPE(*iter->data) * pgsize);
}

static unsigned long iova_bitmap_index_to_iova(struct iova_bitmap_iter *iter,
					       unsigned long index)
{
	unsigned long pgshift = iter->dirty.pgshift;

	return (index * sizeof(*iter->data) * BITS_PER_BYTE) << pgshift;
}

static unsigned long iova_bitmap_iter_left(struct iova_bitmap_iter *iter)
{
	unsigned long left = iter->count - iter->offset;

	left = min_t(unsigned long, left,
		     (iter->dirty.npages << PAGE_SHIFT) / sizeof(*iter->data));

	return left;
}

/*
 * Input argument of number of bits to bitmap_set() is unsigned integer, which
 * further casts to signed integer for unaligned multi-bit operation,
 * __bitmap_set().
 * Then maximum bitmap size supported is 2^31 bits divided by 2^3 bits/byte,
 * that is 2^28 (256 MB) which maps to 2^31 * 2^12 = 2^43 (8TB) on 4K page
 * system.
 */
int iova_bitmap_iter_init(struct iova_bitmap_iter *iter,
			  unsigned long iova, unsigned long length,
			  u64 __user *data)
{
	struct iova_bitmap *dirty = &iter->dirty;

	iter->data = data;
	iter->offset = 0;
	iter->count = iova_bitmap_iova_to_index(iter, length);
	iter->iova = iova;
	iter->length = length;
	dirty->pages = (struct page **)__get_free_page(GFP_KERNEL);

	return !dirty->pages ? -ENOMEM : 0;
}

void iova_bitmap_iter_free(struct iova_bitmap_iter *iter)
{
	struct iova_bitmap *dirty = &iter->dirty;

	if (dirty->pages) {
		free_page((unsigned long)dirty->pages);
		dirty->pages = NULL;
	}
}

bool iova_bitmap_iter_done(struct iova_bitmap_iter *iter)
{
	return iter->offset >= iter->count;
}

unsigned long iova_bitmap_length(struct iova_bitmap_iter *iter)
{
	unsigned long max_iova = iter->dirty.iova + iter->length;
	unsigned long left = iova_bitmap_iter_left(iter);
	unsigned long iova = iova_bitmap_iova(iter);

	left = iova_bitmap_index_to_iova(iter, left);
	if (iova + left > max_iova)
		left -= ((iova + left) - max_iova);

	return left;
}

unsigned long iova_bitmap_iova(struct iova_bitmap_iter *iter)
{
	unsigned long skip = iter->offset;

	return iter->iova + iova_bitmap_index_to_iova(iter, skip);
}

void iova_bitmap_iter_advance(struct iova_bitmap_iter *iter)
{
	unsigned long length = iova_bitmap_length(iter);

	iter->offset += iova_bitmap_iova_to_index(iter, length);
}

void iova_bitmap_iter_put(struct iova_bitmap_iter *iter)
{
	struct iova_bitmap *dirty = &iter->dirty;

	if (dirty->npages)
		unpin_user_pages(dirty->pages, dirty->npages);
}

int iova_bitmap_iter_get(struct iova_bitmap_iter *iter)
{
	struct iova_bitmap *dirty = &iter->dirty;
	unsigned long npages;
	u64 __user *addr;
	long ret;

	npages = DIV_ROUND_UP((iter->count - iter->offset) *
			      sizeof(*iter->data), PAGE_SIZE);
	npages = min(npages,  PAGE_SIZE / sizeof(struct page *));
	addr = iter->data + iter->offset;
	ret = pin_user_pages_fast((unsigned long)addr, npages,
				  FOLL_WRITE, dirty->pages);
	if (ret <= 0)
		return ret;

	dirty->npages = (unsigned long)ret;
	dirty->iova = iova_bitmap_iova(iter);
	dirty->start_offset = offset_in_page(addr);
	return 0;
}

void iova_bitmap_init(struct iova_bitmap *bitmap,
		      unsigned long base, unsigned long pgshift)
{
	memset(bitmap, 0, sizeof(*bitmap));
	bitmap->iova = base;
	bitmap->pgshift = pgshift;
}

unsigned int iova_bitmap_set(struct iova_bitmap *dirty,
			     unsigned long iova,
			     unsigned long length)
{
	unsigned long nbits, offset, start_offset, idx, size, *kaddr;

	nbits = max(1UL, length >> dirty->pgshift);
	offset = (iova - dirty->iova) >> dirty->pgshift;
	idx = offset / (PAGE_SIZE * BITS_PER_BYTE);
	offset = offset % (PAGE_SIZE * BITS_PER_BYTE);
	start_offset = dirty->start_offset;

	while (nbits > 0) {
		kaddr = kmap_local_page(dirty->pages[idx]) + start_offset;
		size = min(PAGE_SIZE * BITS_PER_BYTE - offset, nbits);
		bitmap_set(kaddr, offset, size);
		kunmap_local(kaddr - start_offset);
		start_offset = offset = 0;
		nbits -= size;
		idx++;
	}

	return nbits;
}
EXPORT_SYMBOL_GPL(iova_bitmap_set);

