/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022, Oracle and/or its affiliates.
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef _IOVA_BITMAP_H_
#define _IOVA_BITMAP_H_

#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/uio.h>

struct iova_bitmap {
	unsigned long iova;
	unsigned long pgshift;
	unsigned long start_offset;
	unsigned long npages;
	struct page **pages;
};

struct iova_bitmap_iter {
	struct iova_bitmap dirty;
	u64 __user *data;
	size_t offset;
	size_t count;
	unsigned long iova;
	unsigned long length;
};

int iova_bitmap_iter_init(struct iova_bitmap_iter *iter, unsigned long iova,
			  unsigned long length, u64 __user *data);
void iova_bitmap_iter_free(struct iova_bitmap_iter *iter);
bool iova_bitmap_iter_done(struct iova_bitmap_iter *iter);
unsigned long iova_bitmap_length(struct iova_bitmap_iter *iter);
unsigned long iova_bitmap_iova(struct iova_bitmap_iter *iter);
void iova_bitmap_iter_advance(struct iova_bitmap_iter *iter);
int iova_bitmap_iter_get(struct iova_bitmap_iter *iter);
void iova_bitmap_iter_put(struct iova_bitmap_iter *iter);
void iova_bitmap_init(struct iova_bitmap *bitmap,
		      unsigned long base, unsigned long pgshift);
unsigned int iova_bitmap_set(struct iova_bitmap *dirty,
			     unsigned long iova,
			     unsigned long length);

#endif
