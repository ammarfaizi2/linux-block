/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bvec iterator
 *
 * Copyright (C) 2001 Ming Lei <ming.lei@canonical.com>
 */
#include <linux/bvec.h>
#include <linux/mm.h>
#include <linux/minmax.h>

void bvec_advance(const struct bio_vec *bvec, struct bvec_iter_all *iter_all)
{
	struct bio_vec *bv = &iter_all->bv;

	if (iter_all->done) {
		bv->bv_page++;
		bv->bv_offset = 0;
	} else {
		bv->bv_page = bvec->bv_page + (bvec->bv_offset >> PAGE_SHIFT);
		bv->bv_offset = bvec->bv_offset & ~PAGE_MASK;
	}
	bv->bv_len = min_t(unsigned int, PAGE_SIZE - bv->bv_offset,
			   bvec->bv_len - iter_all->done);
	iter_all->done += bv->bv_len;

	if (iter_all->done == bvec->bv_len) {
		iter_all->idx++;
		iter_all->done = 0;
	}
}
EXPORT_SYMBOL_GPL(bvec_advance);

/**
 * bvec_virt - return the virtual address for a bvec
 * @bvec: bvec to return the virtual address for
 *
 * Note: the caller must ensure that @bvec->bv_page is not a highmem page.
 */
void *bvec_virt(struct bio_vec *bvec)
{
	WARN_ON_ONCE(PageHighMem(bvec->bv_page));
	return page_address(bvec->bv_page) + bvec->bv_offset;
}
EXPORT_SYMBOL_GPL(bvec_virt);
