/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bvec iterator
 *
 * Copyright (C) 2001 Ming Lei <ming.lei@canonical.com>
 */
#ifndef __LINUX_BVEC_API_H
#define __LINUX_BVEC_API_H

#include <linux/bvec_types.h>

#include <linux/highmem_extra.h>
#include <linux/highmem.h>

/**
 * bvec_kmap_local - map a bvec into the kernel virtual address space
 * @bvec: bvec to map
 *
 * Must be called on single-page bvecs only.  Call kunmap_local on the returned
 * address to unmap.
 */
static inline void *bvec_kmap_local(struct bio_vec *bvec)
{
	return kmap_local_page(bvec->bv_page) + bvec->bv_offset;
}

/**
 * memcpy_from_bvec - copy data from a bvec
 * @bvec: bvec to copy from
 *
 * Must be called on single-page bvecs only.
 */
static inline void memcpy_from_bvec(char *to, struct bio_vec *bvec)
{
	memcpy_from_page(to, bvec->bv_page, bvec->bv_offset, bvec->bv_len);
}

/**
 * memcpy_to_bvec - copy data to a bvec
 * @bvec: bvec to copy to
 *
 * Must be called on single-page bvecs only.
 */
static inline void memcpy_to_bvec(struct bio_vec *bvec, const char *from)
{
	memcpy_to_page(bvec->bv_page, bvec->bv_offset, from, bvec->bv_len);
}

/**
 * memzero_bvec - zero all data in a bvec
 * @bvec: bvec to zero
 *
 * Must be called on single-page bvecs only.
 */
static inline void memzero_bvec(struct bio_vec *bvec)
{
	memzero_page(bvec->bv_page, bvec->bv_offset, bvec->bv_len);
}

extern void *bvec_virt(struct bio_vec *bvec);

#endif /* __LINUX_BVEC_API_H */
