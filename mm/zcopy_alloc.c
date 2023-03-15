// SPDX-License-Identifier: GPL-2.0-only
/* Allocator for zerocopy filler fragments
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Provide a facility whereby pieces of bufferage can be allocated for
 * insertion into bio_vec arrays intended for zerocopying, allowing protocol
 * stuff to be mixed in with data.
 *
 * Unlike objects allocated from the slab, the lifetime of these pieces of
 * buffer are governed purely by the refcount of the page in which they reside.
 */

#include <linux/export.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/zcopy_alloc.h>
#include <linux/bvec.h>

struct zcopy_alloc_info {
	struct folio	*folio;		/* Page currently being allocated from */
	struct folio	*spare;		/* Spare page */
	unsigned int	used;		/* Amount of folio used */
	spinlock_t	lock;		/* Allocation lock (needs bh-disable) */
};

static struct zcopy_alloc_info __percpu *zcopy_alloc_info;

static int __init zcopy_alloc_init(void)
{
	zcopy_alloc_info = alloc_percpu(struct zcopy_alloc_info);
	if (!zcopy_alloc_info)
		panic("Unable to set up zcopy_alloc allocator\n");
	return 0;
}
subsys_initcall(zcopy_alloc_init);

/**
 * zcopy_alloc - Allocate some memory for use in zerocopy
 * @size: The amount of memory (maximum 1/2 page).
 * @bvec: Where to store the details of the memory
 * @gfp: Allocation flags under which to make an allocation
 *
 * Allocate some memory for use with zerocopy where protocol bits have to be
 * mixed in with spliced/zerocopied data.  Unlike memory allocated from the
 * slab, this memory's lifetime is purely dependent on the folio's refcount.
 *
 * The way it works is that a folio is allocated and pieces are broken off
 * sequentially and given to the allocators with a ref until it no longer has
 * enough spare space, at which point the allocator's ref is dropped and a new
 * folio is allocated.  The folio remains in existence until the last ref held
 * by, say, a sk_buff is discarded and then the page is returned to the
 * allocator.
 *
 * Returns 0 on success and -ENOMEM on allocation failure.  If successful, the
 * details of the allocated memory are placed in *%bvec.
 *
 * The allocated memory should be disposed of with folio_put().
 */
int zcopy_alloc(size_t size, struct bio_vec *bvec, gfp_t gfp)
{
	struct zcopy_alloc_info *info;
	struct folio *folio, *spare = NULL;
	size_t full_size = round_up(size, 8);

	if (WARN_ON_ONCE(full_size > PAGE_SIZE / 2))
		return -ENOMEM; /* Allocate pages */

try_again:
	info = get_cpu_ptr(zcopy_alloc_info);

	folio = info->folio;
	if (folio && folio_size(folio) - info->used < full_size) {
		folio_put(folio);
		folio = info->folio = NULL;
	}
	if (spare && !info->spare) {
		info->spare = spare;
		spare = NULL;
	}
	if (!folio && info->spare) {
		folio = info->folio = info->spare;
		info->spare = NULL;
		info->used = 0;
	}
	if (folio) {
		bvec_set_folio(bvec, folio, size, info->used);
		info->used += full_size;
		if (info->used < folio_size(folio))
			folio_get(folio);
		else
			info->folio = NULL;
	}

	put_cpu_ptr(zcopy_alloc_info);
	if (folio) {
		if (spare)
			folio_put(spare);
		return 0;
	}

	spare = folio_alloc(gfp, 0);
	if (!spare)
		return -ENOMEM;
	goto try_again;
}
EXPORT_SYMBOL(zcopy_alloc);

/**
 * zcopy_memdup - Allocate some memory for use in zerocopy and fill it
 * @size: The amount of memory to copy (maximum 1/2 page).
 * @p: The source data to copy
 * @bvec: Where to store the details of the memory
 * @gfp: Allocation flags under which to make an allocation
 */
int zcopy_memdup(size_t size, const void *p, struct bio_vec *bvec, gfp_t gfp)
{
	void *q;

	if (zcopy_alloc(size, bvec, gfp) < 0)
		return -ENOMEM;

	q = kmap_local_folio(page_folio(bvec->bv_page), bvec->bv_offset);
	memcpy(q, p, size);
	kunmap_local(q);
	return 0;
}
EXPORT_SYMBOL(zcopy_memdup);
