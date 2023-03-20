// SPDX-License-Identifier: GPL-2.0-only
/* Page fragment allocator
 *
 * Page Fragment:
 *  An arbitrary-length arbitrary-offset area of memory which resides within a
 *  0 or higher order page.  Multiple fragments within that page are
 *  individually refcounted, in the page's reference counter.
 *
 * The page_frag functions provide a simple allocation framework for page
 * fragments.  This is used by the network stack and network device drivers to
 * provide a backing region of memory for use as either an sk_buff->head, or to
 * be used in the "frags" portion of skb_shared_info.
 */

#include <linux/export.h>
#include <linux/init.h>
#include <linux/mm.h>

static DEFINE_PER_CPU(struct page_frag_cache, page_frag_default_allocator);

/*
 * Allocate a new folio for the frag cache.
 */
static struct folio *page_frag_cache_refill(gfp_t gfp)
{
	struct folio *folio;

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	folio = folio_alloc(gfp | __GFP_NOWARN | __GFP_NORETRY | __GFP_NOMEMALLOC,
			    PAGE_FRAG_CACHE_MAX_ORDER);
	if (folio)
		return folio;
#endif

	return folio_alloc(gfp, 0);
}

void __page_frag_cache_drain(struct page *page, unsigned int count)
{
	struct folio *folio = page_folio(page);

	VM_BUG_ON_FOLIO(folio_ref_count(folio) == 0, folio);

	folio_put_refs(folio, count);
}
EXPORT_SYMBOL(__page_frag_cache_drain);

/**
 * page_frag_alloc_align - Allocate some memory for use in zerocopy
 * @frag_cache: The frag cache to use (or NULL for the default)
 * @fragsz: The size of the fragment desired
 * @gfp: Allocation flags under which to make an allocation
 * @align_mask: The required alignment
 *
 * Allocate some memory for use with zerocopy where protocol bits have to be
 * mixed in with spliced/zerocopied data.  Unlike memory allocated from the
 * slab, this memory's lifetime is purely dependent on the folio's refcount.
 *
 * The way it works is that a folio is allocated and fragments are broken off
 * sequentially and returned to the caller with a ref until the folio no longer
 * has enough spare space - at which point the allocator's ref is dropped and a
 * new folio is allocated.  The folio remains in existence until the last ref
 * held by, say, an sk_buff is discarded and then the page is returned to the
 * page allocator.
 *
 * Returns a pointer to the memory on success and -ENOMEM on allocation
 * failure.
 *
 * The allocated memory should be disposed of with folio_put().
 */
void *page_frag_alloc_align(struct page_frag_cache __percpu *frag_cache,
			    size_t fragsz, gfp_t gfp, unsigned long align_mask)
{
	struct page_frag_cache *nc;
	struct folio *folio, *spare = NULL;
	size_t offset;
	void *p;

	if (!frag_cache)
		frag_cache = &page_frag_default_allocator;
	if (WARN_ON_ONCE(fragsz == 0))
		fragsz = 1;
	align_mask &= ~3UL;

	nc = get_cpu_ptr(frag_cache);
reload:
	folio = nc->folio;
	offset = nc->offset;
try_again:

	/* Make the allocation if there's sufficient space. */
	if (fragsz <= offset) {
		nc->pagecnt_bias--;
		offset = (offset - fragsz) & align_mask;
		nc->offset = offset;
		p = folio_address(folio) + offset;
		put_cpu_ptr(frag_cache);
		if (spare)
			folio_put(spare);
		return p;
	}

	/* Insufficient space - see if we can refurbish the current folio. */
	if (folio) {
		if (!folio_ref_sub_and_test(folio, nc->pagecnt_bias))
			goto refill;

		if (unlikely(nc->pfmemalloc)) {
			__folio_put(folio);
			goto refill;
		}

		/* OK, page count is 0, we can safely set it */
		folio_set_count(folio, PAGE_FRAG_CACHE_MAX_SIZE + 1);

		/* reset page count bias and offset to start of new frag */
		nc->pagecnt_bias = PAGE_FRAG_CACHE_MAX_SIZE + 1;
		offset = folio_size(folio);
		if (unlikely(fragsz > offset))
			goto frag_too_big;
		goto try_again;
	}

refill:
	if (!spare) {
		nc->folio = NULL;
		put_cpu_ptr(frag_cache);

		spare = page_frag_cache_refill(gfp);
		if (!spare)
			return NULL;

		nc = get_cpu_ptr(frag_cache);
		/* We may now be on a different cpu and/or someone else may
		 * have refilled it
		 */
		nc->pfmemalloc = folio_is_pfmemalloc(spare);
		if (nc->folio)
			goto reload;
	}

	nc->folio = spare;
	folio = spare;
	spare = NULL;

	/* Even if we own the page, we do not use atomic_set().  This would
	 * break get_page_unless_zero() users.
	 */
	folio_ref_add(folio, PAGE_FRAG_CACHE_MAX_SIZE);

	/* Reset page count bias and offset to start of new frag */
	nc->pagecnt_bias = PAGE_FRAG_CACHE_MAX_SIZE + 1;
	offset = folio_size(folio);
	goto try_again;

frag_too_big:
	/*
	 * The caller is trying to allocate a fragment with fragsz > PAGE_SIZE
	 * but the cache isn't big enough to satisfy the request, this may
	 * happen in low memory conditions.  We don't release the cache page
	 * because it could make memory pressure worse so we simply return NULL
	 * here.
	 */
	nc->offset = offset;
	put_cpu_ptr(frag_cache);
	if (spare)
		folio_put(spare);
	return NULL;
}
EXPORT_SYMBOL(page_frag_alloc_align);

/*
 * Frees a page fragment allocated out of either a compound or order 0 page.
 */
void page_frag_free(void *addr)
{
	folio_put(virt_to_folio(addr));
}
EXPORT_SYMBOL(page_frag_free);

/**
 * page_frag_memdup - Allocate a page fragment and duplicate some data into it
 * @frag_cache: The frag cache to use (or NULL for the default)
 * @fragsz: The amount of memory to copy (maximum 1/2 page).
 * @p: The source data to copy
 * @gfp: Allocation flags under which to make an allocation
 * @align_mask: The required alignment
 */
void *page_frag_memdup(struct page_frag_cache __percpu *frag_cache,
		       const void *p, size_t fragsz, gfp_t gfp,
		       unsigned long align_mask)
{
	void *q;

	q = page_frag_alloc_align(frag_cache, fragsz, gfp, align_mask);
	if (!q)
		return q;

	return memcpy(q, p, fragsz);
}
EXPORT_SYMBOL(page_frag_memdup);
