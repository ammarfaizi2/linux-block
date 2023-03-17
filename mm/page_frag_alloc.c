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

/*
 * Allocate a new folio for the frag cache.
 */
static struct folio *page_frag_cache_refill(struct page_frag_cache *nc,
					    gfp_t gfp_mask)
{
	struct folio *folio = NULL;
	gfp_t gfp = gfp_mask;

#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	gfp_mask |= __GFP_NOWARN | __GFP_NORETRY | __GFP_NOMEMALLOC;
	folio = folio_alloc(gfp_mask, PAGE_FRAG_CACHE_MAX_ORDER);
#endif
	if (unlikely(!folio))
		folio = folio_alloc(gfp, 0);

	if (folio)
		nc->folio = folio;
	return folio;
}

void __page_frag_cache_drain(struct page *page, unsigned int count)
{
	struct folio *folio = page_folio(page);

	VM_BUG_ON_FOLIO(folio_ref_count(folio) == 0, folio);

	folio_put_refs(folio, count);
}
EXPORT_SYMBOL(__page_frag_cache_drain);

void page_frag_cache_clear(struct page_frag_cache *nc)
{
	struct folio *folio = nc->folio;

	if (folio) {
		VM_BUG_ON_FOLIO(folio_ref_count(folio) == 0, folio);
		folio_put_refs(folio, nc->pagecnt_bias);
		nc->folio = NULL;
	}
}
EXPORT_SYMBOL(page_frag_cache_clear);

void *page_frag_alloc_align(struct page_frag_cache *nc,
		      unsigned int fragsz, gfp_t gfp_mask,
		      unsigned int align_mask)
{
	struct folio *folio = nc->folio;
	size_t offset;

	if (unlikely(!folio)) {
refill:
		folio = page_frag_cache_refill(nc, gfp_mask);
		if (!folio)
			return NULL;

		/* Even if we own the page, we do not use atomic_set().
		 * This would break get_page_unless_zero() users.
		 */
		folio_ref_add(folio, PAGE_FRAG_CACHE_MAX_SIZE);

		/* reset page count bias and offset to start of new frag */
		nc->pfmemalloc = folio_is_pfmemalloc(folio);
		nc->pagecnt_bias = PAGE_FRAG_CACHE_MAX_SIZE + 1;
		nc->offset = folio_size(folio);
	}

	offset = nc->offset;
	if (unlikely(fragsz > offset)) {
		/* Reuse the folio if everyone we gave it to has finished with
		 * it.
		 */
		if (!folio_ref_sub_and_test(folio, nc->pagecnt_bias)) {
			nc->folio = NULL;
			goto refill;
		}

		if (unlikely(nc->pfmemalloc)) {
			__folio_put(folio);
			nc->folio = NULL;
			goto refill;
		}

		/* OK, page count is 0, we can safely set it */
		folio_set_count(folio, PAGE_FRAG_CACHE_MAX_SIZE + 1);

		/* reset page count bias and offset to start of new frag */
		nc->pagecnt_bias = PAGE_FRAG_CACHE_MAX_SIZE + 1;
		offset = folio_size(folio);
		if (unlikely(fragsz > offset)) {
			/*
			 * The caller is trying to allocate a fragment
			 * with fragsz > PAGE_SIZE but the cache isn't big
			 * enough to satisfy the request, this may
			 * happen in low memory conditions.
			 * We don't release the cache page because
			 * it could make memory pressure worse
			 * so we simply return NULL here.
			 */
			nc->offset = offset;
			return NULL;
		}
	}

	nc->pagecnt_bias--;
	offset -= fragsz;
	offset &= align_mask;
	nc->offset = offset;

	return folio_address(folio) + offset;
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
