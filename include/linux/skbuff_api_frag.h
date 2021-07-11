/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_SKBUFF_API_FRAG_H
#define _LINUX_SKBUFF_API_FRAG_H

#include <linux/mm_page_address.h>
#include <linux/gfp_api.h>
#include <linux/mm_api.h>
#include <linux/skbuff_api.h>

#include <net/page_pool.h>

/**
 * skb_frag_size() - Returns the size of a skb fragment
 * @frag: skb fragment
 */
static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
	return frag->bv_len;
}

/**
 * skb_frag_size_set() - Sets the size of a skb fragment
 * @frag: skb fragment
 * @size: size of fragment
 */
static inline void skb_frag_size_set(skb_frag_t *frag, unsigned int size)
{
	frag->bv_len = size;
}

/**
 * skb_frag_size_add() - Increments the size of a skb fragment by @delta
 * @frag: skb fragment
 * @delta: value to add
 */
static inline void skb_frag_size_add(skb_frag_t *frag, int delta)
{
	frag->bv_len += delta;
}

/**
 * skb_frag_size_sub() - Decrements the size of a skb fragment by @delta
 * @frag: skb fragment
 * @delta: value to subtract
 */
static inline void skb_frag_size_sub(skb_frag_t *frag, int delta)
{
	frag->bv_len -= delta;
}

/**
 * skb_frag_must_loop - Test if %p is a high memory page
 * @p: fragment's page
 */
static inline bool skb_frag_must_loop(struct page *p)
{
#if defined(CONFIG_HIGHMEM)
	if (IS_ENABLED(CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP) || PageHighMem(p))
		return true;
#endif
	return false;
}

/**
 *	skb_frag_foreach_page - loop over pages in a fragment
 *
 *	@f:		skb frag to operate on
 *	@f_off:		offset from start of f->bv_page
 *	@f_len:		length from f_off to loop over
 *	@p:		(temp var) current page
 *	@p_off:		(temp var) offset from start of current page,
 *	                           non-zero only on first page.
 *	@p_len:		(temp var) length in current page,
 *				   < PAGE_SIZE only on first and last page.
 *	@copied:	(temp var) length so far, excluding current p_len.
 *
 *	A fragment can hold a compound page, in which case per-page
 *	operations, notably kmap_atomic, must be called for each
 *	regular page.
 */
#define skb_frag_foreach_page(f, f_off, f_len, p, p_off, p_len, copied)	\
	for (p = skb_frag_page(f) + ((f_off) >> PAGE_SHIFT),		\
	     p_off = (f_off) & (PAGE_SIZE - 1),				\
	     p_len = skb_frag_must_loop(p) ?				\
	     min_t(u32, f_len, PAGE_SIZE - p_off) : f_len,		\
	     copied = 0;						\
	     copied < f_len;						\
	     copied += p_len, p++, p_off = 0,				\
	     p_len = min_t(u32, f_len - copied, PAGE_SIZE))		\

static inline unsigned int __skb_pagelen(const struct sk_buff *skb)
{
	unsigned int i, len = 0;

	for (i = skb_shinfo(skb)->nr_frags - 1; (int)i >= 0; i--)
		len += skb_frag_size(&skb_shinfo(skb)->frags[i]);
	return len;
}

static inline unsigned int skb_pagelen(const struct sk_buff *skb)
{
	return skb_headlen(skb) + __skb_pagelen(skb);
}

void __skb_fill_page_desc(struct sk_buff *skb, int i,
			  struct page *page, int off, int size);

/**
 * skb_fill_page_desc - initialise a paged fragment in an skb
 * @skb: buffer containing fragment to be initialised
 * @i: paged fragment index to initialise
 * @page: the page to use for this fragment
 * @off: the offset to the data with @page
 * @size: the length of the data
 *
 * As per __skb_fill_page_desc() -- initialises the @i'th fragment of
 * @skb to point to @size bytes at offset @off within @page. In
 * addition updates @skb such that @i is the last fragment.
 *
 * Does not take any additional reference on the fragment.
 */
static inline void skb_fill_page_desc(struct sk_buff *skb, int i,
				      struct page *page, int off, int size)
{
	__skb_fill_page_desc(skb, i, page, off, size);
	skb_shinfo(skb)->nr_frags = i + 1;
}

static inline void skb_free_frag(void *addr)
{
	page_frag_free(addr);
}

void *__napi_alloc_frag_align(unsigned int fragsz, unsigned int align_mask);

static inline void *napi_alloc_frag(unsigned int fragsz)
{
	return __napi_alloc_frag_align(fragsz, ~0u);
}

static inline void *napi_alloc_frag_align(unsigned int fragsz,
					  unsigned int align)
{
	WARN_ON_ONCE(!is_power_of_2(align));
	return __napi_alloc_frag_align(fragsz, -align);
}

/**
 * skb_frag_off() - Returns the offset of a skb fragment
 * @frag: the paged fragment
 */
static inline unsigned int skb_frag_off(const skb_frag_t *frag)
{
	return frag->bv_offset;
}

/**
 * skb_frag_off_add() - Increments the offset of a skb fragment by @delta
 * @frag: skb fragment
 * @delta: value to add
 */
static inline void skb_frag_off_add(skb_frag_t *frag, int delta)
{
	frag->bv_offset += delta;
}

/**
 * skb_frag_off_set() - Sets the offset of a skb fragment
 * @frag: skb fragment
 * @offset: offset of fragment
 */
static inline void skb_frag_off_set(skb_frag_t *frag, unsigned int offset)
{
	frag->bv_offset = offset;
}

/**
 * skb_frag_off_copy() - Sets the offset of a skb fragment from another fragment
 * @fragto: skb fragment where offset is set
 * @fragfrom: skb fragment offset is copied from
 */
static inline void skb_frag_off_copy(skb_frag_t *fragto,
				     const skb_frag_t *fragfrom)
{
	fragto->bv_offset = fragfrom->bv_offset;
}

/**
 * skb_frag_page - retrieve the page referred to by a paged fragment
 * @frag: the paged fragment
 *
 * Returns the &struct page associated with @frag.
 */
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->bv_page;
}

/**
 * __skb_frag_ref - take an addition reference on a paged fragment.
 * @frag: the paged fragment
 *
 * Takes an additional reference on the paged fragment @frag.
 */
static inline void __skb_frag_ref(skb_frag_t *frag)
{
	get_page(skb_frag_page(frag));
}

/**
 * skb_frag_ref - take an addition reference on a paged fragment of an skb.
 * @skb: the buffer
 * @f: the fragment offset.
 *
 * Takes an additional reference on the @f'th paged fragment of @skb.
 */
static inline void skb_frag_ref(struct sk_buff *skb, int f)
{
	__skb_frag_ref(&skb_shinfo(skb)->frags[f]);
}

/**
 * __skb_frag_unref - release a reference on a paged fragment.
 * @frag: the paged fragment
 * @recycle: recycle the page if allocated via page_pool
 *
 * Releases a reference on the paged fragment @frag
 * or recycles the page via the page_pool API.
 */
static inline void __skb_frag_unref(skb_frag_t *frag, bool recycle)
{
	struct page *page = skb_frag_page(frag);

#ifdef CONFIG_PAGE_POOL
	if (recycle && page_pool_return_skb_page(page))
		return;
#endif
	put_page(page);
}

/**
 * skb_frag_unref - release a reference on a paged fragment of an skb.
 * @skb: the buffer
 * @f: the fragment offset
 *
 * Releases a reference on the @f'th paged fragment of @skb.
 */
static inline void skb_frag_unref(struct sk_buff *skb, int f)
{
	__skb_frag_unref(&skb_shinfo(skb)->frags[f], skb->pp_recycle);
}

/**
 * skb_frag_address - gets the address of the data contained in a paged fragment
 * @frag: the paged fragment buffer
 *
 * Returns the address of the data within @frag. The page must already
 * be mapped.
 */
static inline void *skb_frag_address(const skb_frag_t *frag)
{
	return page_address(skb_frag_page(frag)) + skb_frag_off(frag);
}

/**
 * skb_frag_address_safe - gets the address of the data contained in a paged fragment
 * @frag: the paged fragment buffer
 *
 * Returns the address of the data within @frag. Checks that the page
 * is mapped and returns %NULL otherwise.
 */
static inline void *skb_frag_address_safe(const skb_frag_t *frag)
{
	void *ptr = page_address(skb_frag_page(frag));
	if (unlikely(!ptr))
		return NULL;

	return ptr + skb_frag_off(frag);
}

/**
 * skb_frag_page_copy() - sets the page in a fragment from another fragment
 * @fragto: skb fragment where page is set
 * @fragfrom: skb fragment page is copied from
 */
static inline void skb_frag_page_copy(skb_frag_t *fragto,
				      const skb_frag_t *fragfrom)
{
	fragto->bv_page = fragfrom->bv_page;
}

/**
 * __skb_frag_set_page - sets the page contained in a paged fragment
 * @frag: the paged fragment
 * @page: the page to set
 *
 * Sets the fragment @frag to contain @page.
 */
static inline void __skb_frag_set_page(skb_frag_t *frag, struct page *page)
{
	frag->bv_page = page;
}

/**
 * skb_frag_set_page - sets the page contained in a paged fragment of an skb
 * @skb: the buffer
 * @f: the fragment offset
 * @page: the page to set
 *
 * Sets the @f'th fragment of @skb to contain @page.
 */
static inline void skb_frag_set_page(struct sk_buff *skb, int f,
				     struct page *page)
{
	__skb_frag_set_page(&skb_shinfo(skb)->frags[f], page);
}

bool skb_page_frag_refill(unsigned int sz, struct page_frag *pfrag, gfp_t prio);

/**
 * skb_frag_dma_map - maps a paged fragment via the DMA API
 * @dev: the device to map the fragment to
 * @frag: the paged fragment to map
 * @offset: the offset within the fragment (starting at the
 *          fragment's own offset)
 * @size: the number of bytes to map
 * @dir: the direction of the mapping (``PCI_DMA_*``)
 *
 * Maps the page associated with @frag to @device.
 */
#define skb_frag_dma_map(dev, frag, offset, size, dir) \
	dma_map_page(dev, skb_frag_page(frag), skb_frag_off(frag) + (offset), size, dir)

static inline bool skb_can_coalesce(struct sk_buff *skb, int i,
				    const struct page *page, int off)
{
	if (skb_zcopy(skb))
		return false;
	if (i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i - 1];

		return page == skb_frag_page(frag) &&
		       off == skb_frag_off(frag) + skb_frag_size(frag);
	}
	return false;
}

/**
 * __dev_alloc_pages - allocate page for network Rx
 * @gfp_mask: allocation priority. Set __GFP_NOMEMALLOC if not for network Rx
 * @order: size of the allocation
 *
 * Allocate a new page.
 *
 * %NULL is returned if there is no free memory.
*/
static inline struct page *__dev_alloc_pages(gfp_t gfp_mask,
					     unsigned int order)
{
	/* This piece of code contains several assumptions.
	 * 1.  This is for device Rx, therefor a cold page is preferred.
	 * 2.  The expectation is the user wants a compound page.
	 * 3.  If requesting a order 0 page it will not be compound
	 *     due to the check to see if order has a value in prep_new_page
	 * 4.  __GFP_MEMALLOC is ignored if __GFP_NOMEMALLOC is set due to
	 *     code in gfp_to_alloc_flags that should be enforcing this.
	 */
	gfp_mask |= __GFP_COMP | __GFP_MEMALLOC;

	return alloc_pages_node(NUMA_NO_NODE, gfp_mask, order);
}

static inline struct page *dev_alloc_pages(unsigned int order)
{
	return __dev_alloc_pages(GFP_ATOMIC | __GFP_NOWARN, order);
}

/**
 * __dev_alloc_page - allocate a page for network Rx
 * @gfp_mask: allocation priority. Set __GFP_NOMEMALLOC if not for network Rx
 *
 * Allocate a new page.
 *
 * %NULL is returned if there is no free memory.
 */
static inline struct page *__dev_alloc_page(gfp_t gfp_mask)
{
	return __dev_alloc_pages(gfp_mask, 0);
}

static inline struct page *dev_alloc_page(void)
{
	return dev_alloc_pages(0);
}

#endif	/* _LINUX_SKBUFF_API_FRAG_H */
