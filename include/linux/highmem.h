/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HIGHMEM_H
#define _LINUX_HIGHMEM_H

#include <linux/gfp_api.h>
#include <linux/mmdebug.h>
#include <linux/mm_page_address.h>
#include <linux/mm_types.h>
#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/uaccess.h>

#ifdef CONFIG_HIGHMEM
# include <asm/highmem.h>
#endif

/* This memory layout mode's definitions are full of layering violations & require this header: */
#ifdef CONFIG_SPARSEMEM
#include <linux/mm_api.h>
#endif

#include "highmem-internal.h"

/**
 * kmap - Map a page for long term usage
 * @page:	Pointer to the page to be mapped
 *
 * Returns: The virtual address of the mapping
 *
 * Can only be invoked from preemptible task context because on 32bit
 * systems with CONFIG_HIGHMEM enabled this function might sleep.
 *
 * For systems with CONFIG_HIGHMEM=n and for pages in the low memory area
 * this returns the virtual address of the direct kernel mapping.
 *
 * The returned virtual address is globally visible and valid up to the
 * point where it is unmapped via kunmap(). The pointer can be handed to
 * other contexts.
 *
 * For highmem pages on 32bit systems this can be slow as the mapping space
 * is limited and protected by a global lock. In case that there is no
 * mapping slot available the function blocks until a slot is released via
 * kunmap().
 */
void *kmap(struct page *page);

/**
 * kunmap - Unmap the virtual address mapped by kmap()
 * @addr:	Virtual address to be unmapped
 *
 * Counterpart to kmap(). A NOOP for CONFIG_HIGHMEM=n and for mappings of
 * pages in the low memory area.
 */
void kunmap(struct page *page);

/**
 * kmap_to_page - Get the page for a kmap'ed address
 * @addr:	The address to look up
 *
 * Returns: The page which is mapped to @addr.
 */
static inline struct page *kmap_to_page(void *addr);

/**
 * kmap_flush_unused - Flush all unused kmap mappings in order to
 *		       remove stray mappings
 */
static inline void kmap_flush_unused(void);

/**
 * kmap_local_page - Map a page for temporary usage
 * @page:	Pointer to the page to be mapped
 *
 * Returns: The virtual address of the mapping
 *
 * Can be invoked from any context.
 *
 * Requires careful handling when nesting multiple mappings because the map
 * management is stack based. The unmap has to be in the reverse order of
 * the map operation:
 *
 * addr1 = kmap_local_page(page1);
 * addr2 = kmap_local_page(page2);
 * ...
 * kunmap_local(addr2);
 * kunmap_local(addr1);
 *
 * Unmapping addr1 before addr2 is invalid and causes malfunction.
 *
 * Contrary to kmap() mappings the mapping is only valid in the context of
 * the caller and cannot be handed to other contexts.
 *
 * On CONFIG_HIGHMEM=n kernels and for low memory pages this returns the
 * virtual address of the direct mapping. Only real highmem pages are
 * temporarily mapped.
 *
 * While it is significantly faster than kmap() for the higmem case it
 * comes with restrictions about the pointer validity. Only use when really
 * necessary.
 *
 * On HIGHMEM enabled systems mapping a highmem page has the side effect of
 * disabling migration in order to keep the virtual address stable across
 * preemption. No caller of kmap_local_page() can rely on this side effect.
 */
static inline void *kmap_local_page(struct page *page);

/**
 * kmap_local_folio - Map a page in this folio for temporary usage
 * @folio: The folio containing the page.
 * @offset: The byte offset within the folio which identifies the page.
 *
 * Requires careful handling when nesting multiple mappings because the map
 * management is stack based. The unmap has to be in the reverse order of
 * the map operation::
 *
 *   addr1 = kmap_local_folio(folio1, offset1);
 *   addr2 = kmap_local_folio(folio2, offset2);
 *   ...
 *   kunmap_local(addr2);
 *   kunmap_local(addr1);
 *
 * Unmapping addr1 before addr2 is invalid and causes malfunction.
 *
 * Contrary to kmap() mappings the mapping is only valid in the context of
 * the caller and cannot be handed to other contexts.
 *
 * On CONFIG_HIGHMEM=n kernels and for low memory pages this returns the
 * virtual address of the direct mapping. Only real highmem pages are
 * temporarily mapped.
 *
 * While it is significantly faster than kmap() for the higmem case it
 * comes with restrictions about the pointer validity. Only use when really
 * necessary.
 *
 * On HIGHMEM enabled systems mapping a highmem page has the side effect of
 * disabling migration in order to keep the virtual address stable across
 * preemption. No caller of kmap_local_folio() can rely on this side effect.
 *
 * Context: Can be invoked from any context.
 * Return: The virtual address of @offset.
 */
static inline void *kmap_local_folio(struct folio *folio, size_t offset);

/**
 * kmap_atomic - Atomically map a page for temporary usage - Deprecated!
 * @page:	Pointer to the page to be mapped
 *
 * Returns: The virtual address of the mapping
 *
 * Effectively a wrapper around kmap_local_page() which disables pagefaults
 * and preemption.
 *
 * Do not use in new code. Use kmap_local_page() instead.
 */
void *kmap_atomic(struct page *page);

/**
 * kunmap_atomic - Unmap the virtual address mapped by kmap_atomic()
 * @addr:	Virtual address to be unmapped
 *
 * Counterpart to kmap_atomic().
 *
 * Effectively a wrapper around kunmap_local() which additionally undoes
 * the side effects of kmap_atomic(), i.e. reenabling pagefaults and
 * preemption.
 */

#endif /* _LINUX_HIGHMEM_H */
