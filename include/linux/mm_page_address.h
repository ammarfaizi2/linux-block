/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_PAGE_ADDRESS
#define _LINUX_MM_PAGE_ADDRESS

/*
 * CONFIG_SPARSEMEM's definitions have a couple of layering violations,
 * such as the reliance on __pfn_to_section() or page_to_section(),
 * which are defined in a high-level header (linux/mmzone_api.h):
 */
#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
# include <linux/mmzone_api.h>
#endif

#include <linux/mm_types.h>

#include <asm/page.h>
#include <asm/page_types.h>

#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#else
#define nth_page(page,n) ((page) + (n))
#endif

/*
 * The array of struct pages for flatmem.
 * It must be declared for SPARSEMEM as well because there are configurations
 * that rely on that.
 */
extern struct page *mem_map;

/*
 * Architectures that support memory tagging (assigning tags to memory regions,
 * embedding these tags into addresses that point to these memory regions, and
 * checking that the memory and the pointer tags match on memory accesses)
 * redefine this macro to strip tags from pointers.
 * It's defined as noop for architectures that don't support memory tagging.
 */
#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

#ifndef page_to_virt
#define page_to_virt(x)	__va(PFN_PHYS(page_to_pfn(x)))
#endif

#define lowmem_page_address(page) page_to_virt(page)

#if defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL)
#define HASHED_PAGE_VIRTUAL
#endif

#if defined(WANT_PAGE_VIRTUAL)
static inline void *page_address(const struct page *page)
{
	return page->virtual;
}
static inline void set_page_address(struct page *page, void *address)
{
	page->virtual = address;
}
#define page_address_init()  do { } while(0)
#endif

#if defined(HASHED_PAGE_VIRTUAL)
void *page_address(const struct page *page);
void set_page_address(struct page *page, void *virtual);
void page_address_init(void);
#endif

#if !defined(HASHED_PAGE_VIRTUAL) && !defined(WANT_PAGE_VIRTUAL)
#define page_address(page) lowmem_page_address(page)
#define set_page_address(page, address)  do { } while(0)
#define page_address_init()  do { } while(0)
#endif

/**
 * folio_page - Return a page from a folio.
 * @folio: The folio.
 * @n: The page number to return.
 *
 * @n is relative to the start of the folio.  This function does not
 * check that the page number lies within @folio; the caller is presumed
 * to have a reference to the page.
 */
#define folio_page(folio, n)	nth_page(&(folio)->page, n)

#define folio_address(folio) page_address(&(folio)->page)

/**
 * folio_nr_pages - The number of pages in the folio.
 * @folio: The folio.
 *
 * Return: A positive power of two.
 */
static inline long folio_nr_pages(struct folio *folio)
{
	return compound_nr(&folio->page);
}

/**
 * folio_next - Move to the next physical folio.
 * @folio: The folio we're currently operating on.
 *
 * If you have physically contiguous memory which may span more than
 * one folio (eg a &struct bio_vec), use this function to move from one
 * folio to the next.  Do not use it if the memory is only virtually
 * contiguous as the folios are almost certainly not adjacent to each
 * other.  This is the folio equivalent to writing ``page++``.
 *
 * Context: We assume that the folios are refcounted and/or locked at a
 * higher level and do not adjust the reference counts.
 * Return: The next struct folio.
 */
static inline struct folio *folio_next(struct folio *folio)
{
	return (struct folio *)folio_page(folio, folio_nr_pages(folio));
}

/**
 * folio_shift - The size of the memory described by this folio.
 * @folio: The folio.
 *
 * A folio represents a number of bytes which is a power-of-two in size.
 * This function tells you which power-of-two the folio is.  See also
 * folio_size() and folio_order().
 *
 * Context: The caller should have a reference on the folio to prevent
 * it from being split.  It is not necessary for the folio to be locked.
 * Return: The base-2 logarithm of the size of this folio.
 */
static inline unsigned int folio_shift(struct folio *folio)
{
	return PAGE_SHIFT + folio_order(folio);
}

/**
 * folio_size - The number of bytes in a folio.
 * @folio: The folio.
 *
 * Context: The caller should have a reference on the folio to prevent
 * it from being split.  It is not necessary for the folio to be locked.
 * Return: The number of bytes in this folio.
 */
static inline size_t folio_size(struct folio *folio)
{
	return PAGE_SIZE << folio_order(folio);
}

/* Support for virtually mapped pages */
struct page *vmalloc_to_page(const void *addr);
unsigned long vmalloc_to_pfn(const void *addr);

/*
 * Determine if an address is within the vmalloc range
 *
 * On nommu, vmalloc/vfree wrap through kmalloc/kfree directly, so there
 * is no special casing required.
 */

#ifndef is_ioremap_addr
#define is_ioremap_addr(x) is_vmalloc_addr(x)
#endif

#ifdef CONFIG_MMU
extern bool is_vmalloc_addr(const void *x);
extern int is_vmalloc_or_module_addr(const void *x);
#else
static inline bool is_vmalloc_addr(const void *x)
{
	return false;
}
static inline int is_vmalloc_or_module_addr(const void *x)
{
	return 0;
}
#endif

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define offset_in_thp(page, p)	((unsigned long)(p) & (thp_size(page) - 1))
#define offset_in_folio(folio, p) ((unsigned long)(p) & (folio_size(folio) - 1))

#endif /* _LINUX_MM_PAGE_ADDRESS */
