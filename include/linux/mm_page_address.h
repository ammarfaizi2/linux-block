/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_PAGE_ADDRESS
#define _LINUX_MM_PAGE_ADDRESS

#include <linux/mm_types.h>

#include <asm/page.h>
#include <asm/page_types.h>

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

static inline void *folio_address(const struct folio *folio)
{
	return page_address(&folio->page);
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
