/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/page.h
 *
 * Copyright (C) 1995-2003 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_PAGE_H
#define __ASM_PAGE_H

#include <asm/page-def.h>

/*
 * VMALLOC range.
 *
 * VMALLOC_START: beginning of the kernel vmalloc space
 * VMALLOC_END: extends to the available space below vmemmap, PCI I/O space
 *	and fixed mappings
 */
#define VMALLOC_START		(MODULES_END)
#define VMALLOC_END		(VMEMMAP_START - SZ_256M)

#define vmemmap			((struct page *)VMEMMAP_START - (memstart_addr >> PAGE_SHIFT))

/*
 * Hugetlb definitions.
 */
#define HUGE_MAX_HSTATE		4
#define HPAGE_SHIFT		PMD_SHIFT
#define HPAGE_SIZE		(_AC(1, UL) << HPAGE_SHIFT)
#define HPAGE_MASK		(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)

#ifndef __ASSEMBLY__

#include <linux/personality.h> /* for READ_IMPLIES_EXEC */
#include <linux/types.h> /* for gfp_t */
#include <asm/pgtable_types.h>

struct page;
struct vm_area_struct;

extern void copy_page(void *to, const void *from);
extern void clear_page(void *to);

void copy_user_highpage(struct page *to, struct page *from,
			unsigned long vaddr, struct vm_area_struct *vma);
#define __HAVE_ARCH_COPY_USER_HIGHPAGE

void copy_highpage(struct page *to, struct page *from);
#define __HAVE_ARCH_COPY_HIGHPAGE

struct page *alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
						unsigned long vaddr);
#define __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE_MOVABLE

void tag_clear_highpage(struct page *to);
#define __HAVE_ARCH_TAG_CLEAR_HIGHPAGE

#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

int pfn_is_map_memory(unsigned long pfn);

#include <asm/memory.h>

#endif /* !__ASSEMBLY__ */

#include <asm-generic/getorder.h>

#endif
