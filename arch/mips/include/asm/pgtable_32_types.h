#ifndef _ASM_PGTABLE_32_TYPES_H
#define _ASM_PGTABLE_32_TYPES_H

#include <asm/page_types.h>
#include <asm/fixmap.h>

#include <asm-generic/pgtable-nopmd.h>

/*
 * Basically we have the same two-level (which is the logical three level
 * Linux page table layout folded) page tables as the i386.  Some day
 * when we have proper page coloring support we can have a 1% quicker
 * tlb refill handling mechanism, but for now it is a bit slower but
 * works even with the cache aliasing problem the R4k and above have.
 */

/* PGDIR_SHIFT determines what a third-level page table entry can map */
#if defined(CONFIG_MIPS_HUGE_TLB_SUPPORT) && !defined(CONFIG_PHYS_ADDR_T_64BIT)
# define PGDIR_SHIFT	(2 * PAGE_SHIFT + PTE_ORDER - PTE_T_LOG2 - 1)
#else
# define PGDIR_SHIFT	(2 * PAGE_SHIFT + PTE_ORDER - PTE_T_LOG2)
#endif

#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))

/*
 * Entries per page directory level: we use two-level, so
 * we don't really have any PUD/PMD directory physically.
 */
#if defined(CONFIG_MIPS_HUGE_TLB_SUPPORT) && !defined(CONFIG_PHYS_ADDR_T_64BIT)
# define __PGD_ORDER	(32 - 3 * PAGE_SHIFT + PGD_T_LOG2 + PTE_T_LOG2 + 1)
#else
# define __PGD_ORDER	(32 - 3 * PAGE_SHIFT + PGD_T_LOG2 + PTE_T_LOG2)
#endif

#define PGD_ORDER	(__PGD_ORDER >= 0 ? __PGD_ORDER : 0)
#define PUD_ORDER	aieeee_attempt_to_allocate_pud
#define PMD_ORDER	aieeee_attempt_to_allocate_pmd
#define PTE_ORDER	0

#define PTRS_PER_PGD	(USER_PTRS_PER_PGD * 2)
#if defined(CONFIG_MIPS_HUGE_TLB_SUPPORT) && !defined(CONFIG_PHYS_ADDR_T_64BIT)
# define PTRS_PER_PTE	((PAGE_SIZE << PTE_ORDER) / sizeof(pte_t) / 2)
#else
# define PTRS_PER_PTE	((PAGE_SIZE << PTE_ORDER) / sizeof(pte_t))
#endif

#define USER_PTRS_PER_PGD	(0x80000000UL/PGDIR_SIZE)

#define VMALLOC_START	  MAP_BASE

#define PKMAP_END	((FIXADDR_START) & ~((LAST_PKMAP << PAGE_SHIFT)-1))
#define PKMAP_BASE	(PKMAP_END - PAGE_SIZE * LAST_PKMAP)

#ifdef CONFIG_HIGHMEM
# define VMALLOC_END	(PKMAP_BASE-2*PAGE_SIZE)
#else
# define VMALLOC_END	(FIXADDR_START-2*PAGE_SIZE)
#endif

#endif /* _ASM_PGTABLE_32_TYPES_H */
