#ifndef _ASM_PGTABLE_64_TYPES_H
#define _ASM_PGTABLE_64_TYPES_H

#include <asm/page_types.h>

#if CONFIG_PGTABLE_LEVELS == 2
#include <asm-generic/pgtable-nopmd.h>
#elif CONFIG_PGTABLE_LEVELS == 3
#include <asm-generic/pgtable-nopud.h>
#else
#include <asm-generic/pgtable-nop4d.h>
#endif

/*
 * Each address space has 2 4K pages as its page directory, giving 1024
 * (== PTRS_PER_PGD) 8 byte pointers to pmd tables. Each pmd table is a
 * single 4K page, giving 512 (== PTRS_PER_PMD) 8 byte pointers to page
 * tables. Each page table is also a single 4K page, giving 512 (==
 * PTRS_PER_PTE) 8 byte ptes. Each pud entry is initialized to point to
 * invalid_pmd_table, each pmd entry is initialized to point to
 * invalid_pte_table, each pte is initialized to 0.
 *
 * Kernel mappings: kernel mappings are held in the swapper_pg_table.
 * The layout is identical to userspace except it's indexed with the
 * fault address - VMALLOC_START.
 */


/* PGDIR_SHIFT determines what a third-level page table entry can map */
#ifdef __PAGETABLE_PMD_FOLDED
#define PGDIR_SHIFT	(PAGE_SHIFT + PAGE_SHIFT + PTE_ORDER - 3)
#else

/* PMD_SHIFT determines the size of the area a second-level page table can map */
#define PMD_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT + PTE_ORDER - 3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))

# ifdef __PAGETABLE_PUD_FOLDED
# define PGDIR_SHIFT	(PMD_SHIFT + (PAGE_SHIFT + PMD_ORDER - 3))
# endif
#endif

#ifndef __PAGETABLE_PUD_FOLDED
#define PUD_SHIFT	(PMD_SHIFT + (PAGE_SHIFT + PMD_ORDER - 3))
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE-1))
#define PGDIR_SHIFT	(PUD_SHIFT + (PAGE_SHIFT + PUD_ORDER - 3))
#endif

#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))

/*
 * For 4kB page size we use a 3 level page tree and an 8kB pud, which
 * permits us mapping 40 bits of virtual address space.
 *
 * We used to implement 41 bits by having an order 1 pmd level but that seemed
 * rather pointless.
 *
 * For 8kB page size we use a 3 level page tree which permits a total of
 * 8TB of address space.  Alternatively a 33-bit / 8GB organization using
 * two levels would be easy to implement.
 *
 * For 16kB page size we use a 2 level page tree which permits a total of
 * 36 bits of virtual address space.  We could add a third level but it seems
 * like at the moment there's no need for this.
 *
 * For 64kB page size we use a 2 level page table tree for a total of 42 bits
 * of virtual address space.
 */
#ifdef CONFIG_PAGE_SIZE_4KB
# ifdef CONFIG_MIPS_VA_BITS_48
#  define PGD_ORDER		0
#  define PUD_ORDER		0
# else
#  define PGD_ORDER		1
#  define PUD_ORDER		aieeee_attempt_to_allocate_pud
# endif
#define PMD_ORDER		0
#define PTE_ORDER		0
#endif
#ifdef CONFIG_PAGE_SIZE_8KB
#define PGD_ORDER		0
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#define PMD_ORDER		0
#define PTE_ORDER		0
#endif
#ifdef CONFIG_PAGE_SIZE_16KB
#ifdef CONFIG_MIPS_VA_BITS_48
#define PGD_ORDER               1
#else
#define PGD_ORDER               0
#endif
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#define PMD_ORDER		0
#define PTE_ORDER		0
#endif
#ifdef CONFIG_PAGE_SIZE_32KB
#define PGD_ORDER		0
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#define PMD_ORDER		0
#define PTE_ORDER		0
#endif
#ifdef CONFIG_PAGE_SIZE_64KB
#define PGD_ORDER		0
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#ifdef CONFIG_MIPS_VA_BITS_48
#define PMD_ORDER		0
#else
#define PMD_ORDER		aieeee_attempt_to_allocate_pmd
#endif
#define PTE_ORDER		0
#endif

#define PTRS_PER_PGD	((PAGE_SIZE << PGD_ORDER) / sizeof(pgd_t))
#ifndef __PAGETABLE_PUD_FOLDED
#define PTRS_PER_PUD	((PAGE_SIZE << PUD_ORDER) / sizeof(pud_t))
#endif
#ifndef __PAGETABLE_PMD_FOLDED
#define PTRS_PER_PMD	((PAGE_SIZE << PMD_ORDER) / sizeof(pmd_t))
#endif
#define PTRS_PER_PTE	((PAGE_SIZE << PTE_ORDER) / sizeof(pte_t))

#define USER_PTRS_PER_PGD       ((TASK_SIZE64 / PGDIR_SIZE)?(TASK_SIZE64 / PGDIR_SIZE):1)

/*
 * TLB refill handlers also map the vmalloc area into xuseg.  Avoid
 * the first couple of pages so NULL pointer dereferences will still
 * reliably trap.
 */
#define VMALLOC_START		(MAP_BASE + (2 * PAGE_SIZE))
#define VMALLOC_END	\
	(MAP_BASE + \
	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, \
	     (1UL << cpu_vmbits)) - (1UL << 32))

#if defined(CONFIG_MODULES) && defined(KBUILD_64BIT_SYM32) && \
	VMALLOC_START != CKSSEG
/* Load modules into 32bit-compatible segment. */
#define MODULE_START	CKSSEG
#define MODULE_END	(FIXADDR_START-2*PAGE_SIZE)
#endif

#ifndef __PAGETABLE_PUD_FOLDED
/*
 * For 4-level pagetables we defines these ourselves, for 3-level the
 * definitions are below, for 2-level the
 * definitions are supplied by <asm-generic/pgtable-nopmd.h>.
 */
typedef struct { unsigned long pud; } pud_t;
#define pud_val(x)	((x).pud)
#define __pud(x)	((pud_t) { (x) })
#endif

#ifndef __PAGETABLE_PMD_FOLDED
/*
 * For 3-level pagetables we defines these ourselves, for 2-level the
 * definitions are supplied by <asm-generic/pgtable-nopmd.h>.
 */
typedef struct { unsigned long pmd; } pmd_t;
#define pmd_val(x)	((x).pmd)
#define __pmd(x)	((pmd_t) { (x) } )
#endif

#endif /* _ASM_PGTABLE_64_TYPES_H */
