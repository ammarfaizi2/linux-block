#ifndef _ASM_PAGE_TYPES_H
#define _ASM_PAGE_TYPES_H

#include <linux/const.h>

/*
 * PAGE_SHIFT determines the page size
 */
#ifdef CONFIG_PAGE_SIZE_4KB
#define PAGE_SHIFT	12
#endif
#ifdef CONFIG_PAGE_SIZE_8KB
#define PAGE_SHIFT	13
#endif
#ifdef CONFIG_PAGE_SIZE_16KB
#define PAGE_SHIFT	14
#endif
#ifdef CONFIG_PAGE_SIZE_32KB
#define PAGE_SHIFT	15
#endif
#ifdef CONFIG_PAGE_SIZE_64KB
#define PAGE_SHIFT	16
#endif
#define PAGE_SIZE	(_AC(1,UL) << PAGE_SHIFT)
#define PAGE_MASK	(~((1 << PAGE_SHIFT) - 1))

#ifdef CONFIG_MIPS_HUGE_TLB_SUPPORT
#define HPAGE_SHIFT	(PAGE_SHIFT + PAGE_SHIFT - 3)
#define HPAGE_SIZE	(_AC(1,UL) << HPAGE_SHIFT)
#define HPAGE_MASK	(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)
#else /* !CONFIG_MIPS_HUGE_TLB_SUPPORT */
#define HPAGE_SHIFT	({BUILD_BUG(); 0; })
#define HPAGE_SIZE	({BUILD_BUG(); 0; })
#define HPAGE_MASK	({BUILD_BUG(); 0; })
#define HUGETLB_PAGE_ORDER	({BUILD_BUG(); 0; })
#endif /* CONFIG_MIPS_HUGE_TLB_SUPPORT */

/*
 * These are used to make use of C type-checking..
 */
#ifdef CONFIG_PHYS_ADDR_T_64BIT
  #ifdef CONFIG_CPU_MIPS32
    typedef struct { unsigned long pte_low, pte_high; } pte_t;
    #define pte_val(x)	  ((x).pte_low | ((unsigned long long)(x).pte_high << 32))
    #define __pte(x)	  ({ pte_t __pte = {(x), ((unsigned long long)(x)) >> 32}; __pte; })
  #else
     typedef struct { unsigned long long pte; } pte_t;
     #define pte_val(x) ((x).pte)
     #define __pte(x)	((pte_t) { (x) } )
  #endif
#else
typedef struct { unsigned long pte; } pte_t;
#define pte_val(x)	((x).pte)
#define __pte(x)	((pte_t) { (x) } )
#endif
typedef struct page *pgtable_t;

/*
 * Right now we don't support 4-level pagetables, so all pud-related
 * definitions come from <asm-generic/pgtable-nopud.h>.
 */

/*
 * Finall the top of the hierarchy, the pgd
 */
typedef struct { unsigned long pgd; } pgd_t;
#define pgd_val(x)	((x).pgd)
#define __pgd(x)	((pgd_t) { (x) } )

/*
 * Manipulate page protection bits
 */
typedef struct { unsigned long pgprot; } pgprot_t;
#define pgprot_val(x)	((x).pgprot)
#define __pgprot(x)	((pgprot_t) { (x) } )
#define pte_pgprot(x)	__pgprot(pte_val(x) & ~_PFN_MASK)

#endif /* _ASM_PAGE_TYPES_H */
