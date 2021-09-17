#ifndef _ASM_PGTABLE_TYPES_H
#define _ASM_PGTABLE_TYPES_H

#define PGD_T_LOG2	(__builtin_ffs(sizeof(pgd_t)) - 1)
#define PMD_T_LOG2	(__builtin_ffs(sizeof(pmd_t)) - 1)
#define PTE_T_LOG2	(__builtin_ffs(sizeof(pte_t)) - 1)

#ifdef CONFIG_32BIT
#include <asm/pgtable_32_types.h>
#endif
#ifdef CONFIG_64BIT
#include <asm/pgtable_64_types.h>
#endif

#define PAGE_SHARED	vm_get_page_prot(VM_READ|VM_WRITE|VM_SHARED)

#define PAGE_KERNEL	__pgprot(_PAGE_PRESENT | __READABLE | __WRITEABLE | \
				 _PAGE_GLOBAL | _page_cachable_default)
#define PAGE_KERNEL_NC	__pgprot(_PAGE_PRESENT | __READABLE | __WRITEABLE | \
				 _PAGE_GLOBAL | _CACHE_CACHABLE_NONCOHERENT)
#define PAGE_KERNEL_UNCACHED __pgprot(_PAGE_PRESENT | __READABLE | \
			__WRITEABLE | _PAGE_GLOBAL | _CACHE_UNCACHED)

/*
 * If _PAGE_NO_EXEC is not defined, we can't do page protection for
 * execute, and consider it to be the same as read. Also, write
 * permissions imply read permissions. This is the closest we can get
 * by reasonable means..
 */

/*
 * Dummy values to fill the table in mmap.c
 * The real values will be generated at runtime
 */
#define __P000 __pgprot(0)
#define __P001 __pgprot(0)
#define __P010 __pgprot(0)
#define __P011 __pgprot(0)
#define __P100 __pgprot(0)
#define __P101 __pgprot(0)
#define __P110 __pgprot(0)
#define __P111 __pgprot(0)

#define __S000 __pgprot(0)
#define __S001 __pgprot(0)
#define __S010 __pgprot(0)
#define __S011 __pgprot(0)
#define __S100 __pgprot(0)
#define __S101 __pgprot(0)
#define __S110 __pgprot(0)
#define __S111 __pgprot(0)

extern unsigned long _page_cachable_default;
extern void __update_cache(unsigned long address, pte_t pte);

#endif /* _ASM_PGTABLE_TYPES_H */
