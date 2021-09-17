/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1994, 95, 96, 97, 98, 99, 2000, 2003 Ralf Baechle
 * Copyright (C) 1999, 2000, 2001 Silicon Graphics, Inc.
 */
#ifndef _ASM_PGTABLE_64_H
#define _ASM_PGTABLE_64_H

#include <asm/pgtable_64_types.h>

#include <linux/compiler.h>
#include <linux/linkage.h>

#include <asm/addrspace.h>
#include <asm/page.h>
#include <asm/cachectl.h>
#include <asm/fixmap.h>

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %016lx.\n", __FILE__, __LINE__, pte_val(e))
#ifndef __PAGETABLE_PMD_FOLDED
#define pmd_ERROR(e) \
	printk("%s:%d: bad pmd %016lx.\n", __FILE__, __LINE__, pmd_val(e))
#endif
#ifndef __PAGETABLE_PUD_FOLDED
#define pud_ERROR(e) \
	printk("%s:%d: bad pud %016lx.\n", __FILE__, __LINE__, pud_val(e))
#endif
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %016lx.\n", __FILE__, __LINE__, pgd_val(e))

extern pte_t invalid_pte_table[PTRS_PER_PTE];

#ifndef __PAGETABLE_PUD_FOLDED

extern pud_t invalid_pud_table[PTRS_PER_PUD];

/*
 * Empty pgd entries point to the invalid_pud_table.
 */
static inline int p4d_none(p4d_t p4d)
{
	return p4d_val(p4d) == (unsigned long)invalid_pud_table;
}

static inline int p4d_bad(p4d_t p4d)
{
	if (unlikely(p4d_val(p4d) & ~PAGE_MASK))
		return 1;

	return 0;
}

static inline int p4d_present(p4d_t p4d)
{
	return p4d_val(p4d) != (unsigned long)invalid_pud_table;
}

static inline void p4d_clear(p4d_t *p4dp)
{
	p4d_val(*p4dp) = (unsigned long)invalid_pud_table;
}

static inline pud_t *p4d_pgtable(p4d_t p4d)
{
	return (pud_t *)p4d_val(p4d);
}

#define p4d_phys(p4d)		virt_to_phys((void *)p4d_val(p4d))
#define p4d_page(p4d)		(pfn_to_page(p4d_phys(p4d) >> PAGE_SHIFT))

#define p4d_index(address)	(((address) >> P4D_SHIFT) & (PTRS_PER_P4D - 1))

static inline void set_p4d(p4d_t *p4d, p4d_t p4dval)
{
	*p4d = p4dval;
}

#endif

#ifndef __PAGETABLE_PMD_FOLDED
extern pmd_t invalid_pmd_table[PTRS_PER_PMD];
#endif

/*
 * Empty pgd/pmd entries point to the invalid_pte_table.
 */
static inline int pmd_none(pmd_t pmd)
{
	return pmd_val(pmd) == (unsigned long) invalid_pte_table;
}

static inline int pmd_bad(pmd_t pmd)
{
#ifdef CONFIG_MIPS_HUGE_TLB_SUPPORT
	/* pmd_huge(pmd) but inline */
	if (unlikely(pmd_val(pmd) & _PAGE_HUGE))
		return 0;
#endif

	if (unlikely(pmd_val(pmd) & ~PAGE_MASK))
		return 1;

	return 0;
}

static inline int pmd_present(pmd_t pmd)
{
#ifdef CONFIG_MIPS_HUGE_TLB_SUPPORT
	if (unlikely(pmd_val(pmd) & _PAGE_HUGE))
		return pmd_val(pmd) & _PAGE_PRESENT;
#endif

	return pmd_val(pmd) != (unsigned long) invalid_pte_table;
}

static inline void pmd_clear(pmd_t *pmdp)
{
	pmd_val(*pmdp) = ((unsigned long) invalid_pte_table);
}
#ifndef __PAGETABLE_PMD_FOLDED

/*
 * Empty pud entries point to the invalid_pmd_table.
 */
static inline int pud_none(pud_t pud)
{
	return pud_val(pud) == (unsigned long) invalid_pmd_table;
}

static inline int pud_bad(pud_t pud)
{
	return pud_val(pud) & ~PAGE_MASK;
}

static inline int pud_present(pud_t pud)
{
	return pud_val(pud) != (unsigned long) invalid_pmd_table;
}

static inline void pud_clear(pud_t *pudp)
{
	pud_val(*pudp) = ((unsigned long) invalid_pmd_table);
}
#endif

#define pte_page(x)		pfn_to_page(pte_pfn(x))

#ifdef CONFIG_CPU_VR41XX
#define pte_pfn(x)		((unsigned long)((x).pte >> (PAGE_SHIFT + 2)))
#define pfn_pte(pfn, prot)	__pte(((pfn) << (PAGE_SHIFT + 2)) | pgprot_val(prot))
#else
#define pte_pfn(x)		((unsigned long)((x).pte >> _PFN_SHIFT))
#define pfn_pte(pfn, prot)	__pte(((pfn) << _PFN_SHIFT) | pgprot_val(prot))
#define pfn_pmd(pfn, prot)	__pmd(((pfn) << _PFN_SHIFT) | pgprot_val(prot))
#endif

#ifndef __PAGETABLE_PMD_FOLDED
static inline pmd_t *pud_pgtable(pud_t pud)
{
	return (pmd_t *)pud_val(pud);
}
#define pud_phys(pud)		virt_to_phys((void *)pud_val(pud))
#define pud_page(pud)		(pfn_to_page(pud_phys(pud) >> PAGE_SHIFT))

#endif

/*
 * Initialize a new pgd / pmd table with invalid pointers.
 */
extern void pgd_init(unsigned long page);
extern void pud_init(unsigned long page, unsigned long pagetable);
extern void pmd_init(unsigned long page, unsigned long pagetable);

/*
 * Non-present pages:  high 40 bits are offset, next 8 bits type,
 * low 16 bits zero.
 */
static inline pte_t mk_swap_pte(unsigned long type, unsigned long offset)
{ pte_t pte; pte_val(pte) = (type << 16) | (offset << 24); return pte; }

#define __swp_type(x)		(((x).val >> 16) & 0xff)
#define __swp_offset(x)		((x).val >> 24)
#define __swp_entry(type, offset) ((swp_entry_t) { pte_val(mk_swap_pte((type), (offset))) })
#define __pte_to_swp_entry(pte) ((swp_entry_t) { pte_val(pte) })
#define __swp_entry_to_pte(x)	((pte_t) { (x).val })

#endif /* _ASM_PGTABLE_64_H */
