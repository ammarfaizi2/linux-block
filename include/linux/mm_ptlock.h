/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_PTLOCK_H
#define _LINUX_MM_PTLOCK_H

#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/pgtable.h>

#if USE_SPLIT_PTE_PTLOCKS
#if ALLOC_SPLIT_PTLOCKS
void __init ptlock_cache_init(void);
extern bool ptlock_alloc(struct page *page);
extern void ptlock_free(struct page *page);

static inline spinlock_t *ptlock_ptr(struct page *page)
{
	return page->ptl;
}
#else /* ALLOC_SPLIT_PTLOCKS */
static inline void ptlock_cache_init(void)
{
}

static inline bool ptlock_alloc(struct page *page)
{
	return true;
}

static inline void ptlock_free(struct page *page)
{
}

static inline spinlock_t *ptlock_ptr(struct page *page)
{
	return &page->ptl;
}
#endif /* ALLOC_SPLIT_PTLOCKS */

static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(pmd_page(*pmd));
}

static inline bool ptlock_init(struct page *page)
{
	/*
	 * prep_new_page() initialize page->private (and therefore page->ptl)
	 * with 0. Make sure nobody took it in use in between.
	 *
	 * It can happen if arch try to use slab for page table allocation:
	 * slab code uses page->slab_cache, which share storage with page->ptl.
	 */
	VM_BUG_ON_PAGE(*(unsigned long *)&page->ptl, page);
	if (!ptlock_alloc(page))
		return false;
	spin_lock_init(ptlock_ptr(page));
	return true;
}

#else	/* !USE_SPLIT_PTE_PTLOCKS */
/*
 * We use mm->page_table_lock to guard all pagetable pages of the mm.
 */
static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}
static inline void ptlock_cache_init(void) {}
static inline bool ptlock_init(struct page *page) { return true; }
static inline void ptlock_free(struct page *page) {}
#endif /* USE_SPLIT_PTE_PTLOCKS */

static inline void pgtable_init(void)
{
	ptlock_cache_init();
	pgtable_cache_init();
}

static inline bool pgtable_pte_page_ctor(struct page *page)
{
	if (!ptlock_init(page))
		return false;
	__SetPageTable(page);
	inc_lruvec_page_state(page, NR_PAGETABLE);
	return true;
}

static inline void pgtable_pte_page_dtor(struct page *page)
{
	ptlock_free(page);
	__ClearPageTable(page);
	dec_lruvec_page_state(page, NR_PAGETABLE);
}

#define pte_offset_map_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset_map(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

#define pte_unmap_unlock(pte, ptl)	do {		\
	spin_unlock(ptl);				\
	pte_unmap(pte);					\
} while (0)

#define pte_alloc(mm, pmd) (unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, pmd))

#define pte_alloc_map(mm, pmd, address)			\
	(pte_alloc(mm, pmd) ? NULL : pte_offset_map(pmd, address))

#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	(pte_alloc(mm, pmd) ?			\
		 NULL : pte_offset_map_lock(mm, pmd, address, ptlp))

#define pte_alloc_kernel(pmd, address)			\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd))? \
		NULL: pte_offset_kernel(pmd, address))

#if USE_SPLIT_PMD_PTLOCKS

static struct page *pmd_to_page(pmd_t *pmd)
{
	unsigned long mask = ~(PTRS_PER_PMD * sizeof(pmd_t) - 1);
	return virt_to_page((void *)((unsigned long) pmd & mask));
}

static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(pmd_to_page(pmd));
}

static inline bool pmd_ptlock_init(struct page *page)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	page->pmd_huge_pte = NULL;
#endif
	return ptlock_init(page);
}

static inline void pmd_ptlock_free(struct page *page)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	VM_BUG_ON_PAGE(page->pmd_huge_pte, page);
#endif
	ptlock_free(page);
}

#define pmd_huge_pte(mm, pmd) (pmd_to_page(pmd)->pmd_huge_pte)

#else

static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}

static inline bool pmd_ptlock_init(struct page *page) { return true; }
static inline void pmd_ptlock_free(struct page *page) {}

#define pmd_huge_pte(mm, pmd) ((mm)->pmd_huge_pte)

#endif

static inline spinlock_t *pmd_lock(struct mm_struct *mm, pmd_t *pmd)
{
	spinlock_t *ptl = pmd_lockptr(mm, pmd);
	spin_lock(ptl);
	return ptl;
}

static inline bool pgtable_pmd_page_ctor(struct page *page)
{
	if (!pmd_ptlock_init(page))
		return false;
	__SetPageTable(page);
	inc_lruvec_page_state(page, NR_PAGETABLE);
	return true;
}

static inline void pgtable_pmd_page_dtor(struct page *page)
{
	pmd_ptlock_free(page);
	__ClearPageTable(page);
	dec_lruvec_page_state(page, NR_PAGETABLE);
}

/*
 * No scalability reason to split PUD locks yet, but follow the same pattern
 * as the PMD locks to make it easier if we decide to.  The VM should not be
 * considered ready to switch to split PUD locks yet; there may be places
 * which need to be converted from page_table_lock.
 */
static inline spinlock_t *pud_lockptr(struct mm_struct *mm, pud_t *pud)
{
	return &mm->page_table_lock;
}

static inline spinlock_t *pud_lock(struct mm_struct *mm, pud_t *pud)
{
	spinlock_t *ptl = pud_lockptr(mm, pud);

	spin_lock(ptl);
	return ptl;
}

#endif /* _LINUX_MM_PTLOCK_H */
