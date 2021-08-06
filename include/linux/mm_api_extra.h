/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_API_EXTRA_H
#define _LINUX_MM_API_EXTRA_H

#include <linux/mm_api.h>

#include <linux/sched/coredump.h>
#include <linux/memremap.h>
#include <linux/pgtable_api.h>

#ifdef CONFIG_MMU
/*
 * Do pte_mkwrite, but only if the vma says VM_WRITE.  We do this when
 * servicing faults for write access.  In the normal case, do always want
 * pte_mkwrite.  But get_user_pages can cause write faults for mappings
 * that do not have writing enabled, when used by access_process_vm.
 */
static inline pte_t maybe_mkwrite(pte_t pte, struct vm_area_struct *vma)
{
	if (likely(vma->vm_flags & VM_WRITE))
		pte = pte_mkwrite(pte);
	return pte;
}

vm_fault_t do_set_pmd(struct vm_fault *vmf, struct page *page);
void do_set_pte(struct vm_fault *vmf, struct page *page, unsigned long addr);

vm_fault_t finish_fault(struct vm_fault *vmf);
vm_fault_t finish_mkwrite_fault(struct vm_fault *vmf);
#endif

/* MIGRATE_CMA and ZONE_MOVABLE do not allow pin pages */
#ifdef CONFIG_MIGRATION
static inline bool is_pinnable_page(struct page *page)
{
	return !(is_zone_movable_page(page) || is_migrate_cma_page(page)) ||
		is_zero_pfn(page_to_pfn(page));
}
#else
static inline bool is_pinnable_page(struct page *page)
{
	return true;
}
#endif

#if defined(__PAGETABLE_PUD_FOLDED) || !defined(CONFIG_MMU)
static inline int __pud_alloc(struct mm_struct *mm, p4d_t *p4d,
						unsigned long address)
{
	return 0;
}
static inline void mm_inc_nr_puds(struct mm_struct *mm) {}
static inline void mm_dec_nr_puds(struct mm_struct *mm) {}

#else
int __pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address);

static inline void mm_inc_nr_puds(struct mm_struct *mm)
{
	if (mm_pud_folded(mm))
		return;
	atomic_long_add(PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
}

static inline void mm_dec_nr_puds(struct mm_struct *mm)
{
	if (mm_pud_folded(mm))
		return;
	atomic_long_sub(PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
}
#endif

#if defined(__PAGETABLE_PMD_FOLDED) || !defined(CONFIG_MMU)
static inline int __pmd_alloc(struct mm_struct *mm, pud_t *pud,
						unsigned long address)
{
	return 0;
}

static inline void mm_inc_nr_pmds(struct mm_struct *mm) {}
static inline void mm_dec_nr_pmds(struct mm_struct *mm) {}

#else
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address);

static inline void mm_inc_nr_pmds(struct mm_struct *mm)
{
	if (mm_pmd_folded(mm))
		return;
	atomic_long_add(PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
}

static inline void mm_dec_nr_pmds(struct mm_struct *mm)
{
	if (mm_pmd_folded(mm))
		return;
	atomic_long_sub(PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
}
#endif

#if defined(CONFIG_MMU)

static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
		unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && __p4d_alloc(mm, pgd, address)) ?
		NULL : p4d_offset(pgd, address);
}

static inline pud_t *pud_alloc(struct mm_struct *mm, p4d_t *p4d,
		unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) && __pud_alloc(mm, p4d, address)) ?
		NULL : pud_offset(p4d, address);
}

static inline pmd_t *pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __pmd_alloc(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}
#endif /* CONFIG_MMU */

#ifndef io_remap_pfn_range
static inline int io_remap_pfn_range(struct vm_area_struct *vma,
				     unsigned long addr, unsigned long pfn,
				     unsigned long size, pgprot_t prot)
{
	return remap_pfn_range(vma, addr, pfn, size, pgprot_decrypted(prot));
}
#endif

#ifdef CONFIG_DEV_PAGEMAP_OPS
void free_devmap_managed_page(struct page *page);
DECLARE_STATIC_KEY_FALSE(devmap_managed_key);

static inline bool page_is_devmap_managed(struct page *page)
{
	if (!static_branch_unlikely(&devmap_managed_key))
		return false;
	if (!is_zone_device_page(page))
		return false;
	switch (page->pgmap->type) {
	case MEMORY_DEVICE_PRIVATE:
	case MEMORY_DEVICE_FS_DAX:
		return true;
	default:
		break;
	}
	return false;
}

void put_devmap_managed_page(struct page *page);

#else /* CONFIG_DEV_PAGEMAP_OPS */
static inline bool page_is_devmap_managed(struct page *page)
{
	return false;
}

static inline void put_devmap_managed_page(struct page *page)
{
}
#endif /* CONFIG_DEV_PAGEMAP_OPS */

static inline bool is_device_private_page(const struct page *page)
{
	return IS_ENABLED(CONFIG_DEV_PAGEMAP_OPS) &&
		IS_ENABLED(CONFIG_DEVICE_PRIVATE) &&
		is_zone_device_page(page) &&
		page->pgmap->type == MEMORY_DEVICE_PRIVATE;
}

static inline bool is_pci_p2pdma_page(const struct page *page)
{
	return IS_ENABLED(CONFIG_DEV_PAGEMAP_OPS) &&
		IS_ENABLED(CONFIG_PCI_P2PDMA) &&
		is_zone_device_page(page) &&
		page->pgmap->type == MEMORY_DEVICE_PCI_P2PDMA;
}

/*
 * This should most likely only be called during fork() to see whether we
 * should break the cow immediately for a page on the src mm.
 */
static inline bool page_needs_cow_for_dma(struct vm_area_struct *vma,
					  struct page *page)
{
	if (!is_cow_mapping(vma->vm_flags))
		return false;

	if (!test_bit(MMF_HAS_PINNED, &vma->vm_mm->flags))
		return false;

	return page_maybe_dma_pinned(page);
}

#endif /* _LINUX_MM_API_EXTRA_H */
