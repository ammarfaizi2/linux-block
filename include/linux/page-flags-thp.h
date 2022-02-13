/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Macros for manipulating and testing page->flags
 */

#ifndef PAGE_FLAGS_THP_H
#define PAGE_FLAGS_THP_H

#include <linux/page-flags.h>
#include <linux/huge_mm.h>
#include <linux/mmzone.h>

#include "page-flags-helper-macros-define.h"

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/*
 * PageHuge() only returns true for hugetlbfs pages, but not for
 * normal or transparent huge pages.
 *
 * PageTransHuge() returns true for both transparent huge and
 * hugetlbfs pages, but not normal pages. PageTransHuge() can only be
 * called only in the core VM paths where hugetlbfs pages can't exist.
 */
static inline int PageTransHuge(struct page *page)
{
	VM_BUG_ON_PAGE(PageTail(page), page);
	return PageHead(page);
}

static inline bool folio_test_transhuge(struct folio *folio)
{
	return folio_test_head(folio);
}

/*
 * PageTransCompound returns true for both transparent huge pages
 * and hugetlbfs pages, so it should only be called when it's known
 * that hugetlbfs pages aren't involved.
 */
static inline int PageTransCompound(struct page *page)
{
	return PageCompound(page);
}

/*
 * PageTransTail returns true for both transparent huge pages
 * and hugetlbfs pages, so it should only be called when it's known
 * that hugetlbfs pages aren't involved.
 */
static inline int PageTransTail(struct page *page)
{
	return PageTail(page);
}

/*
 * PageDoubleMap indicates that the compound page is mapped with PTEs as well
 * as PMDs.
 *
 * This is required for optimization of rmap operations for THP: we can postpone
 * per small page mapcount accounting (and its overhead from atomic operations)
 * until the first PMD split.
 *
 * For the page PageDoubleMap means ->_mapcount in all sub-pages is offset up
 * by one. This reference will go away with last compound_mapcount.
 *
 * See also __split_huge_pmd_locked() and page_remove_anon_compound_rmap().
 */
PAGEFLAG(DoubleMap, double_map, PF_SECOND)
	TESTSCFLAG(DoubleMap, double_map, PF_SECOND)
#else
TESTPAGEFLAG_FALSE(TransHuge, transhuge)
TESTPAGEFLAG_FALSE(TransCompound, transcompound)
TESTPAGEFLAG_FALSE(TransCompoundMap, transcompoundmap)
TESTPAGEFLAG_FALSE(TransTail, transtail)
PAGEFLAG_FALSE(DoubleMap, double_map)
	TESTSCFLAG_FALSE(DoubleMap, double_map)
#endif

#include "page-flags-helper-macros-undefine.h"

#endif	/* PAGE_FLAGS_THP_H */
