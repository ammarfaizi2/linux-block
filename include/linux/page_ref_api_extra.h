/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_REF_API_EXTRA_H
#define _LINUX_PAGE_REF_API_EXTRA_H

#include <linux/page_ref.h>

#include <linux/preempt.h>
#include <linux/irqflags.h>

/**
 * folio_try_get - Attempt to increase the refcount on a folio.
 * @folio: The folio.
 *
 * If you do not already have a reference to a folio, you can attempt to
 * get one using this function.  It may fail if, for example, the folio
 * has been freed since you found a pointer to it, or it is frozen for
 * the purposes of splitting or migration.
 *
 * Return: True if the reference count was successfully incremented.
 */
static inline bool folio_try_get(struct folio *folio)
{
	return folio_ref_add_unless(folio, 1, 0);
}

static inline bool folio_ref_try_add_rcu(struct folio *folio, int count)
{
#ifdef CONFIG_TINY_RCU
	/*
	 * The caller guarantees the folio will not be freed from interrupt
	 * context, so (on !SMP) we only need preemption to be disabled
	 * and TINY_RCU does that for us.
	 */
# ifdef CONFIG_PREEMPT_COUNT
	VM_BUG_ON(!in_atomic() && !irqs_disabled());
# endif
	VM_BUG_ON_FOLIO(folio_ref_count(folio) == 0, folio);
	folio_ref_add(folio, count);
#else
	if (unlikely(!folio_ref_add_unless(folio, count, 0))) {
		/* Either the folio has been freed, or will be freed. */
		return false;
	}
#endif
	return true;
}

/**
 * folio_try_get_rcu - Attempt to increase the refcount on a folio.
 * @folio: The folio.
 *
 * This is a version of folio_try_get() optimised for non-SMP kernels.
 * If you are still holding the rcu_read_lock() after looking up the
 * page and know that the page cannot have its refcount decreased to
 * zero in interrupt context, you can use this instead of folio_try_get().
 *
 * Example users include get_user_pages_fast() (as pages are not unmapped
 * from interrupt context) and the page cache lookups (as pages are not
 * truncated from interrupt context).  We also know that pages are not
 * frozen in interrupt context for the purposes of splitting or migration.
 *
 * You can also use this function if you're holding a lock that prevents
 * pages being frozen & removed; eg the i_pages lock for the page cache
 * or the mmap_sem or page table lock for page tables.  In this case,
 * it will always succeed, and you could have used a plain folio_get(),
 * but it's sometimes more convenient to have a common function called
 * from both locked and RCU-protected contexts.
 *
 * Return: True if the reference count was successfully incremented.
 */
static inline bool folio_try_get_rcu(struct folio *folio)
{
	return folio_ref_try_add_rcu(folio, 1);
}

#endif /* _LINUX_PAGE_REF_API_EXTRA_H */
