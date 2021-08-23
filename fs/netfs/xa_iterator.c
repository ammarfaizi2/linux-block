// SPDX-License-Identifier: GPL-2.0-only
/* Folio iteration utility functions.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include "internal.h"

/*
 * Iterate over a range of folios.  xarray locks are not held over the iterator
 * function, so it can sleep if necessary.  The start and end positions are
 * updated to indicate the span of folios actually processed.
 */
#define netfs_iterate_folios(MAPPING, START, END, ITERATOR, ...)	\
	({								\
		unsigned long __it_index;				\
		struct folio *folio;					\
		pgoff_t __it_start = (START);				\
		pgoff_t __it_end = (END);				\
		pgoff_t __it_tmp;					\
		int ret = 0;						\
									\
		(END) = __it_start;					\
		xa_for_each_range(&(MAPPING)->i_pages, __it_index,	\
				  folio, __it_start, __it_end) {	\
			if (xa_is_value(folio)) {			\
				ret = -EIO; /* Not a real folio. */	\
				break;					\
			}						\
			if (__it_index < (START))			\
				(START) = __it_index;			\
			ret = ITERATOR(folio, ##__VA_ARGS__);		\
			if (ret < 0)					\
				break;					\
			__it_tmp = folio_next_index(folio) - 1;		\
			if (__it_tmp > (END))				\
				(END) = __it_tmp;			\
		}							\
		ret;							\
	})

/*
 * Iterate over a set of folios, getting each one before calling the iteration
 * function.  The iteration function may drop the RCU read lock, but should
 * call xas_pause() before it does so.  The start and end positions are updated
 * to indicate the span of folios actually processed.
 */
#define netfs_iterate_get_folios(MAPPING, START, END, ITERATOR, ...)	\
	({								\
		unsigned long __it_index;				\
		struct folio *folio;					\
		pgoff_t __it_start = (START);				\
		pgoff_t __it_end = (END);				\
		pgoff_t __it_tmp;					\
		int ret = 0;						\
									\
		XA_STATE(xas, &(MAPPING)->i_pages, __it_start);		\
		(END) = __it_start;					\
		rcu_read_lock();					\
		for (folio = xas_load(&xas);				\
		     folio;						\
		     folio = xas_next_entry(&xas, __it_end)		\
		     ) {						\
			if (xas_retry(&xas, folio))			\
				continue;				\
			if (xa_is_value(folio))				\
				break;					\
			if (!folio_try_get_rcu(folio)) {		\
				xas_reset(&xas);			\
				continue;				\
			}						\
			if (unlikely(folio != xas_reload(&xas))) {	\
				folio_put(folio);			\
				xas_reset(&xas);			\
				continue;				\
			}						\
			__it_index = folio_index(folio);		\
			if (__it_index < (START))			\
				(START) = __it_index;			\
			ret = ITERATOR(&xas, folio, ##__VA_ARGS__);	\
			if (ret < 0)					\
				break;					\
			__it_tmp = folio_next_index(folio) - 1;		\
			if (__it_tmp > (END))				\
				(END) = __it_tmp;			\
		}							\
		rcu_read_unlock();					\
		ret;							\
	})

/*
 * Iterate over a set of folios that we hold pinned with the writeback flag.
 * The iteration function may drop the RCU read lock, but should call
 * xas_pause() before it does so.
 */
#define netfs_iterate_pinned_folios(MAPPING, START, END, ITERATOR, ...)	\
	({								\
		struct folio *folio;					\
		pgoff_t __it_start = (START);				\
		pgoff_t __it_end = (END);				\
		int ret = 0;						\
									\
		XA_STATE(xas, &(MAPPING)->i_pages, __it_start);		\
		rcu_read_lock();					\
		for (folio = xas_load(&xas);				\
		     folio;						\
		     folio = xas_next_entry(&xas, __it_end)		\
		     ) {						\
			if (xas_retry(&xas, folio))			\
				continue;				\
			if (xa_is_value(folio))				\
				break;					\
			if (unlikely(folio != xas_reload(&xas))) {	\
				xas_reset(&xas);			\
				continue;				\
			}						\
			ret = ITERATOR(&xas, folio, ##__VA_ARGS__);	\
			if (ret < 0)					\
				break;					\
		}							\
		rcu_read_unlock();					\
		ret;							\
	})

static int netfs_unlock_folios_iterator(struct folio *folio)
{
	folio_unlock(folio);
	folio_put(folio);
	return 0;
}

/*
 * Unlock all the folios in a range.
 */
void netfs_unlock_folios(struct address_space *mapping, pgoff_t start, pgoff_t end)
{
	netfs_iterate_folios(mapping, start, end, netfs_unlock_folios_iterator);
}

static int netfs_lock_folios_iterator(struct xa_state *xas,
				      struct folio *folio,
				      struct netfs_write_request *wreq,
				      bool may_wait)
{
	int ret = 0;

	/* At this point we hold neither the i_pages lock nor the
	 * folio lock: the folio may be truncated or invalidated
	 * (changing folio->mapping to NULL), or even swizzled
	 * back from swapper_space to tmpfs file mapping
	 */
	if (may_wait) {
		xas_pause(xas);
		rcu_read_unlock();
		ret = folio_lock_killable(folio);
		rcu_read_lock();
	} else {
		if (!folio_trylock(folio))
			ret = -EBUSY;
	}

	return ret;
}

/*
 * Lock all the folios in a range and add them to the write request.
 */
int netfs_lock_folios(struct netfs_write_request *wreq, bool may_wait)
{
	pgoff_t last = wreq->last;
	int ret;

	_enter("%lx-%lx", wreq->first, wreq->last);
	ret = netfs_iterate_get_folios(wreq->mapping, wreq->first, wreq->last,
				       netfs_lock_folios_iterator,
				       wreq, may_wait);
	if (ret < 0) {
		netfs_see_write_request(wreq, netfs_wreq_trace_see_lock_conflict);
		goto failed;
	}

	if (wreq->last < last) {
		kdebug("Some folios missing %lx < %lx", wreq->last, last);
		netfs_see_write_request(wreq, netfs_wreq_trace_see_pages_missing);
		ret = -EIO;
		goto failed;
	}

	wreq->error = 0;
	return 0;

failed:
	netfs_unlock_folios(wreq->mapping, wreq->first, wreq->last);
	wreq->error = ret;
	return ret;
}

static int netfs_mark_writeback_iterator(struct folio *folio)
{
	/* Now we need to clear the dirty flags on any folio that's not shared
	 * with any other dirty region.
	 */
	if (!folio_clear_dirty_for_io(folio))
		BUG();

	/* We set writeback unconditionally because a folio may participate in
	 * more than one simultaneous writeback.
	 */
	folio_start_writeback(folio);
	return 0;
}

/*
 * Mark all the folios in a range for writeback.  The called must have the
 * locked the folios before calling this function.
 */
void netfs_mark_folios_for_writeback(struct netfs_write_request *wreq,
				     pgoff_t first, pgoff_t last)
{
	netfs_iterate_folios(wreq->mapping, first, last,
			     netfs_mark_writeback_iterator);
}

static int netfs_end_writeback_iterator(struct xa_state *xas, struct folio *folio)
{
	folio_end_writeback(folio);
	return 0;
}

/*
 * End the writeback on all the folios in the range set on a write request.
 */
void netfs_end_writeback(struct netfs_write_request *wreq)
{
	netfs_iterate_pinned_folios(wreq->mapping, wreq->first, wreq->last,
				    netfs_end_writeback_iterator);
}
