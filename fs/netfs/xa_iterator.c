// SPDX-License-Identifier: GPL-2.0-only
/* Folio iteration utility functions.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
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
