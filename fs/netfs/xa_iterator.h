/* SPDX-License-Identifier: GPL-2.0-or-later */
/* xarray iterator macros for netfslib.
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

/*
 * Iterate over a set of pages that we hold pinned with the writeback flag.
 * The iteration function may drop the RCU read lock, but should call
 * xas_pause() before it does so.
 */
#define netfs_iterate_pinned_pages(MAPPING, START, END, ITERATOR, ...)	\
	({								\
		struct page *page;					\
		pgoff_t __it_start = (START);				\
		pgoff_t __it_end = (END);				\
		int ret = 0;						\
									\
		XA_STATE(xas, &(MAPPING)->i_pages, __it_start);		\
		rcu_read_lock();					\
		for (page = xas_load(&xas); page; page = xas_next_entry(&xas, __it_end)) { \
			if (xas_retry(&xas, page))			\
				continue;				\
			if (xa_is_value(page))				\
				break;					\
			if (unlikely(page != xas_reload(&xas))) {	\
				xas_reset(&xas);			\
				continue;				\
			}						\
			ret = ITERATOR(&xas, page, ##__VA_ARGS__);	\
			if (ret < 0)					\
				break;					\
		}							\
		rcu_read_unlock();					\
		ret;							\
	})

/*
 * Iterate over a range of pages.  xarray locks are not held over the iterator
 * function, so it can sleep if necessary.  The start and end positions are
 * updated to indicate the span of pages actually processed.
 */
#define netfs_iterate_pages(MAPPING, START, END, ITERATOR, ...)		\
	({								\
		unsigned long __it_index;				\
		struct page *page;					\
		pgoff_t __it_start = (START);				\
		pgoff_t __it_end = (END);				\
		pgoff_t __it_tmp;					\
		int ret = 0;						\
									\
		(END) = __it_start;					\
		xa_for_each_range(&(MAPPING)->i_pages, __it_index, page, \
				  __it_start, __it_end) {		\
			if (xa_is_value(page)) {			\
				ret = -EIO; /* Not a real page. */	\
				break;					\
			}						\
			if (__it_index < (START))			\
				(START) = __it_index;			\
			ret = ITERATOR(page, ##__VA_ARGS__);		\
			if (ret < 0)					\
				break;					\
			__it_tmp = __it_index + thp_nr_pages(page) - 1;	\
			if (__it_tmp > (END))				\
				(END) = __it_tmp;			\
		}							\
		ret;							\
	})

/*
 * Iterate over a set of pages, getting each one before calling the iteration
 * function.  The iteration function may drop the RCU read lock, but should
 * call xas_pause() before it does so.  The start and end positions are updated
 * to indicate the span of pages actually processed.
 */
#define netfs_iterate_get_pages(MAPPING, START, END, ITERATOR, ...)	\
	({								\
		unsigned long __it_index;				\
		struct page *page;					\
		pgoff_t __it_start = (START);				\
		pgoff_t __it_end = (END);				\
		pgoff_t __it_tmp;					\
		int ret = 0;						\
									\
		XA_STATE(xas, &(MAPPING)->i_pages, __it_start);		\
		(END) = __it_start;					\
		rcu_read_lock();					\
		for (page = xas_load(&xas); page; page = xas_next_entry(&xas, __it_end)) { \
			if (xas_retry(&xas, page))			\
				continue;				\
			if (xa_is_value(page))				\
				break;					\
			if (!page_cache_get_speculative(page)) {	\
				xas_reset(&xas);			\
				continue;				\
			}						\
			if (unlikely(page != xas_reload(&xas))) {	\
				put_page(page);				\
				xas_reset(&xas);			\
				continue;				\
			}						\
			__it_index = page_index(page);			\
			if (__it_index < (START))			\
				(START) = __it_index;			\
			ret = ITERATOR(&xas, page, ##__VA_ARGS__);	\
			if (ret < 0)					\
				break;					\
			__it_tmp = __it_index + thp_nr_pages(page) - 1; \
			if (__it_tmp > (END))				\
				(END) = __it_tmp;			\
		}							\
		rcu_read_unlock();					\
		ret;							\
	})
