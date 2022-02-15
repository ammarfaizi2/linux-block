/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGEMAP_API_READAHEAD_H
#define _LINUX_PAGEMAP_API_READAHEAD_H

/*
 * Copyright 1995 Linus Torvalds
 */

#include <linux/xarray_api.h>
#include <linux/pagemap.h>

bool filemap_range_has_writeback(struct address_space *mapping,
				 loff_t start_byte, loff_t end_byte);

/**
 * filemap_range_needs_writeback - check if range potentially needs writeback
 * @mapping:           address space within which to check
 * @start_byte:        offset in bytes where the range starts
 * @end_byte:          offset in bytes where the range ends (inclusive)
 *
 * Find at least one page in the range supplied, usually used to check if
 * direct writing in this range will trigger a writeback. Used by O_DIRECT
 * read/write with IOCB_NOWAIT, to see if the caller needs to do
 * filemap_write_and_wait_range() before proceeding.
 *
 * Return: %true if the caller should do filemap_write_and_wait_range() before
 * doing O_DIRECT to a page in this range, %false otherwise.
 */
static inline bool filemap_range_needs_writeback(struct address_space *mapping,
						 loff_t start_byte,
						 loff_t end_byte)
{
	if (!mapping->nrpages)
		return false;
	if (!mapping_tagged(mapping, PAGECACHE_TAG_DIRTY) &&
	    !mapping_tagged(mapping, PAGECACHE_TAG_WRITEBACK))
		return false;
	return filemap_range_has_writeback(mapping, start_byte, end_byte);
}

/**
 * struct readahead_control - Describes a readahead request.
 *
 * A readahead request is for consecutive pages.  Filesystems which
 * implement the ->readahead method should call readahead_page() or
 * readahead_page_batch() in a loop and attempt to start I/O against
 * each page in the request.
 *
 * Most of the fields in this struct are private and should be accessed
 * by the functions below.
 *
 * @file: The file, used primarily by network filesystems for authentication.
 *	  May be NULL if invoked internally by the filesystem.
 * @mapping: Readahead this filesystem object.
 * @ra: File readahead state.  May be NULL.
 */
struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
/* private: use the readahead_* accessors instead */
	pgoff_t _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
};

#define DEFINE_READAHEAD(ractl, f, r, m, i)				\
	struct readahead_control ractl = {				\
		.file = f,						\
		.mapping = m,						\
		.ra = r,						\
		._index = i,						\
	}

#define VM_READAHEAD_PAGES	(SZ_128K / PAGE_SIZE)

void page_cache_ra_unbounded(struct readahead_control *,
		unsigned long nr_to_read, unsigned long lookahead_count);
void page_cache_sync_ra(struct readahead_control *, unsigned long req_count);
void page_cache_async_ra(struct readahead_control *, struct folio *,
		unsigned long req_count);
void readahead_expand(struct readahead_control *ractl,
		      loff_t new_start, size_t new_len);

/**
 * page_cache_sync_readahead - generic file readahead
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @file: Used by the filesystem for authentication.
 * @index: Index of first page to be read.
 * @req_count: Total number of pages being read by the caller.
 *
 * page_cache_sync_readahead() should be called when a cache miss happened:
 * it will submit the read.  The readahead logic may decide to piggyback more
 * pages onto the read request if access patterns suggest it will improve
 * performance.
 */
static inline
void page_cache_sync_readahead(struct address_space *mapping,
		struct file_ra_state *ra, struct file *file, pgoff_t index,
		unsigned long req_count)
{
	DEFINE_READAHEAD(ractl, file, ra, mapping, index);
	page_cache_sync_ra(&ractl, req_count);
}

/**
 * page_cache_async_readahead - file readahead for marked pages
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @file: Used by the filesystem for authentication.
 * @page: The page at @index which triggered the readahead call.
 * @index: Index of first page to be read.
 * @req_count: Total number of pages being read by the caller.
 *
 * page_cache_async_readahead() should be called when a page is used which
 * is marked as PageReadahead; this is a marker to suggest that the application
 * has used up enough of the readahead window that we should start pulling in
 * more pages.
 */
static inline
void page_cache_async_readahead(struct address_space *mapping,
		struct file_ra_state *ra, struct file *file,
		struct page *page, pgoff_t index, unsigned long req_count)
{
	DEFINE_READAHEAD(ractl, file, ra, mapping, index);
	page_cache_async_ra(&ractl, page_folio(page), req_count);
}

static inline struct folio *__readahead_folio(struct readahead_control *ractl)
{
	struct folio *folio;

	BUG_ON(ractl->_batch_count > ractl->_nr_pages);
	ractl->_nr_pages -= ractl->_batch_count;
	ractl->_index += ractl->_batch_count;

	if (!ractl->_nr_pages) {
		ractl->_batch_count = 0;
		return NULL;
	}

	folio = xa_load(&ractl->mapping->i_pages, ractl->_index);
	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	ractl->_batch_count = folio_nr_pages(folio);

	return folio;
}

/**
 * readahead_page - Get the next page to read.
 * @ractl: The current readahead request.
 *
 * Context: The page is locked and has an elevated refcount.  The caller
 * should decreases the refcount once the page has been submitted for I/O
 * and unlock the page once all I/O to that page has completed.
 * Return: A pointer to the next page, or %NULL if we are done.
 */
static inline struct page *readahead_page(struct readahead_control *ractl)
{
	struct folio *folio = __readahead_folio(ractl);

	return &folio->page;
}

/**
 * readahead_folio - Get the next folio to read.
 * @ractl: The current readahead request.
 *
 * Context: The folio is locked.  The caller should unlock the folio once
 * all I/O to that folio has completed.
 * Return: A pointer to the next folio, or %NULL if we are done.
 */
static inline struct folio *readahead_folio(struct readahead_control *ractl)
{
	struct folio *folio = __readahead_folio(ractl);

	if (folio)
		folio_put(folio);
	return folio;
}

static inline unsigned int __readahead_batch(struct readahead_control *rac,
		struct page **array, unsigned int array_sz)
{
	unsigned int i = 0;
	XA_STATE(xas, &rac->mapping->i_pages, 0);
	struct page *page;

	BUG_ON(rac->_batch_count > rac->_nr_pages);
	rac->_nr_pages -= rac->_batch_count;
	rac->_index += rac->_batch_count;
	rac->_batch_count = 0;

	xas_set(&xas, rac->_index);
	rcu_read_lock();
	xas_for_each(&xas, page, rac->_index + rac->_nr_pages - 1) {
		if (xas_retry(&xas, page))
			continue;
		VM_BUG_ON_PAGE(!PageLocked(page), page);
		VM_BUG_ON_PAGE(PageTail(page), page);
		array[i++] = page;
		rac->_batch_count += thp_nr_pages(page);
		if (i == array_sz)
			break;
	}
	rcu_read_unlock();

	return i;
}

/**
 * readahead_page_batch - Get a batch of pages to read.
 * @rac: The current readahead request.
 * @array: An array of pointers to struct page.
 *
 * Context: The pages are locked and have an elevated refcount.  The caller
 * should decreases the refcount once the page has been submitted for I/O
 * and unlock the page once all I/O to that page has completed.
 * Return: The number of pages placed in the array.  0 indicates the request
 * is complete.
 */
#define readahead_page_batch(rac, array)				\
	__readahead_batch(rac, array, ARRAY_SIZE(array))

/**
 * readahead_pos - The byte offset into the file of this readahead request.
 * @rac: The readahead request.
 */
static inline loff_t readahead_pos(struct readahead_control *rac)
{
	return (loff_t)rac->_index * PAGE_SIZE;
}

/**
 * readahead_length - The number of bytes in this readahead request.
 * @rac: The readahead request.
 */
static inline size_t readahead_length(struct readahead_control *rac)
{
	return rac->_nr_pages * PAGE_SIZE;
}

/**
 * readahead_index - The index of the first page in this readahead request.
 * @rac: The readahead request.
 */
static inline pgoff_t readahead_index(struct readahead_control *rac)
{
	return rac->_index;
}

/**
 * readahead_count - The number of pages in this readahead request.
 * @rac: The readahead request.
 */
static inline unsigned int readahead_count(struct readahead_control *rac)
{
	return rac->_nr_pages;
}

/**
 * readahead_batch_length - The number of bytes in the current batch.
 * @rac: The readahead request.
 */
static inline size_t readahead_batch_length(struct readahead_control *rac)
{
	return rac->_batch_count * PAGE_SIZE;
}

#endif /* _LINUX_PAGEMAP_API_READAHEAD_H */
