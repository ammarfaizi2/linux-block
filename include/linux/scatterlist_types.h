/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCATTERLIST_TYPES_H
#define _LINUX_SCATTERLIST_TYPES_H

#include <linux/types.h>

struct scatterlist {
	unsigned long	page_link;
	unsigned int	offset;
	unsigned int	length;
	dma_addr_t	dma_address;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
	unsigned int	dma_length;
#endif
};

struct sg_table {
	struct scatterlist *sgl;	/* the list */
	unsigned int nents;		/* number of mapped entries */
	unsigned int orig_nents;	/* original size of list */
};

/*
 * Maximum number of entries that will be allocated in one piece, if
 * a list larger than this is required then chaining will be utilized.
 */
#define SG_MAX_SINGLE_ALLOC		(PAGE_SIZE / sizeof(struct scatterlist))

/*
 * The maximum number of SG segments that we will put inside a
 * scatterlist (unless chaining is used). Should ideally fit inside a
 * single page, to avoid a higher order allocation.  We could define this
 * to SG_MAX_SINGLE_ALLOC to pack correctly at the highest order.  The
 * minimum value is 32
 */
#define SG_CHUNK_SIZE	128

struct sg_append_table {
	struct sg_table sgt;		/* The scatter list table */
	struct scatterlist *prv;	/* last populated sge in the table */
	unsigned int total_nents;	/* Total entries in the table */
};

/*
 * Like SG_CHUNK_SIZE, but for archs that have sg chaining. This limit
 * is totally arbitrary, a setting of 2048 will get you at least 8mb ios.
 */
#ifdef CONFIG_ARCH_NO_SG_CHAIN
#define SG_MAX_SEGMENTS	SG_CHUNK_SIZE
#else
#define SG_MAX_SEGMENTS	2048
#endif

/*
 * sg page iterator
 *
 * Iterates over sg entries page-by-page.  On each successful iteration, you
 * can call sg_page_iter_page(@piter) to get the current page.
 * @piter->sg will point to the sg holding this page and @piter->sg_pgoffset to
 * the page's page offset within the sg. The iteration will stop either when a
 * maximum number of sg entries was reached or a terminating sg
 * (sg_last(sg) == true) was reached.
 */
struct sg_page_iter {
	struct scatterlist	*sg;		/* sg holding the page */
	unsigned int		sg_pgoffset;	/* page offset within the sg */

	/* these are internal states, keep away */
	unsigned int		__nents;	/* remaining sg entries */
	int			__pg_advance;	/* nr pages to advance at the
						 * next step */
};

/*
 * sg page iterator for DMA addresses
 *
 * This is the same as sg_page_iter however you can call
 * sg_page_iter_dma_address(@dma_iter) to get the page's DMA
 * address. sg_page_iter_page() cannot be called on this iterator.
 */
struct sg_dma_page_iter {
	struct sg_page_iter base;
};

struct sg_mapping_iter {
	/* the following three fields can be accessed directly */
	struct page		*page;		/* currently mapped page */
	void			*addr;		/* pointer to the mapped area */
	size_t			length;		/* length of the mapped area */
	size_t			consumed;	/* number of consumed bytes */
	struct sg_page_iter	piter;		/* page iterator */

	/* these are internal states, keep away */
	unsigned int		__offset;	/* offset within page */
	unsigned int		__remaining;	/* remaining bytes on page */
	unsigned int		__flags;
};

#endif /* _LINUX_SCATTERLIST_TYPES_H */
