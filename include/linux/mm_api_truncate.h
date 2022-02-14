/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_API_TRUNCATE_H
#define _LINUX_MM_API_TRUNCATE_H

#include <linux/types.h>

struct address_space;
struct inode;
struct page;

/* truncate.c */
extern void truncate_inode_pages(struct address_space *, loff_t);
extern void truncate_inode_pages_range(struct address_space *,
				       loff_t lstart, loff_t lend);
extern void truncate_inode_pages_final(struct address_space *);

extern void truncate_pagecache(struct inode *inode, loff_t new);
extern void truncate_setsize(struct inode *inode, loff_t newsize);
void pagecache_isize_extended(struct inode *inode, loff_t from, loff_t to);
void truncate_pagecache_range(struct inode *inode, loff_t offset, loff_t end);
int generic_error_remove_page(struct address_space *mapping, struct page *page);
int invalidate_inode_page(struct page *page);

#endif /* _LINUX_MM_API_TRUNCATE_H */
