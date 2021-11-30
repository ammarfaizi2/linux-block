/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_API_MAPPING_H
#define _LINUX_FS_API_MAPPING_H

#include <linux/fs_api.h>

#include <linux/atomic_api.h>

/*
 * Might pages of this file have been modified in userspace?
 * Note that i_mmap_writable counts all VM_SHARED vmas: do_mmap
 * marks vma as VM_SHARED if it is shared, and the file was opened for
 * writing i.e. vma may be mprotected writable even if now readonly.
 *
 * If i_mmap_writable is negative, no new writable mappings are allowed. You
 * can only deny writable mappings, if none exists right now.
 */
static inline int mapping_writably_mapped(struct address_space *mapping)
{
	return atomic_read(&mapping->i_mmap_writable) > 0;
}

static inline int mapping_map_writable(struct address_space *mapping)
{
	return atomic_inc_unless_negative(&mapping->i_mmap_writable) ?
		0 : -EPERM;
}

static inline void mapping_unmap_writable(struct address_space *mapping)
{
	atomic_dec(&mapping->i_mmap_writable);
}

static inline int mapping_deny_writable(struct address_space *mapping)
{
	return atomic_dec_unless_positive(&mapping->i_mmap_writable) ?
		0 : -EBUSY;
}

static inline void mapping_allow_writable(struct address_space *mapping)
{
	atomic_inc(&mapping->i_mmap_writable);
}

#endif /* _LINUX_FS_API_MAPPING_H */
