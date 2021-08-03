#ifndef __DRM_VMA_MANAGER_API_VM_LOCK_H__
#define __DRM_VMA_MANAGER_API_VM_LOCK_H__

/*
 * Copyright (c) 2013 David Herrmann <dh.herrmann@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <drm/drm_vma_manager.h>

/**
 * drm_vma_offset_lock_lookup() - Lock lookup for extended private use
 * @mgr: Manager object
 *
 * Lock VMA manager for extended lookups. Only locked VMA function calls
 * are allowed while holding this lock. All other contexts are blocked from VMA
 * until the lock is released via drm_vma_offset_unlock_lookup().
 *
 * Use this if you need to take a reference to the objects returned by
 * drm_vma_offset_lookup_locked() before releasing this lock again.
 *
 * This lock must not be used for anything else than extended lookups. You must
 * not call any other VMA helpers while holding this lock.
 *
 * Note: You're in atomic-context while holding this lock!
 */
static inline void drm_vma_offset_lock_lookup(struct drm_vma_offset_manager *mgr)
{
	read_lock(&mgr->vm_lock);
}

/**
 * drm_vma_offset_unlock_lookup() - Unlock lookup for extended private use
 * @mgr: Manager object
 *
 * Release lookup-lock. See drm_vma_offset_lock_lookup() for more information.
 */
static inline void drm_vma_offset_unlock_lookup(struct drm_vma_offset_manager *mgr)
{
	read_unlock(&mgr->vm_lock);
}

/**
 * drm_vma_node_reset() - Initialize or reset node object
 * @node: Node to initialize or reset
 *
 * Reset a node to its initial state. This must be called before using it with
 * any VMA offset manager.
 *
 * This must not be called on an already allocated node, or you will leak
 * memory.
 */
static inline void drm_vma_node_reset(struct drm_vma_offset_node *node)
{
	memset(node, 0, sizeof(*node));
	node->vm_files = RB_ROOT;
	rwlock_init(&node->vm_lock);
}

#endif /* __DRM_VMA_MANAGER_API_VM_LOCK_H__ */
