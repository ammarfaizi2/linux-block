/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_VMACACHE_H
#define __LINUX_VMACACHE_H

#include <linux/sched.h>
#include <linux/sched/per_task.h>
#include <linux/mm.h>

/* Per-thread vma caching: */
DECLARE_PER_TASK(struct vmacache, vmacache);

static inline void vmacache_flush(struct task_struct *tsk)
{
	memset(per_task(tsk, vmacache).vmas, 0,
	       sizeof(per_task(tsk, vmacache).vmas));
}

extern void vmacache_update(unsigned long addr, struct vm_area_struct *newvma);
extern struct vm_area_struct *vmacache_find(struct mm_struct *mm,
						    unsigned long addr);

#ifndef CONFIG_MMU
extern struct vm_area_struct *vmacache_find_exact(struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end);
#endif

static inline void vmacache_invalidate(struct mm_struct *mm)
{
	mm->vmacache_seqnum++;
}

#endif /* __LINUX_VMACACHE_H */
