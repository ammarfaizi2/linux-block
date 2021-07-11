/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_API_GATE_AREA_H
#define _LINUX_MM_API_GATE_AREA_H

#include <linux/types.h>

struct mm_struct;
struct vm_area_struct;

#ifdef __HAVE_ARCH_GATE_AREA
extern struct vm_area_struct *get_gate_vma(struct mm_struct *mm);
extern int in_gate_area_no_mm(unsigned long addr);
extern int in_gate_area(struct mm_struct *mm, unsigned long addr);
#else
static inline struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
	return NULL;
}
static inline int in_gate_area_no_mm(unsigned long addr) { return 0; }
static inline int in_gate_area(struct mm_struct *mm, unsigned long addr)
{
	return 0;
}
#endif	/* __HAVE_ARCH_GATE_AREA */

#endif /* _LINUX_MM_API_GATE_AREA_H */
