/*
 * linux/arch/unicore32/include/asm/mmu_context.h
 *
 * Code specific to PKUnity SoC and UniCore ISA
 *
 * Copyright (C) 2001-2010 GUAN Xue-tao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __UNICORE_MMU_CONTEXT_H__
#define __UNICORE_MMU_CONTEXT_H__

#include <linux/compiler.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/io.h>

#include <asm/cacheflush.h>
#include <asm/cpu-single.h>
#include <asm-generic/mm_hooks.h>

#define init_new_context(tsk, mm)	0

#define destroy_context(mm)		do { } while (0)

/*
 * This is called when "tsk" is about to enter lazy TLB mode.
 *
 * mm:  describes the currently active mm context
 * tsk: task which is entering lazy tlb
 * cpu: cpu number which is entering lazy tlb
 *
 * tsk->mm will be NULL
 */
static inline void
enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{
}

/*
 * This is the actual mm switch as far as the scheduler
 * is concerned.  No registers are touched.  We avoid
 * calling the CPU specific function when the mm hasn't
 * actually changed.
 */
static inline void
switch_mm(struct mm_struct *prev, struct mm_struct *next,
	  struct task_struct *tsk)
{
	unsigned int cpu = smp_processor_id();

	if (!cpumask_test_and_set_cpu(cpu, mm_cpumask(next)) || prev != next)
		cpu_switch_mm(next->pgd, next);
}

#define deactivate_mm(tsk, mm)	do { } while (0)
#define activate_mm(prev, next)	switch_mm(prev, next, NULL)

static inline void arch_dup_mmap(struct mm_struct *oldmm,
				 struct mm_struct *mm)
{
}

static inline void arch_unmap(struct mm_struct *mm,
			struct vm_area_struct *vma,
			unsigned long start, unsigned long end)
{
}

static inline void arch_bprm_mm_init(struct mm_struct *mm,
				     struct vm_area_struct *vma)
{
}
#endif
