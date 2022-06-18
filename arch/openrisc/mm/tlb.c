// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OpenRISC tlb.c
 *
 * Linux architectural port borrowing liberally from similar works of
 * others.  All original copyrights apply as per the original source
 * declaration.
 *
 * Modifications for the OpenRISC architecture:
 * Copyright (C) 2003 Matjaz Breskvar <phoenix@bsemi.com>
 * Copyright (C) 2010-2011 Julius Baxter <julius.baxter@orsoc.se>
 * Copyright (C) 2010-2011 Jonas Bonn <jonas@southpole.se>
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/init.h>

#include <asm/cpuinfo.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/spr_defs.h>

#define NO_CONTEXT -1

/*
 * Calculates the SPR register offset top access the xTLB mask
 * registers.
 *
 * The offset is made up of the following bits:
 *
 *   +-------+---+-------+---------+
 *   | 10  8 | 7 | 6   4 | 3     0 |
 *   +-------+---+-------+---------+
 *   |   way | MT|             set |
 *   +-------+---+-------+---------+
 *
 * MT is the 0 for mask register and 1 for the translation
 * register. So we always set 0 here.
 *
 * The TLB way replace mechanism just uses more upper bits of
 * the address rather than attempting something fancy like LRU.
 *
 * Side note we always use SPR_xTLBMR_BASE(0) because the base must
 * be constant.
 */

static unsigned long dtlb_offset(unsigned long vaddr,
				 struct cpuinfo_or1k *cpuinfo)
{
	unsigned long addr = vaddr >> PAGE_SHIFT;
	unsigned long idx = addr & (cpuinfo->dtlb_sets - 1);
	unsigned long way = (addr >> SPR_DMMUCFGR_NTS_WIDTH) &
			    (cpuinfo->dtlb_ways - 1);

	return (way << (SPR_DMMUCFGR_NTS_WIDTH + 1)) + idx;
}

static unsigned long itlb_offset(unsigned long vaddr,
				 struct cpuinfo_or1k *cpuinfo)
{
	unsigned long addr = vaddr >> PAGE_SHIFT;
	unsigned long idx = addr & (cpuinfo->itlb_sets - 1);
	unsigned long way = (addr >> SPR_IMMUCFGR_NTS_WIDTH) &
			    (cpuinfo->itlb_ways - 1);

	return (way << (SPR_IMMUCFGR_NTS_WIDTH + 1)) + idx;
}
/*
 * Invalidate all TLB entries.
 *
 * This comes down to setting the 'valid' bit for all xTLBMR registers to 0.
 * Easiest way to accomplish this is to just zero out the xTLBMR register
 * completely.
 *
 */

void local_flush_tlb_all(void)
{
	int set, way;
	unsigned long offset;
	struct cpuinfo_or1k *cpuinfo = &cpuinfo_or1k[smp_processor_id()];

	/* FIXME: Assumption is I & D nsets equal. */
	for (set = 0; set < cpuinfo->itlb_sets; set++) {
		for (way = 0; way < cpuinfo->itlb_ways; way++) {
			offset = (way << (SPR_IMMUCFGR_NTS_WIDTH + 1)) + set;

			mtspr_off(SPR_DTLBMR_BASE(0), offset, 0);
			mtspr_off(SPR_ITLBMR_BASE(0), offset, 0);
		}
	}
}

#define have_dtlbeir (mfspr(SPR_DMMUCFGR) & SPR_DMMUCFGR_TEIRI)
#define have_itlbeir (mfspr(SPR_IMMUCFGR) & SPR_IMMUCFGR_TEIRI)

/*
 * Invalidate a single page.  This is what the xTLBEIR register is for.
 *
 * There's no point in checking the vma for PAGE_EXEC to determine whether it's
 * the data or instruction TLB that should be flushed... that would take more
 * than the few instructions that the following compiles down to!
 *
 * The case where we don't have the xTLBEIR register really only works for
 * MMU's with a single way and is hard-coded that way.
 */

#define flush_dtlb_page_eir(addr) mtspr(SPR_DTLBEIR, addr)
#define flush_dtlb_page_no_eir(addr, cpuinfo) \
	mtspr_off(SPR_DTLBMR_BASE(0), dtlb_offset(addr, cpuinfo), 0)

#define flush_itlb_page_eir(addr) mtspr(SPR_ITLBEIR, addr)
#define flush_itlb_page_no_eir(addr, cpuinfo) \
	mtspr_off(SPR_ITLBMR_BASE(0), itlb_offset(addr, cpuinfo), 0)

void local_flush_tlb_page(struct vm_area_struct *vma, unsigned long addr)
{
	struct cpuinfo_or1k *cpuinfo = &cpuinfo_or1k[smp_processor_id()];

	if (have_dtlbeir)
		flush_dtlb_page_eir(addr);
	else
		flush_dtlb_page_no_eir(addr, cpuinfo);

	if (have_itlbeir)
		flush_itlb_page_eir(addr);
	else
		flush_itlb_page_no_eir(addr, cpuinfo);
}

void local_flush_tlb_range(struct vm_area_struct *vma,
			   unsigned long start, unsigned long end)
{
	int addr;
	bool dtlbeir;
	bool itlbeir;
	struct cpuinfo_or1k *cpuinfo = &cpuinfo_or1k[smp_processor_id()];

	dtlbeir = have_dtlbeir;
	itlbeir = have_itlbeir;

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		if (dtlbeir)
			flush_dtlb_page_eir(addr);
		else
			flush_dtlb_page_no_eir(addr, cpuinfo);

		if (itlbeir)
			flush_itlb_page_eir(addr);
		else
			flush_itlb_page_no_eir(addr, cpuinfo);
	}
}

/*
 * Invalidate the selected mm context only.
 *
 * FIXME: Due to some bug here, we're flushing everything for now.
 * This should be changed to loop over over mm and call flush_tlb_range.
 */

void local_flush_tlb_mm(struct mm_struct *mm)
{

	/* Was seeing bugs with the mm struct passed to us. Scrapped most of
	   this function. */
	/* Several architectures do this */
	local_flush_tlb_all();
}

/* called in schedule() just before actually doing the switch_to */

void switch_mm(struct mm_struct *prev, struct mm_struct *next,
	       struct task_struct *next_tsk)
{
	unsigned int cpu;

	if (unlikely(prev == next))
		return;

	cpu = smp_processor_id();

	cpumask_clear_cpu(cpu, mm_cpumask(prev));
	cpumask_set_cpu(cpu, mm_cpumask(next));

	/* remember the pgd for the fault handlers
	 * this is similar to the pgd register in some other CPU's.
	 * we need our own copy of it because current and active_mm
	 * might be invalid at points where we still need to derefer
	 * the pgd.
	 */
	current_pgd[cpu] = next->pgd;

	/* We don't have context support implemented, so flush all
	 * entries belonging to previous map
	 */
	local_flush_tlb_mm(prev);
}

/*
 * Initialize the context related info for a new mm_struct
 * instance.
 */

int init_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
	mm->context = NO_CONTEXT;
	return 0;
}

/* called by __exit_mm to destroy the used MMU context if any before
 * destroying the mm itself. this is only called when the last user of the mm
 * drops it.
 */

void destroy_context(struct mm_struct *mm)
{
	flush_tlb_mm(mm);

}

/* called once during VM initialization, from init.c */

void __init tlb_init(void)
{
	/* Do nothing... */
	/* invalidate the entire TLB */
	/* flush_tlb_all(); */
}
