/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1994 - 1999, 2000, 03 Ralf Baechle
 * Copyright (C) 1999, 2000 Silicon Graphics, Inc.
 */
#ifndef _ASM_PAGE_H
#define _ASM_PAGE_H

#include <asm/page_types.h>

#include <spaces.h>
#include <linux/const.h>
#include <linux/kernel.h>
#include <asm/mipsregs.h>
#include <asm/addrspace.h>
#include <asm/io.h>

#include <linux/pfn.h>

extern void build_clear_page(void);
extern void build_copy_page(void);

/*
 * It's normally defined only for FLATMEM config but it's
 * used in our early mem init code for all memory models.
 * So always define it.
 */
#ifdef CONFIG_MIPS_AUTO_PFN_OFFSET
extern unsigned long ARCH_PFN_OFFSET;
# define ARCH_PFN_OFFSET	ARCH_PFN_OFFSET
#else
# define ARCH_PFN_OFFSET	PFN_UP(PHYS_OFFSET)
#endif

extern void clear_page(void * page);
extern void copy_page(void * to, void * from);

extern unsigned long shm_align_mask;

static inline unsigned long pages_do_alias(unsigned long addr1,
	unsigned long addr2)
{
	return (addr1 ^ addr2) & shm_align_mask;
}

struct page;

static inline void clear_user_page(void *addr, unsigned long vaddr,
	struct page *page)
{
	extern void (*flush_data_cache_page)(unsigned long addr);

	clear_page(addr);
	if (pages_do_alias((unsigned long) addr, vaddr & PAGE_MASK))
		flush_data_cache_page((unsigned long)addr);
}

struct vm_area_struct;
extern void copy_user_highpage(struct page *to, struct page *from,
	unsigned long vaddr, struct vm_area_struct *vma);

#define __HAVE_ARCH_COPY_USER_HIGHPAGE

/*
 * On R4000-style MMUs where a TLB entry is mapping a adjacent even / odd
 * pair of pages we only have a single global bit per pair of pages.  When
 * writing to the TLB make sure we always have the bit set for both pages
 * or none.  This macro is used to access the `buddy' of the pte we're just
 * working on.
 */
#define ptep_buddy(x)	((pte_t *)((unsigned long)(x) ^ sizeof(pte_t)))

/*
 * __pa()/__va() should be used only during mem init.
 */
static inline unsigned long ___pa(unsigned long x)
{
	if (IS_ENABLED(CONFIG_64BIT)) {
		/*
		 * For MIPS64 the virtual address may either be in one of
		 * the compatibility segements ckseg0 or ckseg1, or it may
		 * be in xkphys.
		 */
		return x < CKSEG0 ? XPHYSADDR(x) : CPHYSADDR(x);
	}

	if (!IS_ENABLED(CONFIG_EVA)) {
		/*
		 * We're using the standard MIPS32 legacy memory map, ie.
		 * the address x is going to be in kseg0 or kseg1. We can
		 * handle either case by masking out the desired bits using
		 * CPHYSADDR.
		 */
		return CPHYSADDR(x);
	}

	/*
	 * EVA is in use so the memory map could be anything, making it not
	 * safe to just mask out bits.
	 */
	return x - PAGE_OFFSET + PHYS_OFFSET;
}
#define __pa(x)		___pa((unsigned long)(x))
#define __va(x)		((void *)((unsigned long)(x) + PAGE_OFFSET - PHYS_OFFSET))
#include <asm/io.h>

/*
 * RELOC_HIDE was originally added by 6007b903dfe5f1d13e0c711ac2894bdd4a61b1ad
 * (lmo) rsp. 8431fd094d625b94d364fe393076ccef88e6ce18 (kernel.org).  The
 * discussion can be found in
 * https://lore.kernel.org/lkml/a2ebde260608230500o3407b108hc03debb9da6e62c@mail.gmail.com
 *
 * It is unclear if the misscompilations mentioned in
 * https://lore.kernel.org/lkml/1281303490-390-1-git-send-email-namhyung@gmail.com
 * also affect MIPS so we keep this one until GCC 3.x has been retired
 * before we can apply https://patchwork.linux-mips.org/patch/1541/
 */
#define __pa_symbol_nodebug(x)	__pa(RELOC_HIDE((unsigned long)(x), 0))

#ifdef CONFIG_DEBUG_VIRTUAL
extern phys_addr_t __phys_addr_symbol(unsigned long x);
#else
#define __phys_addr_symbol(x)	__pa_symbol_nodebug(x)
#endif

#ifndef __pa_symbol
#define __pa_symbol(x)		__phys_addr_symbol((unsigned long)(x))
#endif

#define pfn_to_kaddr(pfn)	__va((pfn) << PAGE_SHIFT)

#ifdef CONFIG_FLATMEM

static inline int pfn_valid(unsigned long pfn)
{
	/* avoid <linux/mm.h> include hell */
	extern unsigned long max_mapnr;
	unsigned long pfn_offset = ARCH_PFN_OFFSET;

	return pfn >= pfn_offset && pfn < max_mapnr;
}

#elif defined(CONFIG_SPARSEMEM)

/* pfn_valid is defined in linux/mmzone.h */

#elif defined(CONFIG_NUMA)

#define pfn_valid(pfn)							\
({									\
	unsigned long __pfn = (pfn);					\
	int __n = pfn_to_nid(__pfn);					\
	((__n >= 0) ? (__pfn < NODE_DATA(__n)->node_start_pfn +		\
			       NODE_DATA(__n)->node_spanned_pages)	\
		    : 0);						\
})

#endif

#define virt_to_pfn(kaddr)   	PFN_DOWN(virt_to_phys((void *)(kaddr)))
#define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))

extern bool __virt_addr_valid(const volatile void *kaddr);
#define virt_addr_valid(kaddr)						\
	__virt_addr_valid((const volatile void *) (kaddr))

extern unsigned long __kaslr_offset;
static inline unsigned long kaslr_offset(void)
{
	return __kaslr_offset;
}

#include <asm-generic/memory_model.h>
#include <asm-generic/getorder.h>

#endif /* _ASM_PAGE_H */
