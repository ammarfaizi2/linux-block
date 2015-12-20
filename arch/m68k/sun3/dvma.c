/*
 * linux/arch/m68k/sun3/dvma.c
 *
 * Written by Sam Creasey
 *
 * Sun3 IOMMU routines used for dvma accesses.
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/bootmem.h>
#include <linux/list.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/sun3mmu.h>
#include <asm/dvma.h>


static unsigned long ptelist[120];

static void *dvma_page(void *kaddr, void *vaddr)
{
	unsigned long pte;
	unsigned long j;
	pte_t ptep;
	int idx;

	j = *(volatile unsigned long *)kaddr;
	*(volatile unsigned long *)kaddr = j;

	ptep = pfn_pte(virt_to_pfn(kaddr), PAGE_KERNEL);
	pte = pte_val(ptep);
//		printk("dvma_remap: addr %p -> %lx pte %08lx len %x\n",
//		       kaddr, vaddr, pte, len);
	idx = ((unsigned long)vaddr & 0xff000) >> PAGE_SHIFT;

	if (ptelist[idx] != pte) {
		sun3_put_pte((unsigned long)vaddr, pte);
		ptelist[idx] = pte;
	}

	return vaddr + offset_in_page(kaddr);
}

int dvma_map_iommu(void *kaddr, unsigned long baddr, int len)
{
	void *vaddr = dvma_btov(baddr);
	void *end = vaddr + len;

	while (vaddr < end) {
		dvma_page(kaddr, vaddr);
		kaddr += PAGE_SIZE;
		vaddr += PAGE_SIZE;
	}

	return 0;
}

void __init sun3_dvma_init(void)
{
	memset(ptelist, 0, sizeof(ptelist));
}
