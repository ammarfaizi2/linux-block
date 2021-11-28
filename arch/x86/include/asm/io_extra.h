/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_IO_EXTRA_H
#define _ASM_X86_IO_EXTRA_H

#include <asm/io.h>

#include <asm/special_insns.h>

/**
 * iosubmit_cmds512 - copy data to single MMIO location, in 512-bit units
 * @dst: destination, in MMIO space (must be 512-bit aligned)
 * @src: source
 * @count: number of 512 bits quantities to submit
 *
 * Submit data from kernel space to MMIO space, in units of 512 bits at a
 * time.  Order of access is not guaranteed, nor is a memory barrier
 * performed afterwards.
 *
 * Warning: Do not use this helper unless your driver has checked that the CPU
 * instruction is supported on the platform.
 */
static inline void iosubmit_cmds512(void __iomem *dst, const void *src,
				    size_t count)
{
	const u8 *from = src;
	const u8 *end = from + count * 64;

	while (from < end) {
		movdir64b(dst, from);
		from += 64;
	}
}

#define ARCH_HAS_VALID_PHYS_ADDR_RANGE

extern int valid_phys_addr_range(phys_addr_t addr, size_t size);
extern int valid_mmap_phys_addr_range(unsigned long pfn, size_t size);

/**
 *	virt_to_phys	-	map virtual addresses to physical
 *	@address: address to remap
 *
 *	The returned physical address is the physical (CPU) mapping for
 *	the memory address given. It is only valid to use this function on
 *	addresses directly mapped or allocated via kmalloc.
 *
 *	This function does not give bus mappings for DMA transfers. In
 *	almost all conceivable cases a device driver should not be using
 *	this function
 */

static inline phys_addr_t virt_to_phys(volatile void *address)
{
	return __pa(address);
}
#define virt_to_phys virt_to_phys

/**
 *	phys_to_virt	-	map physical address to virtual
 *	@address: address to remap
 *
 *	The returned virtual address is a current CPU mapping for
 *	the memory address given. It is only valid to use this function on
 *	addresses that have a kernel mapping
 *
 *	This function does not handle bus mappings for DMA transfers. In
 *	almost all conceivable cases a device driver should not be using
 *	this function
 */

static inline void *phys_to_virt(phys_addr_t address)
{
	return __va(address);
}
#define phys_to_virt phys_to_virt

/*
 * Change "struct page" to physical address.
 */
#define page_to_phys(page)    ((dma_addr_t)page_to_pfn(page) << PAGE_SHIFT)

/*
 * ISA I/O bus memory addresses are 1:1 with the physical address.
 * However, we truncate the address to unsigned int to avoid undesirable
 * promotions in legacy drivers.
 */
static inline unsigned int isa_virt_to_bus(volatile void *address)
{
	return (unsigned int)virt_to_phys(address);
}
#define isa_bus_to_virt		phys_to_virt

/*
 * However PCI ones are not necessarily 1:1 and therefore these interfaces
 * are forbidden in portable PCI drivers.
 *
 * Allow them on x86 for legacy drivers, though.
 */
#define virt_to_bus virt_to_phys
#define bus_to_virt phys_to_virt

#endif /* _ASM_X86_IO_EXTRA_H */
