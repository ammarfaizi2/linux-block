/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_HW_IRQ_H
#define _ASM_X86_HW_IRQ_H

/*
 * (C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar
 *
 * moved some of the old arch/i386/kernel/irq.h to here. VY
 *
 * IRQ/IPI changes taken from work by Thomas Radke
 * <tomsoft@informatik.tu-chemnitz.de>
 *
 * hacked by Andi Kleen for x86-64.
 * unified by tglx
 */

#include <asm/irq_vectors.h>

#define IRQ_MATRIX_BITS		NR_VECTORS

#ifndef __ASSEMBLY__

#include <asm/irq.h>

/* Statistics */
extern atomic_t irq_err_count;
extern atomic_t irq_mis_count;

#ifdef CONFIG_X86_LOCAL_APIC
struct irq_data;
struct pci_dev;
struct msi_desc;

enum irq_alloc_type {
	X86_IRQ_ALLOC_TYPE_IOAPIC = 1,
	X86_IRQ_ALLOC_TYPE_HPET,
	X86_IRQ_ALLOC_TYPE_PCI_MSI,
	X86_IRQ_ALLOC_TYPE_PCI_MSIX,
	X86_IRQ_ALLOC_TYPE_DMAR,
	X86_IRQ_ALLOC_TYPE_AMDVI,
	X86_IRQ_ALLOC_TYPE_UV,
};

struct ioapic_alloc_info {
	int		pin;
	int		node;
	u32		is_level	: 1;
	u32		active_low	: 1;
	u32		valid		: 1;
};

struct uv_alloc_info {
	int		limit;
	int		blade;
	unsigned long	offset;
	char		*name;

};

/**
 * irq_alloc_info - X86 specific interrupt allocation info
 * @type:	X86 specific allocation type
 * @flags:	Flags for allocation tweaks
 * @devid:	Device ID for allocations
 * @hwirq:	Associated hw interrupt number in the domain
 * @mask:	CPU mask for vector allocation
 * @desc:	Pointer to msi descriptor
 * @data:	Allocation specific data
 *
 * @ioapic:	IOAPIC specific allocation data
 * @uv:		UV specific allocation data
*/
struct irq_alloc_info {
	enum irq_alloc_type	type;
	u32			flags;
	u32			devid;
	irq_hw_number_t		hwirq;
	const struct cpumask	*mask;
	struct msi_desc		*desc;
	void			*data;

	union {
		struct ioapic_alloc_info	ioapic;
		struct uv_alloc_info		uv;
	};
};

struct irq_cfg {
	unsigned int		dest_apicid;
	unsigned int		vector;
};

#endif /* CONFIG_X86_LOCAL_APIC */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_HW_IRQ_H */
