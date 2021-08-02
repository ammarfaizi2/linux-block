/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQ_API_IO_H
#define _LINUX_IRQ_API_IO_H

#include <linux/irq.h>

#include <linux/io.h>

static inline void irq_reg_writel(struct irq_chip_generic *gc,
				  u32 val, int reg_offset)
{
	if (gc->reg_writel)
		gc->reg_writel(val, gc->reg_base + reg_offset);
	else
		writel(val, gc->reg_base + reg_offset);
}

static inline u32 irq_reg_readl(struct irq_chip_generic *gc,
				int reg_offset)
{
	if (gc->reg_readl)
		return gc->reg_readl(gc->reg_base + reg_offset);
	else
		return readl(gc->reg_base + reg_offset);
}

#endif /* _LINUX_IRQ_API_IO_H */
