/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQ_API_FREE_H
#define _LINUX_IRQ_API_FREE_H

#include <linux/irq.h>

#include <linux/slab.h>

static inline void irq_free_generic_chip(struct irq_chip_generic *gc)
{
	kfree(gc);
}

static inline void irq_destroy_generic_chip(struct irq_chip_generic *gc,
					    u32 msk, unsigned int clr,
					    unsigned int set)
{
	irq_remove_generic_chip(gc, msk, clr, set);
	irq_free_generic_chip(gc);
}

#endif /* _LINUX_IRQ_API_FREE_H */
