/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQ_API_GC_LOCK_H
#define _LINUX_IRQ_API_GC_LOCK_H

#include <linux/irq.h>

#include <linux/spinlock_api.h>

#ifdef CONFIG_SMP
static inline void irq_gc_lock(struct irq_chip_generic *gc)
{
	raw_spin_lock(&gc->lock);
}

static inline void irq_gc_unlock(struct irq_chip_generic *gc)
{
	raw_spin_unlock(&gc->lock);
}
#else
static inline void irq_gc_lock(struct irq_chip_generic *gc) { }
static inline void irq_gc_unlock(struct irq_chip_generic *gc) { }
#endif

/*
 * The irqsave variants are for usage in non interrupt code. Do not use
 * them in irq_chip callbacks. Use irq_gc_lock() instead.
 */
#define irq_gc_lock_irqsave(gc, flags)	\
	raw_spin_lock_irqsave(&(gc)->lock, flags)

#define irq_gc_unlock_irqrestore(gc, flags)	\
	raw_spin_unlock_irqrestore(&(gc)->lock, flags)

#endif /* _LINUX_IRQ_API_GC_LOCK_H */
