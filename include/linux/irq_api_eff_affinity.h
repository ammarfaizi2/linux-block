/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQ_API_EFF_AFFINITY_H
#define _LINUX_IRQ_API_EFF_AFFINITY_H

#include <linux/irq.h>

#ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
# include <linux/cpumask_api.h>
#endif

#ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
static inline
struct cpumask *irq_data_get_effective_affinity_mask(struct irq_data *d)
{
	return d->common->effective_affinity;
}
static inline void irq_data_update_effective_affinity(struct irq_data *d,
						      const struct cpumask *m)
{
	cpumask_copy(d->common->effective_affinity, m);
}
#else
static inline void irq_data_update_effective_affinity(struct irq_data *d,
						      const struct cpumask *m)
{
}
static inline
struct cpumask *irq_data_get_effective_affinity_mask(struct irq_data *d)
{
	return d->common->affinity;
}
#endif

static inline struct cpumask *irq_get_effective_affinity_mask(unsigned int irq)
{
	struct irq_data *d = irq_get_irq_data(irq);

	return d ? irq_data_get_effective_affinity_mask(d) : NULL;
}

#endif /* _LINUX_IRQ_API_EFF_AFFINITY_H */
