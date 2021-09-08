/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SOFTIRQ_H
#define _LINUX_SOFTIRQ_H

#include <linux/interrupt_types.h>

#include <linux/linkage.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/irqflags.h>

#include <asm/hardirq.h>
#include <asm/sections.h>

#ifndef local_softirq_pending

#ifndef local_softirq_pending_ref
#define local_softirq_pending_ref irq_stat.__softirq_pending
#endif

#define local_softirq_pending()	(__this_cpu_read(local_softirq_pending_ref))
#define set_softirq_pending(x)	(__this_cpu_write(local_softirq_pending_ref, (x)))
#define or_softirq_pending(x)	(__this_cpu_or(local_softirq_pending_ref, (x)))

#endif /* local_softirq_pending */

/* map softirq index to softirq name. update 'softirq_to_name' in
 * kernel/softirq.c when adding a new softirq.
 */
extern const char * const softirq_to_name[NR_SOFTIRQS];

/* softirq mask and active fields moved to irq_cpustat_t in
 * asm/hardirq.h to get better cache usage.  KAO
 */

struct softirq_action
{
	void	(*action)(struct softirq_action *);
};

asmlinkage void do_softirq(void);
asmlinkage void __do_softirq(void);

extern void open_softirq(int nr, void (*action)(struct softirq_action *));
extern void softirq_init(void);
extern void __raise_softirq_irqoff(unsigned int nr);

extern void raise_softirq_irqoff(unsigned int nr);
extern void raise_softirq(unsigned int nr);

DECLARE_PER_CPU(struct task_struct *, ksoftirqd);

static inline struct task_struct *this_cpu_ksoftirqd(void)
{
	return this_cpu_read(ksoftirqd);
}

#define __softirq_entry  __section(".softirqentry.text")

#endif /* _LINUX_SOFTIRQ_H */
