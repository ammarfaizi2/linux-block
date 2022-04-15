/* SPDX-License-Identifier: GPL-2.0 */
/* interrupt.h */
#ifndef _LINUX_INTERRUPT_TYPES_H
#define _LINUX_INTERRUPT_TYPES_H

/* PLEASE, avoid to allocate new softirqs, if you need not _really_ high
   frequency threaded job scheduling. For almost all the purposes
   tasklets are more than enough. F.e. all serial device BHs et
   al. should be converted to tasklets, not to softirqs.
 */

enum
{
	HI_SOFTIRQ=0,
	TIMER_SOFTIRQ,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	BLOCK_SOFTIRQ,
	IRQ_POLL_SOFTIRQ,
	TASKLET_SOFTIRQ,
	SCHED_SOFTIRQ,
	HRTIMER_SOFTIRQ,
	RCU_SOFTIRQ,    /* Preferable RCU should always be the last softirq */

	NR_SOFTIRQS
};

/*
 * The following vectors can be safely ignored after ksoftirqd is parked:
 *
 * _ RCU:
 * 	1) rcutree_migrate_callbacks() migrates the queue.
 * 	2) rcu_report_dead() reports the final quiescent states.
 *
 * _ IRQ_POLL: irq_poll_cpu_dead() migrates the queue
 */
#define SOFTIRQ_HOTPLUG_SAFE_MASK (BIT(RCU_SOFTIRQ) | BIT(IRQ_POLL_SOFTIRQ))

#endif
