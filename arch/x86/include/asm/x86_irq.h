/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_X86_IRQ_H
#define _ASM_X86_X86_IRQ_H

#include <linux/irqdesc.h>
#include <linux/percpu.h>

#include <linux/smp.h>

#include <linux/atomic.h>
#include <asm/sections.h>
#include <asm/hw_irq.h>

#ifdef	CONFIG_X86_LOCAL_APIC
extern struct irq_cfg *irq_cfg(unsigned int irq);
extern struct irq_cfg *irqd_cfg(struct irq_data *irq_data);
extern void lock_vector_lock(void);
extern void unlock_vector_lock(void);
#ifdef CONFIG_SMP
extern void send_cleanup_vector(struct irq_cfg *);
extern void irq_complete_move(struct irq_cfg *cfg);
#else
static inline void send_cleanup_vector(struct irq_cfg *c) { }
static inline void irq_complete_move(struct irq_cfg *c) { }
#endif

extern void apic_ack_edge(struct irq_data *data);
#else	/*  CONFIG_X86_LOCAL_APIC */
static inline void lock_vector_lock(void) {}
static inline void unlock_vector_lock(void) {}
#endif	/* CONFIG_X86_LOCAL_APIC */

extern void elcr_set_level_irq(unsigned int irq);

extern char irq_entries_start[];
#ifdef CONFIG_TRACING
#define trace_irq_entries_start irq_entries_start
#endif

extern char spurious_entries_start[];

#define VECTOR_UNUSED		NULL
#define VECTOR_SHUTDOWN		((void *)-1L)
#define VECTOR_RETRIGGERED	((void *)-2L)

typedef struct irq_desc* vector_irq_t[NR_VECTORS];
DECLARE_PER_CPU(vector_irq_t, vector_irq);

#endif /* _ASM_X86_X86_IRQ_H */
