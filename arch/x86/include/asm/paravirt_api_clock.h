/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PARAVIRT_API_CLOCK_H
#define _ASM_X86_PARAVIRT_API_CLOCK_H

#include <asm/paravirt.h>

#include <linux/static_call_types.h>

u64 dummy_steal_clock(int cpu);
u64 dummy_sched_clock(void);

DECLARE_STATIC_CALL(pv_steal_clock, dummy_steal_clock);
DECLARE_STATIC_CALL(pv_sched_clock, dummy_sched_clock);

void paravirt_set_sched_clock(u64 (*func)(void));

static inline u64 paravirt_sched_clock(void)
{
	return static_call(pv_sched_clock)();
}

static inline u64 paravirt_steal_clock(int cpu)
{
	return static_call(pv_steal_clock)(cpu);
}

#endif /* _ASM_X86_PARAVIRT_API_CLOCK_H */
