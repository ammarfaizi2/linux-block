/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PERCPU_COUNTER_TYPES_H
#define _LINUX_PERCPU_COUNTER_TYPES_H
/*
 * A simple "approximate counter" for use in ext2 and ext3 superblocks.
 *
 * WARNING: these things are HUGE.  4 kbytes per counter on 32-way P4.
 */

#include <linux/spinlock_types.h>

#ifdef CONFIG_SMP

struct percpu_counter {
	raw_spinlock_t lock;
	s64 count;
#ifdef CONFIG_HOTPLUG_CPU
	struct list_head list;	/* All percpu_counters are on a list */
#endif
	s32 __percpu *counters;
};

#else /* !CONFIG_SMP */

struct percpu_counter {
	s64 count;
};

#endif	/* CONFIG_SMP */

#endif /* _LINUX_PERCPU_COUNTER_TYPES_H */
