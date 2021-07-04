/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KERNEL_STAT_TYPES_H
#define _LINUX_KERNEL_STAT_TYPES_H

#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
# include <linux/spinlock_types.h>
#endif

/**
 * struct prev_cputime - snapshot of system and user cputime
 * @utime: time spent in user mode
 * @stime: time spent in system mode
 * @lock: protects the above two fields
 *
 * Stores previous user/system time values such that we can guarantee
 * monotonicity.
 */
struct prev_cputime {
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
	u64				utime;
	u64				stime;
	raw_spinlock_t			lock;
#endif
};

#endif /* _LINUX_KERNEL_STAT_TYPES_H */
