/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_U64_STATS_SYNC_TYPES_H
#define _LINUX_U64_STATS_SYNC_TYPES_H

#include <asm/bitsperlong.h>

#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
#include <linux/seqlock_types.h>
#endif

struct u64_stats_sync {
#if BITS_PER_LONG == 32 && (defined(CONFIG_SMP) || defined(CONFIG_PREEMPT_RT))
	seqcount_t	seq;
#endif
};

#endif /* _LINUX_U64_STATS_SYNC_TYPES_H */
