/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_U64_STATS_SYNC_TYPES_H
#define _LINUX_U64_STATS_SYNC_TYPES_H

#include <linux/types.h>

#include <asm/bitsperlong.h>

#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
#include <linux/seqlock_types.h>
#endif

struct u64_stats_sync {
#if BITS_PER_LONG == 32 && (defined(CONFIG_SMP) || defined(CONFIG_PREEMPT_RT))
	seqcount_t	seq;
#endif
};

#if BITS_PER_LONG == 64
#include <asm/local64.h>

typedef struct {
	local64_t	v;
} u64_stats_t ;

#else

typedef struct {
	u64		v;
} u64_stats_t;

#endif

#endif /* _LINUX_U64_STATS_SYNC_TYPES_H */
