/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_DQL_TYPES_H
#define _LINUX_DQL_TYPES_H

#include <linux/cache.h>

struct dql {
	/* Fields accessed in enqueue path (dql_queued) */
	unsigned int	num_queued;		/* Total ever queued */
	unsigned int	adj_limit;		/* limit + num_completed */
	unsigned int	last_obj_cnt;		/* Count at last queuing */

	/* Fields accessed only by completion path (dql_completed) */

	unsigned int	limit ____cacheline_aligned_in_smp; /* Current limit */
	unsigned int	num_completed;		/* Total ever completed */

	unsigned int	prev_ovlimit;		/* Previous over limit */
	unsigned int	prev_num_queued;	/* Previous queue total */
	unsigned int	prev_last_obj_cnt;	/* Previous queuing cnt */

	unsigned int	lowest_slack;		/* Lowest slack found */
	unsigned long	slack_start_time;	/* Time slacks seen */

	/* Configuration */
	unsigned int	max_limit;		/* Max limit */
	unsigned int	min_limit;		/* Minimum limit */
	unsigned int	slack_hold_time;	/* Time to measure slack */
};

#endif /* _LINUX_DQL_TYPES_H */
