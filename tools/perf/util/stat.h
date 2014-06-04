#ifndef __PERF_STATS_H
#define __PERF_STATS_H

#include <stdio.h>
#include <linux/types.h>

#define NUM_SPARK_VALS 8 /* support spark line on first N items */

struct stats
{
	double n, mean, M2;
	u64 max, min;
	unsigned long long svals[NUM_SPARK_VALS];
};

void update_stats(struct stats *stats, u64 val);
double avg_stats(struct stats *stats);
double stddev_stats(struct stats *stats);
double rel_stddev_stats(double stddev, double avg);

void print_stat_spark(FILE *f, struct stats *stat);

static inline void init_stats(struct stats *stats)
{
	int i;

	stats->n    = 0.0;
	stats->mean = 0.0;
	stats->M2   = 0.0;
	stats->min  = (u64) -1;
	stats->max  = 0;
	for (i = 0; i < NUM_SPARK_VALS; i++)
		stats->svals[i] = 0;
}
#endif
