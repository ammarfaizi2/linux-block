#include <math.h>
#include <stdio.h>

#include "stat.h"
#include "spark.h"

void update_stats(struct stats *stats, u64 val)
{
	double delta;
	int n = stats->n;

	if (n < NUM_SPARK_VALS)
		stats->svals[n] = val;

	stats->n++;
	delta = val - stats->mean;
	stats->mean += delta / stats->n;
	stats->M2 += delta*(val - stats->mean);

	if (val > stats->max)
		stats->max = val;

	if (val < stats->min)
		stats->min = val;
}

double avg_stats(struct stats *stats)
{
	return stats->mean;
}

/*
 * http://en.wikipedia.org/wiki/Algorithms_for_calculating_variance
 *
 *       (\Sum n_i^2) - ((\Sum n_i)^2)/n
 * s^2 = -------------------------------
 *                  n - 1
 *
 * http://en.wikipedia.org/wiki/Stddev
 *
 * The std dev of the mean is related to the std dev by:
 *
 *             s
 * s_mean = -------
 *          sqrt(n)
 *
 */
double stddev_stats(struct stats *stats)
{
	double variance, variance_mean;

	if (stats->n < 2)
		return 0.0;

	variance = stats->M2 / (stats->n - 1);
	variance_mean = variance / stats->n;

	return sqrt(variance_mean);
}

double rel_stddev_stats(double stddev, double avg)
{
	double pct = 0.0;

	if (avg)
		pct = 100.0 * stddev/avg;

	return pct;
}

static int all_zero(unsigned long long *vals, int len)
{
	int i;

	for (i = 0; i < len; i++)
		if (vals[i] != 0)
			return 0;
	return 1;
}

void print_stat_spark(FILE *f, struct stats *stat)
{
	int len;

	if (stat->n <= 1)
		return;

	len = stat->n;
	if (len > NUM_SPARK_VALS)
		len = NUM_SPARK_VALS;
	if (all_zero(stat->svals, len))
		return;

	print_spark(f, stat->svals, len);
	if (stat->n > NUM_SPARK_VALS)
		fputs("..", f);
}
