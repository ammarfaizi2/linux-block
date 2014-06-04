#include <stdio.h>
#include <limits.h>
#include "spark.h"

#define NUM_SPARKS 8
#define SPARK_SHIFT 8

/* Print spark lines on outf for numval values in val. */
void print_spark(FILE *outf, unsigned long long *val, int numval)
{
	static const char *ticks[NUM_SPARKS] = {
		"▁",  "▂", "▃", "▄", "▅", "▆", "▇", "█"
	};
	int i;
	unsigned long long min = ULLONG_MAX, max = 0, f;

	for (i = 0; i < numval; i++) {
		if (val[i] < min)
			min = val[i];
		if (val[i] > max)
			max = val[i];
	}
	f = ((max - min) << SPARK_SHIFT) / (NUM_SPARKS - 1);
	if (f < 1)
		f = 1;
	for (i = 0; i < numval; i++) {
		int index = ((val[i] - min) << SPARK_SHIFT) / f;
		if (index >= 0 && index < NUM_SPARKS)
			fputs(ticks[index], outf);
	}
}
