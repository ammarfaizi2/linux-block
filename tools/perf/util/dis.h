#ifndef DIS_H
#define DIS_H 1

#include <stdbool.h>
#include <linux/types.h>

struct thread;

#define MAXINSN 15

struct perf_dis {
	/* Initialized by callers: */
	struct thread *thread;
	u8	      cpumode;
	int	      cpu;
	bool	      is64bit;
	/* Temporary */
	char	      out[256];
};

char *disas_inst(struct perf_dis *x, uint64_t ip, u8 *inbuf, int inlen, int *lenp);

#endif
