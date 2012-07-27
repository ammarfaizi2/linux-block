#ifndef __PERF_REGS_H
#define __PERF_REGS_H

#ifndef NO_PERF_REGS_DEFS
#include <perf_regs.h>
#else
#define PERF_REGS_MASK	0

static inline const char *perf_reg_name(int id __used)
{
	return NULL;
}
#endif /* NO_PERF_REGS_DEFS */
#endif /* __PERF_REGS_H */
