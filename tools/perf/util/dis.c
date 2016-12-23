#include "perf.h"
#include "dis.h"
#include "util.h"

/* Fallback for architectures with no disassembler */

__weak char *disas_inst(struct perf_dis *x, uint64_t ip __maybe_unused,
			u8 *inbuf __maybe_unused, int inlen __maybe_unused,
			int *lenp)
{
	if (lenp)
		*lenp = 0;
	strcpy(x->out, "?");
	return x->out;
}
