// SPDX-License-Identifier: GPL-2.0

#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#define REQ_OP_READ	0
#define REQ_OP_WRITE	1
#define REQ_OP_BITS	8
#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)

#define LCOEF_RSEQIO	14663889
#define LCOEF_RRANDIO	248752010
#define LCOEF_RPAGE	28151808
#define LCOEF_WSEQIO	32671670
#define LCOEF_WRANDIO	63150006
#define LCOEF_WPAGE	7323648

#define RAND_IO_CUTOFF	10

SEC("io_cost")
int func(struct bpf_io_cost *ctx)
{
	int op;
	__u64 seqio, randio, page;
	__s64 delta;

	switch (ctx->opf & REQ_OP_MASK) {
	case REQ_OP_READ:
		seqio = LCOEF_RSEQIO;
		randio = LCOEF_RRANDIO;
		page = LCOEF_RPAGE;
		break;
	case REQ_OP_WRITE:
		seqio = LCOEF_WSEQIO;
		randio = LCOEF_WRANDIO;
		page = LCOEF_WPAGE;
		break;
	default:
		return 0;
	}

	delta = ctx->sector - ctx->last_sector;
	if (delta >= -RAND_IO_CUTOFF && delta <= RAND_IO_CUTOFF)
		ctx->cost += seqio;
	else
		ctx->cost += randio;
	if (!ctx->is_merge)
		ctx->cost += page * (ctx->nr_sectors >> 3);

	return 0;
}
