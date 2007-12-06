#ifndef _LINUX_SYSLET_ABI_H
#define _LINUX_SYSLET_ABI_H

#include <asm/syslet-abi.h> /* for struct syslet_frame */

struct syslet_args {
	u64 completion_ring_ptr;
	u64 caller_data;
	struct syslet_frame frame;
};

struct syslet_completion {
	u64 status;
	u64 caller_data;
};

/*
 * The ring follows the "wrapping" convention as described by Andrew at:
 * 	http://lkml.org/lkml/2007/4/11/276
 * The head is updated by the kernel as completions are added and the
 * tail is updated by userspace as completions are removed.
 *
 * The number of elements must be a power of two and the ring must be
 * aligned to a u64.
 */
struct syslet_ring {
	u32 kernel_head;
	u32 user_tail;
	u32 elements;
	u32 wait_group;
	struct syslet_completion comp[0];
};

#endif
