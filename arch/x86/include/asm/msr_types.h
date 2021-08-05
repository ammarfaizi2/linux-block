/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MSR_TYPES_H
#define _ASM_X86_MSR_TYPES_H

#ifndef __ASSEMBLY__

#include <linux/types.h>

struct msr {
	union {
		struct {
			u32 l;
			u32 h;
		};
		u64 q;
	};
};

struct msr_info {
	u32 msr_no;
	struct msr reg;
	struct msr *msrs;
	int err;
};

struct msr_regs_info {
	u32 *regs;
	int err;
};

struct saved_msr {
	bool valid;
	struct msr_info info;
};

struct saved_msrs {
	unsigned int num;
	struct saved_msr *array;
};
#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_MSR_TYPES_H */
