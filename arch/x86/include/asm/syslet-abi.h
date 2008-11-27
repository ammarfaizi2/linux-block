#ifndef __ASM_X86_SYSLET_ABI_H
#define __ASM_X86_SYSLET_ABI_H

struct syslet_frame {
	u64 ip;
	u64 sp;
};

#endif
