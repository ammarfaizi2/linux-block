#ifndef _ASM_GENERIC_SYSLET_ABI_H
#define _ASM_GENERIC_SYSLET_ABI_H

/*
 * I'm assuming that a u64 ip and u64 esp won't be enough for all
 * archs, so I just let each arch define its own.
 */
struct syslet_frame {
};

#endif
