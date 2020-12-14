#ifndef _ASM_POWERPC_MEMBARRIER_H
#define _ASM_POWERPC_MEMBARRIER_H

#include <asm/barrier.h>

/*
 * The RFI family of instructions are context synchronising, and
 * that is how we return to userspace, so nothing is required here.
 */
static inline void membarrier_sync_core_before_usermode(void)
{
}

#endif /* _ASM_POWERPC_MEMBARRIER_H */
