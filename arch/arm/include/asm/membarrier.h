/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM_MEMBARRIER_H
#define _ASM_ARM_MEMBARRIER_H

#include <asm/barrier.h>

/*
 * On arm, anyone trying to use membarrier() to handle JIT code is required
 * to first flush the icache (most likely by using cacheflush(2) and then
 * do SYNC_CORE.  All that's needed after the icache flush is to execute a
 * "context synchronization event".
 *
 * Returning to user mode is a context synchronization event, so no
 * specific action by the kernel is needed other than ensuring that the
 * kernel is entered.
 */
static inline void membarrier_sync_core_before_usermode(void)
{
}

#endif /* _ASM_ARM_MEMBARRIER_H */
