/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MEMBARRIER_H
#define _ASM_ARM64_MEMBARRIER_H

#include <asm/barrier.h>

/*
 * On arm64, anyone trying to use membarrier() to handle JIT code is
 * required to first flush the icache and then do SYNC_CORE.  All that's
 * needed after the icache flush is to execute a "context synchronization
 * event".  Right now, ERET does this, and we are guaranteed to ERET before
 * any user code runs.  If Linux ever programs the CPU to make ERET stop
 * being a context synchronizing event, then this will need to be adjusted.
 */
static inline void membarrier_sync_core_before_usermode(void)
{
}

#endif /* _ASM_ARM64_MEMBARRIER_H */
