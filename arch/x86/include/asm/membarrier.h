#ifndef _ASM_X86_MEMBARRIER_H
#define _ASM_X86_MEMBARRIER_H

#include <asm/sync_core.h>

/*
 * Ensure that the CPU notices any instruction changes before the next time
 * it returns to usermode.
 */
static inline void membarrier_sync_core_before_usermode(void)
{
	/* With PTI, we unconditionally serialize before running user code. */
	if (static_cpu_has(X86_FEATURE_PTI))
		return;

	/*
	 * Even if we're in an interrupt, we might reschedule before returning,
	 * in which case we could switch to a different thread in the same mm
	 * and return using SYSRET or SYSEXIT.  Instead of trying to keep
	 * track of our need to sync the core, just sync right away.
	 */
	sync_core();
}

#endif /* _ASM_X86_MEMBARRIER_H */
