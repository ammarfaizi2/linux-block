/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PAGEFAULT_CTRL__
#define __LINUX_PAGEFAULT_CTRL__

#include <linux/sched.h>

DECLARE_PER_TASK(int, pagefault_disabled);

static __always_inline void pagefault_disabled_inc(void)
{
	per_task(current, pagefault_disabled)++;
}

static __always_inline void pagefault_disabled_dec(void)
{
	per_task(current, pagefault_disabled)--;
}

/*
 * These routines enable/disable the pagefault handler. If disabled, it will
 * not take any locks and go straight to the fixup table.
 *
 * User access methods will not sleep when called from a pagefault_disabled()
 * environment.
 */
static inline void pagefault_disable(void)
{
	pagefault_disabled_inc();
	/*
	 * make sure to have issued the store before a pagefault
	 * can hit.
	 */
	barrier();
}

static inline void pagefault_enable(void)
{
	/*
	 * make sure to issue those last loads/stores before enabling
	 * the pagefault handler again.
	 */
	barrier();
	pagefault_disabled_dec();
}

/*
 * Is the pagefault handler disabled? If so, user access methods will not sleep.
 */
static inline bool pagefault_disabled(void)
{
	return per_task(current, pagefault_disabled) != 0;
}

/*
 * The pagefault handler is in general disabled by pagefault_disable() or
 * when in irq context (via in_atomic()).
 *
 * This function should only be used by the fault handlers. Other users should
 * stick to pagefault_disabled().
 * Please NEVER use preempt_disable() to disable the fault handler. With
 * !CONFIG_PREEMPT_COUNT, this is like a NOP. So the handler won't be disabled.
 * in_atomic() will report different values based on !CONFIG_PREEMPT_COUNT.
 */
#define faulthandler_disabled() (pagefault_disabled() || in_atomic())

#endif /* __LINUX_PAGEFAULT_CTRL__ */
