// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>

long negative = -1023;

static int just_crash(void)
{
	/* Leak some memory. */
	long *p = kmalloc(1 << 30, GFP_KERNEL);

	/* Try our best to deadlock. */
	p = (void *)p[negative];
	spin_lock((spinlock_t*)p);

	/* If that doesn't break anything, then I give up. */
	panic("Please don't merge this");

	return -EOWNERDEAD;
}

module_init(just_crash);
MODULE_AUTHOR("Not me! <help@riscv.org>");
MODULE_DESCRIPTION("Just crashes");
MODULE_LICENSE("GPL v2");
