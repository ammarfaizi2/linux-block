/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TASKLET_TYPES_H
#define _LINUX_TASKLET_TYPES_H

#include <linux/atomic_types.h>

struct tasklet_struct
{
	struct tasklet_struct *next;
	unsigned long state;
	atomic_t count;
	bool use_callback;
	union {
		void (*func)(unsigned long data);
		void (*callback)(struct tasklet_struct *t);
	};
	unsigned long data;
};

#endif /* _LINUX_TASKLET_TYPES_H */
