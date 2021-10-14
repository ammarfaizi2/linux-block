/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NOTIFIER_TYPES_H
#define _LINUX_NOTIFIER_TYPES_H

struct notifier_block;

typedef	int (*notifier_fn_t)(struct notifier_block *nb,
			unsigned long action, void *data);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block __rcu *next;
	int priority;
};

#endif /* _LINUX_NOTIFIER_TYPES_H */
