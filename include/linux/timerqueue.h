/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIMERQUEUE_H
#define _LINUX_TIMERQUEUE_H

#include <linux/rbtree_types.h>
#include <linux/ktime.h>

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

struct timerqueue_head {
	struct rb_root_cached rb_root;
};

#endif /* _LINUX_TIMERQUEUE_H */
