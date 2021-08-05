/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * RCU-based infrastructure for lightweight reader-writer locking
 *
 * Copyright (c) 2015, Red Hat, Inc.
 *
 * Author: Oleg Nesterov <oleg@redhat.com>
 */

#ifndef _LINUX_RCU_SYNC_TYPES_H_
#define _LINUX_RCU_SYNC_TYPES_H_

#include <linux/wait_types.h>

/* Structure to mediate between updaters and fastpath-using readers.  */
struct rcu_sync {
	int			gp_state;
	int			gp_count;
	wait_queue_head_t	gp_wait;

	struct rcu_head		cb_head;
};

#define __RCU_SYNC_INITIALIZER(name) {					\
		.gp_state = 0,						\
		.gp_count = 0,						\
		.gp_wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.gp_wait),	\
	}

#define	DEFINE_RCU_SYNC(name)	\
	struct rcu_sync name = __RCU_SYNC_INITIALIZER(name)

extern void rcu_sync_init(struct rcu_sync *);

#endif /* _LINUX_RCU_SYNC_TYPES_H_ */
