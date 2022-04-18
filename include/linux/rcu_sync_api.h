/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * RCU-based infrastructure for lightweight reader-writer locking
 *
 * Copyright (c) 2015, Red Hat, Inc.
 *
 * Author: Oleg Nesterov <oleg@redhat.com>
 */

#ifndef _LINUX_RCU_SYNC_API_H_
#define _LINUX_RCU_SYNC_API_H_

#include <linux/rcu_sync_types.h>

#include <linux/rcupdate.h>
#include <linux/rcupdate_api_debug.h>
#include <linux/irqflags.h>

/**
 * rcu_sync_is_idle() - Are readers permitted to use their fastpaths?
 * @rsp: Pointer to rcu_sync structure to use for synchronization
 *
 * Returns true if readers are permitted to use their fastpaths.  Must be
 * invoked within some flavor of RCU read-side critical section.
 */
static inline bool rcu_sync_is_idle(struct rcu_sync *rsp)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_any_held(),
			 "suspicious rcu_sync_is_idle() usage");
	return !READ_ONCE(rsp->gp_state); /* GP_IDLE */
}

extern void rcu_sync_enter_start(struct rcu_sync *);
extern void rcu_sync_enter(struct rcu_sync *);
extern void rcu_sync_exit(struct rcu_sync *);
extern void rcu_sync_dtor(struct rcu_sync *);

#endif /* _LINUX_RCU_SYNC_API_H_ */
