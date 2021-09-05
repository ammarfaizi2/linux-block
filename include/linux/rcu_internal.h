/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __LINUX_RCU_INTERNAL_H
#define __LINUX_RCU_INTERNAL_H

/*
 * Internal APIs between the RCU subsystem and core kernel facilities.
 */

#include <linux/sched/per_task.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>

DECLARE_PER_TASK(refcount_t, rcu_users);

#endif /* __LINUX_RCU_INTERNAL_H */
