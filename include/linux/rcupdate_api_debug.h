/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __LINUX_RCUPDATE_API_DEBUG_H
#define __LINUX_RCUPDATE_API_DEBUG_H

#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/lockdep_api.h>
#include <linux/kernel.h>

#ifdef CONFIG_DEBUG_LOCK_ALLOC

static inline void rcu_lock_acquire(struct lockdep_map *map)
{
	lock_acquire(map, 0, 0, 2, 0, NULL, _THIS_IP_);
}

static inline void rcu_lock_release(struct lockdep_map *map)
{
	lock_release(map, _THIS_IP_);
}

int debug_lockdep_rcu_enabled(void);
int rcu_read_lock_held(void);
int rcu_read_lock_bh_held(void);
int rcu_read_lock_sched_held(void);
int rcu_read_lock_any_held(void);

#else /* #ifdef CONFIG_DEBUG_LOCK_ALLOC */

# define rcu_lock_acquire(a)		do { } while (0)
# define rcu_lock_release(a)		do { } while (0)

static inline int rcu_read_lock_held(void)
{
	return 1;
}

static inline int rcu_read_lock_bh_held(void)
{
	return 1;
}

static inline int rcu_read_lock_sched_held(void)
{
	return !preemptible();
}

static inline int rcu_read_lock_any_held(void)
{
	return !preemptible();
}

#endif /* #else #ifdef CONFIG_DEBUG_LOCK_ALLOC */

#endif /* __LINUX_RCUPDATE_API_DEBUG_H */
