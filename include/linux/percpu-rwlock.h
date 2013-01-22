/*
 * Flexible Per-CPU Reader-Writer Locks
 * (with relaxed locking rules and reduced deadlock-possibilities)
 *
 * Copyright (C) IBM Corporation, 2012-2013
 * Author: Srivatsa S. Bhat <srivatsa.bhat@linux.vnet.ibm.com>
 *
 * With lots of invaluable suggestions from:
 * 	   Oleg Nesterov <oleg@redhat.com>
 * 	   Tejun Heo <tj@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _LINUX_PERCPU_RWLOCK_H
#define _LINUX_PERCPU_RWLOCK_H

#include <linux/percpu.h>
#include <linux/lockdep.h>
#include <linux/spinlock.h>

struct percpu_rwlock {
	rwlock_t		global_rwlock;
};

extern void percpu_read_lock(struct percpu_rwlock *);
extern void percpu_read_unlock(struct percpu_rwlock *);

extern void percpu_write_lock(struct percpu_rwlock *);
extern void percpu_write_unlock(struct percpu_rwlock *);

extern int __percpu_init_rwlock(struct percpu_rwlock *,
				const char *, struct lock_class_key *);

#define percpu_init_rwlock(pcpu_rwlock)					\
({	static struct lock_class_key rwlock_key;			\
	__percpu_init_rwlock(pcpu_rwlock, #pcpu_rwlock, &rwlock_key);	\
})

#endif
