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

#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/lockdep.h>
#include <linux/percpu-rwlock.h>
#include <linux/errno.h>


int __percpu_init_rwlock(struct percpu_rwlock *pcpu_rwlock,
			 const char *name, struct lock_class_key *rwlock_key)
{
	/* ->global_rwlock represents the whole percpu_rwlock for lockdep */
#ifdef CONFIG_DEBUG_SPINLOCK
	__rwlock_init(&pcpu_rwlock->global_rwlock, name, rwlock_key);
#else
	pcpu_rwlock->global_rwlock =
			__RW_LOCK_UNLOCKED(&pcpu_rwlock->global_rwlock);
#endif
	return 0;
}

void percpu_read_lock(struct percpu_rwlock *pcpu_rwlock)
{
	read_lock(&pcpu_rwlock->global_rwlock);
}

void percpu_read_unlock(struct percpu_rwlock *pcpu_rwlock)
{
	read_unlock(&pcpu_rwlock->global_rwlock);
}

void percpu_write_lock(struct percpu_rwlock *pcpu_rwlock)
{
	write_lock(&pcpu_rwlock->global_rwlock);
}

void percpu_write_unlock(struct percpu_rwlock *pcpu_rwlock)
{
	write_unlock(&pcpu_rwlock->global_rwlock);
}

