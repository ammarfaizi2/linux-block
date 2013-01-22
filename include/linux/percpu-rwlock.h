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
	unsigned long __percpu	*reader_refcnt;
	bool __percpu		*writer_signal;
	rwlock_t		global_rwlock;
};

extern void percpu_read_lock_irqsafe(struct percpu_rwlock *);
extern void percpu_read_unlock_irqsafe(struct percpu_rwlock *);

extern void percpu_write_lock_irqsave(struct percpu_rwlock *,
				      unsigned long *flags);
extern void percpu_write_unlock_irqrestore(struct percpu_rwlock *,
					   unsigned long *flags);

extern int __percpu_init_rwlock(struct percpu_rwlock *,
				const char *, struct lock_class_key *);

extern void percpu_free_rwlock(struct percpu_rwlock *);


#define __PERCPU_RWLOCK_INIT(name)					\
	{								\
		.reader_refcnt = &name##_reader_refcnt,			\
		.writer_signal = &name##_writer_signal,			\
		.global_rwlock = __RW_LOCK_UNLOCKED(name.global_rwlock) \
	}

#define DEFINE_PERCPU_RWLOCK(name)					\
	static DEFINE_PER_CPU(unsigned long, name##_reader_refcnt);	\
	static DEFINE_PER_CPU(bool, name##_writer_signal);		\
	struct percpu_rwlock (name) = __PERCPU_RWLOCK_INIT(name);

#define DEFINE_STATIC_PERCPU_RWLOCK(name)				\
	static DEFINE_PER_CPU(unsigned long, name##_reader_refcnt);	\
	static DEFINE_PER_CPU(bool, name##_writer_signal);		\
	static struct percpu_rwlock(name) = __PERCPU_RWLOCK_INIT(name);

#define percpu_init_rwlock(pcpu_rwlock)					\
({	static struct lock_class_key rwlock_key;			\
	__percpu_init_rwlock(pcpu_rwlock, #pcpu_rwlock, &rwlock_key);	\
})

#define READER_PRESENT		(1UL << 16)
#define READER_REFCNT_MASK	(READER_PRESENT - 1)

#define reader_uses_percpu_refcnt(pcpu_rwlock, cpu)			\
		(ACCESS_ONCE(per_cpu(*((pcpu_rwlock)->reader_refcnt), cpu)))

#define reader_nested_percpu(pcpu_rwlock)				\
	(__this_cpu_read(*((pcpu_rwlock)->reader_refcnt)) & READER_REFCNT_MASK)

#define writer_active(pcpu_rwlock)					\
			(__this_cpu_read(*((pcpu_rwlock)->writer_signal)))

#endif

