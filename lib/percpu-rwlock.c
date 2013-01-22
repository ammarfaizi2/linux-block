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
	pcpu_rwlock->reader_refcnt = alloc_percpu(unsigned long);
	if (unlikely(!pcpu_rwlock->reader_refcnt))
		return -ENOMEM;

	pcpu_rwlock->writer_signal = alloc_percpu(bool);
	if (unlikely(!pcpu_rwlock->writer_signal)) {
		free_percpu(pcpu_rwlock->reader_refcnt);
		pcpu_rwlock->reader_refcnt = NULL;
		return -ENOMEM;
	}

	/* ->global_rwlock represents the whole percpu_rwlock for lockdep */
#ifdef CONFIG_DEBUG_SPINLOCK
	__rwlock_init(&pcpu_rwlock->global_rwlock, name, rwlock_key);
#else
	pcpu_rwlock->global_rwlock =
			__RW_LOCK_UNLOCKED(&pcpu_rwlock->global_rwlock);
#endif
	return 0;
}

void percpu_free_rwlock(struct percpu_rwlock *pcpu_rwlock)
{
	free_percpu(pcpu_rwlock->reader_refcnt);
	free_percpu(pcpu_rwlock->writer_signal);

	/* Catch use-after-free bugs */
	pcpu_rwlock->reader_refcnt = NULL;
	pcpu_rwlock->writer_signal = NULL;
}

void percpu_read_lock_irqsafe(struct percpu_rwlock *pcpu_rwlock)
{
	preempt_disable();

	/* First and foremost, let the writer know that a reader is active */
	this_cpu_add(*pcpu_rwlock->reader_refcnt, READER_PRESENT);

	/*
	 * If we are already using per-cpu refcounts, it is not safe to switch
	 * the synchronization scheme. So continue using the refcounts.
	 */
	if (reader_nested_percpu(pcpu_rwlock)) {
		this_cpu_inc(*pcpu_rwlock->reader_refcnt);
	} else {
		/*
		 * The write to 'reader_refcnt' must be visible before we
		 * read 'writer_signal'.
		 */
		smp_mb(); /* Paired with smp_rmb() in sync_reader() */

		if (likely(!writer_active(pcpu_rwlock))) {
			this_cpu_inc(*pcpu_rwlock->reader_refcnt);

			/* Pretend that we take global_rwlock for lockdep */
			rwlock_acquire_read(&pcpu_rwlock->global_rwlock.dep_map,
					    0, 0, _RET_IP_);
		} else {
			/* Writer is active, so switch to global rwlock. */

			/*
			 * While we are spinning on ->global_rwlock, an
			 * interrupt can hit us, and the interrupt handler
			 * might call this function. The distinction between
			 * READER_PRESENT and the refcnt helps ensure that the
			 * interrupt handler also takes this branch and spins
			 * on the ->global_rwlock, as long as the writer is
			 * active.
			 */
			read_lock(&pcpu_rwlock->global_rwlock);

			/*
			 * We might have raced with a writer going inactive
			 * before we took the read-lock. So re-evaluate whether
			 * we still need to hold the rwlock or if we can switch
			 * back to per-cpu refcounts. (This also helps avoid
			 * heterogeneous nesting of readers).
			 */
			if (!writer_active(pcpu_rwlock)) {
				this_cpu_inc(*pcpu_rwlock->reader_refcnt);
				read_unlock(&pcpu_rwlock->global_rwlock);

				/*
				 * Pretend that we take global_rwlock for lockdep
				 */
				rwlock_acquire_read(&pcpu_rwlock->global_rwlock.dep_map,
						    0, 0, _RET_IP_);
			}
		}
	}

	this_cpu_sub(*pcpu_rwlock->reader_refcnt, READER_PRESENT);

	/* Prevent reordering of any subsequent reads */
	smp_rmb();
}

void percpu_read_unlock_irqsafe(struct percpu_rwlock *pcpu_rwlock)
{
	/*
	 * We never allow heterogeneous nesting of readers. So it is trivial
	 * to find out the kind of reader we are, and undo the operation
	 * done by our corresponding percpu_read_lock().
	 */
	if (reader_nested_percpu(pcpu_rwlock)) {
		this_cpu_dec(*pcpu_rwlock->reader_refcnt);
		smp_wmb(); /* Paired with smp_rmb() in sync_reader() */

		/*
		 * If this is the last decrement, then it is time to pretend
		 * to lockdep that we are releasing the read lock.
		 */
		if (!reader_nested_percpu(pcpu_rwlock))
			rwlock_release(&pcpu_rwlock->global_rwlock.dep_map,
				       1, _RET_IP_);
	} else {
		read_unlock(&pcpu_rwlock->global_rwlock);
	}

	preempt_enable();
}

static inline void raise_writer_signal(struct percpu_rwlock *pcpu_rwlock,
				       unsigned int cpu)
{
	per_cpu(*pcpu_rwlock->writer_signal, cpu) = true;
}

static inline void drop_writer_signal(struct percpu_rwlock *pcpu_rwlock,
				      unsigned int cpu)
{
	per_cpu(*pcpu_rwlock->writer_signal, cpu) = false;
}

static void announce_writer_active(struct percpu_rwlock *pcpu_rwlock)
{
	unsigned int cpu;

	for_each_online_cpu(cpu)
		raise_writer_signal(pcpu_rwlock, cpu);

	smp_mb(); /* Paired with smp_rmb() in percpu_read_[un]lock() */
}

static void announce_writer_inactive(struct percpu_rwlock *pcpu_rwlock)
{
	unsigned int cpu;

	drop_writer_signal(pcpu_rwlock, smp_processor_id());

	for_each_online_cpu(cpu)
		drop_writer_signal(pcpu_rwlock, cpu);

	smp_mb(); /* Paired with smp_rmb() in percpu_read_[un]lock() */
}

/*
 * Wait for the reader to see the writer's signal and switch from percpu
 * refcounts to global rwlock.
 *
 * If the reader is still using percpu refcounts, wait for him to switch.
 * Else, we can safely go ahead, because either the reader has already
 * switched over, or the next reader that comes along on that CPU will
 * notice the writer's signal and will switch over to the rwlock.
 */
static inline void sync_reader(struct percpu_rwlock *pcpu_rwlock,
			       unsigned int cpu)
{
	smp_rmb(); /* Paired with smp_[w]mb() in percpu_read_[un]lock() */

	while (reader_uses_percpu_refcnt(pcpu_rwlock, cpu))
		cpu_relax();
}

static void sync_all_readers(struct percpu_rwlock *pcpu_rwlock)
{
	unsigned int cpu;

	for_each_online_cpu(cpu)
		sync_reader(pcpu_rwlock, cpu);
}

void percpu_write_lock_irqsave(struct percpu_rwlock *pcpu_rwlock,
			       unsigned long *flags)
{
	/*
	 * Tell all readers that a writer is becoming active, so that they
	 * start switching over to the global rwlock.
	 */
	announce_writer_active(pcpu_rwlock);
	sync_all_readers(pcpu_rwlock);
	write_lock_irqsave(&pcpu_rwlock->global_rwlock, *flags);
	this_cpu_inc(*pcpu_rwlock->reader_refcnt);
}

void percpu_write_unlock_irqrestore(struct percpu_rwlock *pcpu_rwlock,
			 unsigned long *flags)
{
	this_cpu_dec(*pcpu_rwlock->reader_refcnt);

	/*
	 * Inform all readers that we are done, so that they can switch back
	 * to their per-cpu refcounts. (We don't need to wait for them to
	 * see it).
	 */
	announce_writer_inactive(pcpu_rwlock);
	write_unlock_irqrestore(&pcpu_rwlock->global_rwlock, *flags);
}

