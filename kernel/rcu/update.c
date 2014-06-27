/*
 * Read-Copy Update mechanism for mutual exclusion
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can access it online at
 * http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * Copyright IBM Corporation, 2001
 *
 * Authors: Dipankar Sarma <dipankar@in.ibm.com>
 *	    Manfred Spraul <manfred@colorfullife.com>
 *
 * Based on the original work by Paul McKenney <paulmck@us.ibm.com>
 * and inputs from Rusty Russell, Andrea Arcangeli and Andi Kleen.
 * Papers:
 * http://www.rdrop.com/users/paulmck/paper/rclockpdcsproof.pdf
 * http://lse.sourceforge.net/locking/rclock_OLS.2001.05.01c.sc.pdf (OLS2001)
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 *		http://lse.sourceforge.net/locking/rcupdate.html
 *
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/mutex.h>
#include <linux/export.h>
#include <linux/hardirq.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kthread.h>

#define CREATE_TRACE_POINTS

#include "rcu.h"

MODULE_ALIAS("rcupdate");
#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "rcupdate."

module_param(rcu_expedited, int, 0);

#ifdef CONFIG_PREEMPT_RCU

/*
 * Preemptible RCU implementation for rcu_read_lock().
 * Just increment ->rcu_read_lock_nesting, shared state will be updated
 * if we block.
 */
void __rcu_read_lock(void)
{
	current->rcu_read_lock_nesting++;
	barrier();  /* critical section after entry code. */
}
EXPORT_SYMBOL_GPL(__rcu_read_lock);

/*
 * Preemptible RCU implementation for rcu_read_unlock().
 * Decrement ->rcu_read_lock_nesting.  If the result is zero (outermost
 * rcu_read_unlock()) and ->rcu_read_unlock_special is non-zero, then
 * invoke rcu_read_unlock_special() to clean up after a context switch
 * in an RCU read-side critical section and other special cases.
 */
void __rcu_read_unlock(void)
{
	struct task_struct *t = current;

	if (t->rcu_read_lock_nesting != 1) {
		--t->rcu_read_lock_nesting;
	} else {
		barrier();  /* critical section before exit code. */
		t->rcu_read_lock_nesting = INT_MIN;
#ifdef CONFIG_PROVE_RCU_DELAY
		udelay(10); /* Make preemption more probable. */
#endif /* #ifdef CONFIG_PROVE_RCU_DELAY */
		barrier();  /* assign before ->rcu_read_unlock_special load */
		if (unlikely(ACCESS_ONCE(t->rcu_read_unlock_special)))
			rcu_read_unlock_special(t);
		barrier();  /* ->rcu_read_unlock_special load before assign */
		t->rcu_read_lock_nesting = 0;
	}
#ifdef CONFIG_PROVE_LOCKING
	{
		int rrln = ACCESS_ONCE(t->rcu_read_lock_nesting);

		WARN_ON_ONCE(rrln < 0 && rrln > INT_MIN / 2);
	}
#endif /* #ifdef CONFIG_PROVE_LOCKING */
}
EXPORT_SYMBOL_GPL(__rcu_read_unlock);

#endif /* #ifdef CONFIG_PREEMPT_RCU */

#ifdef CONFIG_DEBUG_LOCK_ALLOC
static struct lock_class_key rcu_lock_key;
struct lockdep_map rcu_lock_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_read_lock", &rcu_lock_key);
EXPORT_SYMBOL_GPL(rcu_lock_map);

static struct lock_class_key rcu_bh_lock_key;
struct lockdep_map rcu_bh_lock_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_read_lock_bh", &rcu_bh_lock_key);
EXPORT_SYMBOL_GPL(rcu_bh_lock_map);

static struct lock_class_key rcu_sched_lock_key;
struct lockdep_map rcu_sched_lock_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_read_lock_sched", &rcu_sched_lock_key);
EXPORT_SYMBOL_GPL(rcu_sched_lock_map);

static struct lock_class_key rcu_callback_key;
struct lockdep_map rcu_callback_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_callback", &rcu_callback_key);
EXPORT_SYMBOL_GPL(rcu_callback_map);

int notrace debug_lockdep_rcu_enabled(void)
{
	return rcu_scheduler_active && debug_locks &&
	       current->lockdep_recursion == 0;
}
EXPORT_SYMBOL_GPL(debug_lockdep_rcu_enabled);

/**
 * rcu_read_lock_bh_held() - might we be in RCU-bh read-side critical section?
 *
 * Check for bottom half being disabled, which covers both the
 * CONFIG_PROVE_RCU and not cases.  Note that if someone uses
 * rcu_read_lock_bh(), but then later enables BH, lockdep (if enabled)
 * will show the situation.  This is useful for debug checks in functions
 * that require that they be called within an RCU read-side critical
 * section.
 *
 * Check debug_lockdep_rcu_enabled() to prevent false positives during boot.
 *
 * Note that rcu_read_lock() is disallowed if the CPU is either idle or
 * offline from an RCU perspective, so check for those as well.
 */
int rcu_read_lock_bh_held(void)
{
	if (!debug_lockdep_rcu_enabled())
		return 1;
	if (!rcu_is_watching())
		return 0;
	if (!rcu_lockdep_current_cpu_online())
		return 0;
	return in_softirq() || irqs_disabled();
}
EXPORT_SYMBOL_GPL(rcu_read_lock_bh_held);

#endif /* #ifdef CONFIG_DEBUG_LOCK_ALLOC */

struct rcu_synchronize {
	struct rcu_head head;
	struct completion completion;
};

/*
 * Awaken the corresponding synchronize_rcu() instance now that a
 * grace period has elapsed.
 */
static void wakeme_after_rcu(struct rcu_head  *head)
{
	struct rcu_synchronize *rcu;

	rcu = container_of(head, struct rcu_synchronize, head);
	complete(&rcu->completion);
}

void wait_rcu_gp(call_rcu_func_t crf)
{
	struct rcu_synchronize rcu;

	init_rcu_head_on_stack(&rcu.head);
	init_completion(&rcu.completion);
	/* Will wake me after RCU finished. */
	crf(&rcu.head, wakeme_after_rcu);
	/* Wait for it. */
	wait_for_completion(&rcu.completion);
	destroy_rcu_head_on_stack(&rcu.head);
}
EXPORT_SYMBOL_GPL(wait_rcu_gp);

#ifdef CONFIG_DEBUG_OBJECTS_RCU_HEAD
void init_rcu_head(struct rcu_head *head)
{
	debug_object_init(head, &rcuhead_debug_descr);
}

void destroy_rcu_head(struct rcu_head *head)
{
	debug_object_free(head, &rcuhead_debug_descr);
}

/*
 * fixup_activate is called when:
 * - an active object is activated
 * - an unknown object is activated (might be a statically initialized object)
 * Activation is performed internally by call_rcu().
 */
static int rcuhead_fixup_activate(void *addr, enum debug_obj_state state)
{
	struct rcu_head *head = addr;

	switch (state) {

	case ODEBUG_STATE_NOTAVAILABLE:
		/*
		 * This is not really a fixup. We just make sure that it is
		 * tracked in the object tracker.
		 */
		debug_object_init(head, &rcuhead_debug_descr);
		debug_object_activate(head, &rcuhead_debug_descr);
		return 0;
	default:
		return 1;
	}
}

/**
 * init_rcu_head_on_stack() - initialize on-stack rcu_head for debugobjects
 * @head: pointer to rcu_head structure to be initialized
 *
 * This function informs debugobjects of a new rcu_head structure that
 * has been allocated as an auto variable on the stack.  This function
 * is not required for rcu_head structures that are statically defined or
 * that are dynamically allocated on the heap.  This function has no
 * effect for !CONFIG_DEBUG_OBJECTS_RCU_HEAD kernel builds.
 */
void init_rcu_head_on_stack(struct rcu_head *head)
{
	debug_object_init_on_stack(head, &rcuhead_debug_descr);
}
EXPORT_SYMBOL_GPL(init_rcu_head_on_stack);

/**
 * destroy_rcu_head_on_stack() - destroy on-stack rcu_head for debugobjects
 * @head: pointer to rcu_head structure to be initialized
 *
 * This function informs debugobjects that an on-stack rcu_head structure
 * is about to go out of scope.  As with init_rcu_head_on_stack(), this
 * function is not required for rcu_head structures that are statically
 * defined or that are dynamically allocated on the heap.  Also as with
 * init_rcu_head_on_stack(), this function has no effect for
 * !CONFIG_DEBUG_OBJECTS_RCU_HEAD kernel builds.
 */
void destroy_rcu_head_on_stack(struct rcu_head *head)
{
	debug_object_free(head, &rcuhead_debug_descr);
}
EXPORT_SYMBOL_GPL(destroy_rcu_head_on_stack);

struct debug_obj_descr rcuhead_debug_descr = {
	.name = "rcu_head",
	.fixup_activate = rcuhead_fixup_activate,
};
EXPORT_SYMBOL_GPL(rcuhead_debug_descr);
#endif /* #ifdef CONFIG_DEBUG_OBJECTS_RCU_HEAD */

#if defined(CONFIG_TREE_RCU) || defined(CONFIG_TREE_PREEMPT_RCU) || defined(CONFIG_RCU_TRACE)
void do_trace_rcu_torture_read(const char *rcutorturename, struct rcu_head *rhp,
			       unsigned long secs,
			       unsigned long c_old, unsigned long c)
{
	trace_rcu_torture_read(rcutorturename, rhp, secs, c_old, c);
}
EXPORT_SYMBOL_GPL(do_trace_rcu_torture_read);
#else
#define do_trace_rcu_torture_read(rcutorturename, rhp, secs, c_old, c) \
	do { } while (0)
#endif

#ifdef CONFIG_RCU_STALL_COMMON

#ifdef CONFIG_PROVE_RCU
#define RCU_STALL_DELAY_DELTA	       (5 * HZ)
#else
#define RCU_STALL_DELAY_DELTA	       0
#endif

int rcu_cpu_stall_suppress __read_mostly; /* 1 = suppress stall warnings. */
static int rcu_cpu_stall_timeout __read_mostly = CONFIG_RCU_CPU_STALL_TIMEOUT;

module_param(rcu_cpu_stall_suppress, int, 0644);
module_param(rcu_cpu_stall_timeout, int, 0644);

int rcu_jiffies_till_stall_check(void)
{
	int till_stall_check = ACCESS_ONCE(rcu_cpu_stall_timeout);

	/*
	 * Limit check must be consistent with the Kconfig limits
	 * for CONFIG_RCU_CPU_STALL_TIMEOUT.
	 */
	if (till_stall_check < 3) {
		ACCESS_ONCE(rcu_cpu_stall_timeout) = 3;
		till_stall_check = 3;
	} else if (till_stall_check > 300) {
		ACCESS_ONCE(rcu_cpu_stall_timeout) = 300;
		till_stall_check = 300;
	}
	return till_stall_check * HZ + RCU_STALL_DELAY_DELTA;
}

void rcu_sysrq_start(void)
{
	if (!rcu_cpu_stall_suppress)
		rcu_cpu_stall_suppress = 2;
}

void rcu_sysrq_end(void)
{
	if (rcu_cpu_stall_suppress == 2)
		rcu_cpu_stall_suppress = 0;
}

static int rcu_panic(struct notifier_block *this, unsigned long ev, void *ptr)
{
	rcu_cpu_stall_suppress = 1;
	return NOTIFY_DONE;
}

static struct notifier_block rcu_panic_block = {
	.notifier_call = rcu_panic,
};

static int __init check_cpu_stall_init(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &rcu_panic_block);
	return 0;
}
early_initcall(check_cpu_stall_init);

#endif /* #ifdef CONFIG_RCU_STALL_COMMON */

#ifdef CONFIG_TASKS_RCU

/*
 * Simple variant of RCU whose quiescent states are voluntary context switch,
 * user-space execution, and idle.  As such, grace periods can take one good
 * long time.  There are no read-side primitives similar to rcu_read_lock()
 * and rcu_read_unlock() because this implementation is intended to get
 * the system into a safe state for some of the manipulations involved in
 * tracing and the like.  Finally, this implementation does not support
 * high call_rcu_tasks() rates from multiple CPUs.  If this is required,
 * per-CPU callback lists will be needed.
 */

/* Lists of tasks that we are still waiting for during this grace period. */
LIST_HEAD(rcu_tasks_holdouts);

/* Global list of callbacks and associated lock. */
struct rcu_head *rcu_tasks_cbs_head;
struct rcu_head **rcu_tasks_cbs_tail = &rcu_tasks_cbs_head;
DEFINE_RAW_SPINLOCK(rcu_tasks_cbs_lock);

/* Post an RCU-tasks callback. */
void call_rcu_tasks(struct rcu_head *rhp, void (*func)(struct rcu_head *rhp))
{
	unsigned long flags;

	rhp->next = NULL;
	rhp->func = func;
	raw_spin_lock_irqsave(&rcu_tasks_cbs_lock, flags);
	*rcu_tasks_cbs_tail = rhp;
	rcu_tasks_cbs_tail = &rhp->next;
	raw_spin_unlock_irqrestore(&rcu_tasks_cbs_lock, flags);
}

/* RCU-tasks kthread that detects grace periods and invokes callbacks. */
static int rcu_tasks_kthread(void *arg)
{
	unsigned long flags;
	struct task_struct *g, *t;
	struct rcu_head *list;
	struct rcu_head *next;

	/* FIXME: Add housekeeping affinity. */

	/*
	 * Each pass through the following loop makes one check for
	 * newly arrived callbacks, and, if there are some, waits for
	 * one RCU-tasks grace period and then invokes the callbacks.
	 * This loop is terminated by the system going down.  ;-)
	 */
	for (;;) {

		/* Pick up any new callbacks. */
		raw_spin_lock_irqsave(&rcu_tasks_cbs_lock, flags);
		smp_mb__after_unlock_lock(); /* Enforce GP memory ordering. */
		list = rcu_tasks_cbs_head;
		rcu_tasks_cbs_head = NULL;
		rcu_tasks_cbs_tail = &rcu_tasks_cbs_head;
		raw_spin_unlock_irqrestore(&rcu_tasks_cbs_lock, flags);

		/* If there were none, wait a bit and start over. */
		if (!list) {
			schedule_timeout_interruptible(HZ);
			flush_signals(current);
			continue;
		}

		/*
		 * There were callbacks, so we need to wait for an
		 * RCU-tasks grace period.  Start off by scanning
		 * the task list for tasks that are not already
		 * voluntarily blocked.  Mark these tasks and make
		 * a list of them in rcu_tasks_holdouts.
		 */
		do_each_thread(g, t) {
			cond_resched();
			if (t != current && ACCESS_ONCE(t->on_rq) &&
			    !is_idle_task(t)) {
				t->rcu_tasks_holdout = 1;
				list_add(&t->rcu_tasks_holdout_list,
					 &rcu_tasks_holdouts);
			}
		} while_each_thread(g, t);

		/*
		 * The "t != current" and "!is_idle_task()" comparisons
		 * above are stable, but the "t->on_rq" value could
		 * change at any time, and is generally unordered.
		 * Therefore, we need some ordering.  The trick is
		 * that t->on_rq is updated with a runqueue lock held,
		 * and thus with interrupts disabled.  So the following
		 * synchronize_sched() provides the needed ordering by:
		 * (1) Waiting for all interrupts-disabled code sections
		 * to complete and (2) The synchronize_sched() ordering
		 * guarantees, which provide for a memory barrier on each
		 * CPU since the completion of its last read-side critical
		 * section, including interrupt-disabled code sections.
		 */
		synchronize_sched();

		/*
		 * Each pass through the following loop scans the list
		 * of holdout tasks, removing any that are no longer
		 * holdouts.  When the list is empty, we are done.
		 */
		do {
			struct task_struct *n;

			schedule_timeout_interruptible(HZ / 10);
			flush_signals(current);
			list_for_each_entry_safe(t, n, &rcu_tasks_holdouts,
						 rcu_tasks_holdout_list) {
				cond_resched();
				if (smp_load_acquire(&t->rcu_tasks_holdout))
					continue;
				list_del_init(&t->rcu_tasks_holdout_list);
				/* @@@ need to check for usermode on CPU. */
			}
		} while (!list_empty(&rcu_tasks_holdouts));

		/*
		 * Most implementations of RCU would need to force a
		 * memory barrier on all non-idle non-userspace CPUs at
		 * this point.  The reason that this implementation does
		 * not is that all of the callbacks are invoked by this
		 * kthread.  Therefore, the quiescent states on the other
		 * CPUs need only be ordered against this one kthread,
		 * and the smp_store_release() and smp_load_acquire()
		 * on ->rcu_tasks_holdout suffices for this ordering.
		 */

		/* Invoke the callbacks. */
		while (list) {
			next = list->next;
			local_bh_disable();
			list->func(list);
			local_bh_enable();
			list = next;
			cond_resched();
		}
	}
	return 0;  /* Some compilers don't grok non-terminating loops. */
}

/* Spawn rcu_tasks_kthread() at boot time. */
static int __init rcu_spawn_tasks_kthread(void)
{
	struct task_struct __maybe_unused *t;

	t = kthread_run(rcu_tasks_kthread, NULL, "rcu_tasks_kthread");
	BUG_ON(IS_ERR(t));
	return 0;
}
early_initcall(rcu_spawn_tasks_kthread);

#endif /* #ifdef CONFIG_TASKS_RCU */
