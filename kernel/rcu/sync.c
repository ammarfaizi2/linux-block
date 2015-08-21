
#include <linux/rcusync.h>
#include <linux/sched.h>

enum { GP_IDLE = 0, GP_PENDING, GP_PASSED };
enum { CB_IDLE = 0, CB_PENDING, CB_REPLAY };

#define	rss_lock	gp_wait.lock

void rcu_sync_init(struct rcu_sync_struct *rss, enum rcu_sync_type type)
{
	memset(rss, 0, sizeof(*rss));
	init_waitqueue_head(&rss->gp_wait);

	switch (type) {
	case RCU_SYNC:
		rss->sync = synchronize_rcu;
		rss->call = call_rcu;
		break;

	case RCU_SCHED_SYNC:
		rss->sync = synchronize_sched;
		rss->call = call_rcu_sched;
		break;

	case RCU_BH_SYNC:
		rss->sync = synchronize_rcu_bh;
		rss->call = call_rcu_bh;
		break;
	}
}

void rcu_sync_enter(struct rcu_sync_struct *rss)
{
	bool need_wait, need_sync;

	spin_lock_irq(&rss->rss_lock);
	need_wait = rss->gp_count++;
	need_sync = rss->gp_state == GP_IDLE;
	if (need_sync)
		rss->gp_state = GP_PENDING;
	spin_unlock_irq(&rss->rss_lock);

	BUG_ON(need_wait && need_sync);

	if (need_sync) {
		rss->sync();
		rss->gp_state = GP_PASSED;
		wake_up_all(&rss->gp_wait);
	} else if (need_wait) {
		wait_event(rss->gp_wait, rss->gp_state == GP_PASSED);
	} else {
		/*
		 * Possible when there's a pending CB from a rcu_sync_exit().
		 * Nobody has yet been allowed the 'fast' path and thus we can
		 * avoid doing any sync(). The callback will get 'dropped'.
		 */
		BUG_ON(rss->gp_state != GP_PASSED);
	}
}

static void rcu_sync_func(struct rcu_head *rcu)
{
	struct rcu_sync_struct *rss =
		container_of(rcu, struct rcu_sync_struct, cb_head);
	unsigned long flags;


	BUG_ON(rss->gp_state != GP_PASSED);
	BUG_ON(rss->cb_state == CB_IDLE);

	spin_lock_irqsave(&rss->rss_lock, flags);
	if (rss->gp_count) {
		/*
		 * A new rcu_sync_begin() has happened; drop the callback.
		 */
		rss->cb_state = CB_IDLE;
	} else if (rss->cb_state == CB_REPLAY) {
		/*
		 * A new rcu_sync_exit() has happened; requeue the callback
		 * to catch a later GP.
		 */
		rss->cb_state = CB_PENDING;
		rss->call(&rss->cb_head, rcu_sync_func);
	} else {
		/*
		 * We're at least a GP after rcu_sync_exit(); eveybody will now
		 * have observed the write side critical section. Let 'em rip!.
		 */
		rss->cb_state = CB_IDLE;
		rss->gp_state = GP_IDLE;
	}
	spin_unlock_irqrestore(&rss->rss_lock, flags);
}

void rcu_sync_exit(struct rcu_sync_struct *rss)
{
	spin_lock_irq(&rss->rss_lock);
	if (!--rss->gp_count) {
		if (rss->cb_state == CB_IDLE) {
			rss->cb_state = CB_PENDING;
			rss->call(&rss->cb_head, rcu_sync_func);
		} else if (rss->cb_state == CB_PENDING) {
			rss->cb_state = CB_REPLAY;
		}
	}
	spin_unlock_irq(&rss->rss_lock);
}
