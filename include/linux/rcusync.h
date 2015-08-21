#ifndef _LINUX_RCUSYNC_H_
#define _LINUX_RCUSYNC_H_

#include <linux/wait.h>
#include <linux/rcupdate.h>

struct rcu_sync_struct {
	int			gp_state;
	int			gp_count;
	wait_queue_head_t	gp_wait;

	int			cb_state;
	struct rcu_head		cb_head;

	void (*sync)(void);
	void (*call)(struct rcu_head *, void (*)(struct rcu_head *));
};

#define ___RCU_SYNC_INIT(name)						\
	.gp_state = 0,							\
	.gp_count = 0,							\
	.gp_wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.gp_wait),		\
	.cb_state = 0

#define __RCU_SCHED_SYNC_INIT(name) {					\
	___RCU_SYNC_INIT(name),						\
	.sync = synchronize_sched,					\
	.call = call_rcu_sched,						\
}

#define __RCU_BH_SYNC_INIT(name) {					\
	___RCU_SYNC_INIT(name),						\
	.sync = synchronize_rcu_bh,					\
	.call = call_rcu_bh,						\
}

#define __RCU_SYNC_INIT(name) {						\
	___RCU_SYNC_INIT(name),						\
	.sync = synchronize_rcu,					\
	.call = call_rcu,						\
}

#define DEFINE_RCU_SCHED_SYNC(name)					\
	struct rcu_sync_struct name = __RCU_SCHED_SYNC_INIT(name)

#define DEFINE_RCU_BH_SYNC(name)					\
	struct rcu_sync_struct name = __RCU_BH_SYNC_INIT(name)

#define DEFINE_RCU_SYNC(name)						\
	struct rcu_sync_struct name = __RCU_SYNC_INIT(name)

static inline bool rcu_sync_is_idle(struct rcu_sync_struct *rss)
{
	return !rss->gp_state; /* GP_IDLE */
}

enum rcu_sync_type { RCU_SYNC, RCU_SCHED_SYNC, RCU_BH_SYNC };

extern void rcu_sync_init(struct rcu_sync_struct *, enum rcu_sync_type);
extern void rcu_sync_enter(struct rcu_sync_struct *);
extern void rcu_sync_exit(struct rcu_sync_struct *);

#endif /* _LINUX_RCUSYNC_H_ */
