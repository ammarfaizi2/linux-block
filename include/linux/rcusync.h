#ifndef _LINUX_RCUSYNC_H_
#define _LINUX_RCUSYNC_H_

#include <linux/wait.h>
#include <linux/rcupdate.h>

enum rcu_sync_type { RCU_SYNC, RCU_SCHED_SYNC, RCU_BH_SYNC };

struct rcu_sync_struct {
	int			gp_state;
	int			gp_count;
	wait_queue_head_t	gp_wait;

	int			cb_state;
	struct rcu_head		cb_head;

	enum rcu_sync_type	gp_type;
};

extern bool __rcu_sync_is_idle(struct rcu_sync_struct *);

static inline bool rcu_sync_is_idle(struct rcu_sync_struct *rss)
{
#ifdef CONFIG_PROVE_RCU
	return __rcu_sync_is_idle(rss);
#else
	return !rss->gp_state; /* GP_IDLE */
#endif
}

extern void rcu_sync_init(struct rcu_sync_struct *, enum rcu_sync_type);
extern void rcu_sync_enter(struct rcu_sync_struct *);
extern void rcu_sync_exit(struct rcu_sync_struct *);
extern void rcu_sync_dtor(struct rcu_sync_struct *);

#define __RCU_SYNC_INITIALIZER(name, type) {				\
		.gp_state = 0,						\
		.gp_count = 0,						\
		.gp_wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.gp_wait),	\
		.cb_state = 0,						\
		.gp_type = type,					\
	}

#define	__DEFINE_RCU_SYNC(name, type)	\
	struct rcu_sync_struct name = __RCU_SYNC_INITIALIZER(name, type)

#define DEFINE_RCU_SYNC(name)		\
	__DEFINE_RCU_SYNC(name, RCU_SYNC)

#define DEFINE_RCU_SCHED_SYNC(name)	\
	__DEFINE_RCU_SYNC(name, RCU_SCHED_SYNC)

#define DEFINE_RCU_BH_SYNC(name)	\
	__DEFINE_RCU_SYNC(name, RCU_BH_SYNC)

#endif /* _LINUX_RCUSYNC_H_ */
