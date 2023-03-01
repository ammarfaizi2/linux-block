// SPDX-License-Identifier: GPL-2.0-only
/*
 * Infrastructure for migrateable timers
 *
 * Copyright(C) 2022 linutronix GmbH
 */
#include <linux/cpuhotplug.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/timerqueue.h>

#include "timer_migration.h"
#include "tick-internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/timer_migration.h>

/*
 * The timer migration mechanism is built on a hierarchy of groups. The
 * lowest level group contains CPUs, the next level groups of CPU groups
 * and so forth. The CPU groups are kept per node so for the normal case
 * lock contention won't happen accross nodes. Depending on the number of
 * CPUs per node even the next level might be kept as groups of CPU groups
 * per node and only the levels above cross the node topology.
 *
 * Example topology for a two node system with 24 CPUs each.
 *
 * LVL 2			[GRP2:0]
 *			      GRP1:0 = GRP1:M
 *
 * LVL 1            [GRP1:0]		         [GRP1:1]
 *	         GRP0:0 - GRP0:2	      GRP0:3 - GRP0:5
 *
 * LVL 0  [GRP0:0]  [GRP0:1]  [GRP0:2]  [GRP0:3]  [GRP0:4]  [GRP0:5]
 * CPUS     0-7       8-15     16-23     24-31	   32-39     40-47
 *
 * The groups hold a timer queue of events sorted by expiry time. These
 * queues are updated when CPUs go in idle. When they come out of idle
 * ignore bit of events is set.
 *
 * Each group has a designated migrator CPU/group as long as a CPU/group is
 * active in the group. This designated role is necessary to avoid that all
 * active CPUs in a group try to migrate expired timers from other cpus,
 * which would result in massive lock bouncing.
 *
 * When a CPU is awake, it checks in it's own timer tick the group
 * hierarchy up to the point where it is assigned the migrator role or if
 * no CPU is active, it also checks the groups where no migrator is set
 * (TMIGR_NONE).
 *
 * If it finds expired timers in one of the group queues it pulls them over
 * from the idle CPU and runs the timer function. After that it updates the
 * group and the parent groups if required.
 *
 * CPUs which go idle arm their CPU local timer hardware for the next local
 * (pinned) timer event. If the next migrateable timer expires after the
 * next local timer or the CPU has no migrateable timer pending then the
 * CPU does not queue an event in the LVL0 group. If the next migrateable
 * timer expires before the next local timer then the CPU queues that timer
 * in the LVL0 group. In both cases the CPU marks itself idle in the LVL0
 * group.
 *
 * If the CPU is the migrator of the group then it delegates that role to
 * the next active CPU in the group or sets migrator to TMIGR_NONE when
 * there is no active CPU in the group. This delegation needs to be
 * propagated up the hierarchy so hand over from other leaves can happen at
 * all hierarchy levels w/o doing a search.
 *
 * When the last CPU in the system goes idle, then it drops all migrator
 * duties up to the top level of the hierarchy (LVL2 in the example). It
 * then has to make sure, that it arms it's own local hardware timer for
 * the earliest event in the system.
 *
 * Lifetime rules:
 *
 * The groups are built up at init time or when CPUs come online. They are
 * not destroyed when a group becomes empty due to offlining. The group
 * just won't participate in the hierachary management anymore. Destroying
 * groups would result in interesting race conditions which would just make
 * the whole mechanism slow and complex.
 *
 * Locking rules:
 *
 * For setting up new groups and handling events it's required to lock both
 * child and parent group. The lock odering is always bottom up. This also
 * includes the per CPU locks in struct tmigr_cpu. For updating migrator
 * and active CPU/group information atomic_cmpxchg() is used instead and
 * only per CPU tmigr_cpu->lock is held.
 *
 * During setup of groups tmigr_level_list is required. It is protected by
 * tmigr_mutex.
 */

#ifdef DEBUG
# define DBG_BUG_ON(x) BUG_ON(x)
#else
# define DBG_BUG_ON(x)
#endif

static DEFINE_MUTEX(tmigr_mutex);
static struct list_head *tmigr_level_list __read_mostly;

static unsigned int tmigr_cores_per_group __read_mostly;
static unsigned int tmigr_hierarchy_levels __read_mostly;
static unsigned int tmigr_crossnode_level __read_mostly;

static DEFINE_PER_CPU(struct tmigr_cpu, tmigr_cpu);

#define TMIGR_NONE	0xFF
#define BIT_CNT		8

static DEFINE_STATIC_KEY_FALSE(tmigr_enabled);

static inline bool is_tmigr_enabled(void)
{
	return static_branch_unlikely(&tmigr_enabled);
}

/*
 * Returns true, when @childmask corresponds to group migrator or when group
 * is not active - so no migrator is set.
 */
static bool tmigr_check_migrator(struct tmigr_group *group, u32 childmask)
{
	union tmigr_state s;

	s.state = atomic_read(group->migr_state);

	if ((s.migrator != (u8)childmask) && (s.migrator != TMIGR_NONE))
		return false;

	return true;
}

typedef bool (*up_f)(struct tmigr_group *, struct tmigr_group *, void *);

static void __walk_groups(up_f up, void *data,
			  struct tmigr_cpu *tmc)
{
	struct tmigr_group *child = NULL, *group = tmc->tmgroup;

	do {
		DBG_BUG_ON(group->level >= tmigr_hierarchy_levels);

		if (up(group, child, data))
			break;

		child = group;
		group = group->parent;
	} while (group);
}

static void walk_groups(up_f up, void *data, struct tmigr_cpu *tmc)
{
	lockdep_assert_held(&tmc->lock);

	__walk_groups(up, data, tmc);
}

/**
 * struct tmigr_walk - data required for walking the hierarchy
 * @evt:		Pointer to tmigr_event which needs to be queued (of idle
 *			child group)
 * @childmask:		childmask of child group
 * @nextexp:		Next CPU event expiry information which is handed
 *			into tmigr code by timer code
 *			(get_next_timer_interrupt()); it is furthermore
 *			used for first event which is queued, if timer
 *			migration hierarchy is completely idle
 * @childstate:		tmigr_group->migr_state of child - will be only reread
 *			when cmpxchg in group fails (is required for deactive
 *			path and new timer path)
 * @groupstate:		tmigr_group->migr_state of group - will be only reread
 *			when cmpxchg in group fails (is required for active,
 *			deactive and new timer path)
 * @remote: 		Is set, when new timer path is executed in
 *			tmigr_handle_remote_cpu()
 */
struct tmigr_walk {
	struct tmigr_event	*evt;
	u32			childmask;
	u64			nextexp;
	union tmigr_state	childstate;
	union tmigr_state	groupstate;
	bool			remote;
};

/**
 * struct tmigr_remote_data -	data required for (check) remote expiry
 *				hierarchy walk
 * @basej:	timer base in jiffies
 * @now:	timer base monotonic
 * @childmask:	childmask of child group
 * @check:	is set to 1 if there is the need to handle remote timers;
 *		required in tmigr_check_handle_remote() only
 * @wakeup:	returns expiry of first timer in idle timer migration hierarchy
 *		to make sure timer is handled in time; it is stored in per CPU
 *		tmigr_cpu struct of CPU which expires remote timers
 */
struct tmigr_remote_data {
	unsigned long	basej;
	u64		now;
	u32		childmask;
	int		check;
	u64		wakeup;
};

/*
 * Returns next event of timerqueue @group->events
 *
 * Removes timers with ignore bits and update next_expiry and event cpu
 * value in group. Expiry value of group event is updated in
 * tmigr_update_events() only.
 */
static struct tmigr_event *tmigr_next_groupevt(struct tmigr_group *group)
{
	struct timerqueue_node *node = NULL;
	struct tmigr_event *evt = NULL;

	lockdep_assert_held(&group->lock);

	group->next_expiry = KTIME_MAX;

	while ((node = timerqueue_getnext(&group->events))) {
		evt = container_of(node, struct tmigr_event, nextevt);

		if (!evt->ignore) {
			group->next_expiry = evt->nextevt.expires;
			return evt;
		}

		/*
		 * Remove next timers with ignore bits, because group lock
		 * is held anyway
		 */
		if (!timerqueue_del(&group->events, node))
			break;
	}

	return NULL;
}

/*
 * Return next event which is already expired of group timerqueue
 *
 * Event is also removed from queue.
 */
static struct tmigr_event *tmigr_next_expired_groupevt(struct tmigr_group *group,
						     u64 now)
{
	struct tmigr_event *evt = tmigr_next_groupevt(group);

	if (!evt || now < evt->nextevt.expires)
		return NULL;

	/*
	 * Event is already expired. Remove it. If it's not the last event,
	 * then update all group event related information.
	 */
	if (timerqueue_del(&group->events, &evt->nextevt))
		tmigr_next_groupevt(group);
	else
		group->next_expiry = KTIME_MAX;

	return evt;
}

static u64 tmigr_next_groupevt_expires(struct tmigr_group *group)
{
	struct tmigr_event *evt;

	evt = tmigr_next_groupevt(group);

	if (!evt)
		return KTIME_MAX;
	else
		return evt->nextevt.expires;
}

static bool tmigr_active_up(struct tmigr_group *group,
			    struct tmigr_group *child,
			    void *ptr)
{
	union tmigr_state curstate, newstate;
	struct tmigr_walk *data = ptr;
	bool walk_done;
	u32 childmask;

	childmask = data->childmask;
	newstate = curstate = data->groupstate;

retry:
	walk_done = true;

	if (newstate.migrator == TMIGR_NONE) {
		newstate.migrator = (u8)childmask;

		/* Changes need to be propagated */
		walk_done = false;
	}

	newstate.active |= (u8)childmask;

	newstate.seq++;

	if (atomic_cmpxchg(group->migr_state, curstate.state, newstate.state) != curstate.state) {
		newstate.state = curstate.state = atomic_read(group->migr_state);
		goto retry;
	}

	if (group->parent && (walk_done == false)) {
		data->groupstate.state = atomic_read(group->parent->migr_state);
		data->childmask = group->childmask;
	}

	/*
	 * Group is active, event will be ignored - bit is updated without
	 * holding the lock. In case bit is set while another CPU already
	 * handles remote events, nothing happens, because it is clear that
	 * CPU became active just in this moment, or in worst case event is
	 * handled remote. Nothing to worry about.
	 */
	group->groupevt.ignore = 1;

	trace_tmigr_group_set_cpu_active(group, newstate, childmask);

	return walk_done;
}

static void __tmigr_cpu_activate(struct tmigr_cpu *tmc)
{
	struct tmigr_walk data;
	data.childmask = tmc->childmask;
	data.groupstate.state = atomic_read(tmc->tmgroup->migr_state);

	tmc->cpuevt.ignore = 1;

	walk_groups(&tmigr_active_up, &data, tmc);
}

void tmigr_cpu_activate(void)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);

	if (!is_tmigr_enabled() || !tmc->tmgroup || !tmc->online || !tmc->idle)
		return;

	raw_spin_lock(&tmc->lock);
	tmc->idle = 0;
	tmc->wakeup = KTIME_MAX;
	trace_tmigr_cpu_active(tmc);
	__tmigr_cpu_activate(tmc);
	raw_spin_unlock(&tmc->lock);
}

/*
 * Returns true, if there is nothing to be propagated to the next level
 *
 * @data->nextexp is reset to KTIME_MAX; it is reused for first global
 * event which needs to be handled by migrator (in toplevel group)
 *
 * This is the only place where group event expiry value is set.
 */
static bool tmigr_update_events(struct tmigr_group *group,
				struct tmigr_group *child,
				struct tmigr_walk *data)
{
	struct tmigr_event *evt, *first_childevt;
	bool walk_done, remote = data->remote;
	u64 nextexp;

	if (child) {
		if (data->childstate.active)
			return true;

		raw_spin_lock(&child->lock);
		raw_spin_lock_nested(&group->lock, SINGLE_DEPTH_NESTING);

		first_childevt = tmigr_next_groupevt(child);
		nextexp = child->next_expiry;
		evt = &child->groupevt;
	} else {
		nextexp = data->nextexp;

		/*
		 * Set @data->nextexp to KTIME_MAX; it is reused for first
		 * global event which needs to be handled by migrator (in
		 * toplevel group)
		 */
		data->nextexp = KTIME_MAX;

		first_childevt = evt = data->evt;
		if (evt->ignore)
			return true;

		raw_spin_lock(&group->lock);
	}

	if (nextexp == KTIME_MAX)
		evt->ignore = 1;

	/*
	 * When next event could be ignored (nextexp is KTIME MAX) and
	 * there was no remote timer handling before or the group is
	 * already active active, there is no need to walk the hierarchy
	 * even if there is a parent group.
	 *
	 * The other way round: even if the event could be ignored, but if
	 * a remote timer handling was executed before and the group is not
	 * active, walking the hierarchy is required to not miss a enqueued
	 * timer in the non active group. The enqueued timer needs to be
	 * propagated to a higher level to ensure it is handeld.
	 */
	if (nextexp == KTIME_MAX && (!remote || data->groupstate.active)) {
		walk_done = true;
		goto unlock;
	}

	walk_done = !group->parent;

	/*
	 * Update of event cpu and ignore bit is required only when @child
	 * is set (child is equal or higher than lvl0), but it doesn't
	 * matter if it is written once more to per cpu event; make the
	 * update unconditional.
	 */
	evt->cpu = first_childevt->cpu;
	evt->ignore = 0;

	/*
	 * If child event is already queued in group, remove it from queue
	 * when expiry time changed only
	 */
	if (timerqueue_node_queued(&evt->nextevt)) {
		if (evt->nextevt.expires == nextexp)
			goto check_toplvl;
		else if (!timerqueue_del(&group->events, &evt->nextevt))
			group->next_expiry = KTIME_MAX;
	}

	evt->nextevt.expires = nextexp;

	if (timerqueue_add(&group->events, &evt->nextevt))
		group->next_expiry = nextexp;

check_toplvl:
	if (walk_done && (data->groupstate.migrator == TMIGR_NONE)) {
		/*
		 * Toplevel group is idle and it has to be ensured global
		 * timers are handled in time. (This could be optimized by
		 * keeping track of the last global scheduled event and
		 * only arming it on CPU if the new event is earlier. Not
		 * sure if its worth the complexity.)
		 */
		data->nextexp = tmigr_next_groupevt_expires(group);
	}

	trace_tmigr_update_events(child, group, data->childstate,
				  data->groupstate, nextexp);

unlock:
	raw_spin_unlock(&group->lock);

	if (child)
		raw_spin_unlock(&child->lock);

	return walk_done;
}

static bool tmigr_new_timer_up(struct tmigr_group *group,
			       struct tmigr_group *child,
			       void *ptr)
{
	struct tmigr_walk *data = ptr;
	bool walk_done;

	walk_done = tmigr_update_events(group, child, data);

	if (!walk_done) {
		/* Update state information for next iteration */
		data->childstate.state = atomic_read(group->migr_state);
		if (group->parent)
			data->groupstate.state = atomic_read(group->parent->migr_state);
	}

	return walk_done;
}

/*
 * Returns expiry of next timer that needs to be handled. KTIME_MAX is
 * returned, when an active CPU will handle all timer migration hierarchy
 * timers.
 */
static u64 tmigr_new_timer(struct tmigr_cpu *tmc, u64 nextexp)
{
	struct tmigr_walk data = { .evt = &tmc->cpuevt,
				   .nextexp = nextexp };

	lockdep_assert_held(&tmc->lock);

	if (tmc->remote)
		return KTIME_MAX;

	trace_tmigr_cpu_new_timer(tmc);

	tmc->cpuevt.ignore = 0;

	data.groupstate.state = atomic_read(tmc->tmgroup->migr_state);
	data.remote = false;

	walk_groups(&tmigr_new_timer_up, &data, tmc);

	/* If there is a new first global event, make sure it is handled */
	return data.nextexp;
}

static bool tmigr_inactive_up(struct tmigr_group *group,
			      struct tmigr_group *child,
			      void *ptr)
{
	union tmigr_state curstate, newstate;
	struct tmigr_walk *data = ptr;
	bool walk_done;
	u32 childmask;

	childmask = data->childmask;
	newstate = curstate = data->groupstate;

retry:
	walk_done = true;

	/* Reset active bit when child is no longer active */
	if (!data->childstate.active)
		newstate.active &= ~(u8)childmask;

	if (newstate.migrator == (u8)childmask) {
		/*
		 * Find a new migrator for the group, because child group
		 * is idle!
		 */
		if (!data->childstate.active) {
			unsigned long new_migr_bit, active = newstate.active;

			new_migr_bit = find_first_bit(&active, BIT_CNT);

			/* Changes need to be propagated */
			walk_done = false;

			if (new_migr_bit != BIT_CNT)
				newstate.migrator = BIT(new_migr_bit);
			else
				newstate.migrator = TMIGR_NONE;
		}
	}

	newstate.seq++;

	DBG_BUG_ON((newstate.migrator != TMIGR_NONE) && !(newstate.active));

	if (atomic_cmpxchg(group->migr_state, curstate.state, newstate.state) != curstate.state) {
		/*
		 * Something changed in child/parent group in the meantime,
		 * reread the state of child and parent; Update of
		 * data->childstate is required for event handling;
		 */
		if (child)
			data->childstate.state = atomic_read(child->migr_state);
		newstate.state = curstate.state = atomic_read(group->migr_state);

		goto retry;
	}

	data->groupstate = newstate;
	data->remote = false;

	/* Event Handling */
	tmigr_update_events(group, child, data);

	if (group->parent && (walk_done == false)) {
		data->childmask = group->childmask;
		data->childstate = newstate;
		data->groupstate.state = atomic_read(group->parent->migr_state);
	}

	/*
	 * data->nextexp was set by tmigr_update_events() and contains the
	 * expiry of first global event which needs to be handled
	 */
	if (data->nextexp != KTIME_MAX) {
		DBG_BUG_ON(group->parent);
		/*
		 * Toplevel path - If this cpu is about going offline wake
		 * up some random other cpu so it will take over the
		 * migrator duty and program its timer properly. Ideally
		 * wake the cpu with the closest expiry time, but that's
		 * overkill to figure out.
		 */
		if (!(this_cpu_ptr(&tmigr_cpu)->online)) {
			unsigned int cpu = smp_processor_id();

			cpu = cpumask_any_but(cpu_online_mask, cpu);
			smp_send_reschedule(cpu);
		}
	}

	trace_tmigr_group_set_cpu_inactive(group, newstate, childmask);

	return walk_done;
}

static u64 __tmigr_cpu_deactivate(struct tmigr_cpu *tmc, u64 nextexp)
{
	struct tmigr_walk data = { .childmask = tmc->childmask,
				   .evt = &tmc->cpuevt,
				   .nextexp = nextexp,
				   .childstate.state = 0 };

	data.groupstate.state = atomic_read(tmc->tmgroup->migr_state);

	/*
	 * If nextexp is KTIME_MAX, CPU event will be ignored because,
	 * local timer expires before global timer, no global timer is set
	 * or CPU goes offline.
	 */
	if (nextexp != KTIME_MAX)
		tmc->cpuevt.ignore = 0;

	walk_groups(&tmigr_inactive_up, &data, tmc);
	return data.nextexp;
}

/**
 * tmigr_cpu_deactivate - Put current CPU into inactive state
 * @nextexp:	The next timer event expiry set in the current CPU
 *
 * Must be called with interrupts disabled.
 *
 * Return: next event of the current CPU or next event from the hierarchy
 * if this CPU is the top level migrator or hierarchy is completely idle.
 */
u64 tmigr_cpu_deactivate(u64 nextexp)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	u64 ret;

	if (!is_tmigr_enabled() || !tmc->tmgroup || !tmc->online)
		return nextexp;

	raw_spin_lock(&tmc->lock);

	/*
	 * CPU is already deactivated in timer migration
	 * hierarchy. tick_nohz_get_sleep_length() calls
	 * tick_nohz_next_event() and thereby timer idle path is
	 * executed once more. tmc->wakeup holds the first timer, when
	 * timer migration hierarchy is completely idle and remote
	 * expiry was done. If there is no new next expiry value
	 * handed in which should be inserted into the timer migration
	 * hierarchy, wakeup value is returned.
	 */
	if (tmc->idle) {
		ret = tmc->wakeup;

		tmc->wakeup = KTIME_MAX;

		if (nextexp != KTIME_MAX) {
			if (nextexp != tmc->cpuevt.nextevt.expires ||
			    tmc->cpuevt.ignore)
				ret = tmigr_new_timer(tmc, nextexp);
		}

		goto unlock;
	}

	/*
	 * When tmigr_remote is active, set cpu inactive path and queuing of
	 * nextexp is done by handle remote path.
	 */
	ret = __tmigr_cpu_deactivate(tmc, nextexp);

	tmc->idle = 1;

unlock:
	trace_tmigr_cpu_idle(tmc, ret);
	raw_spin_unlock(&tmc->lock);
	return ret;
}

static u64 tmigr_handle_remote_cpu(unsigned int cpu, u64 now,
				   unsigned long jif)
{
	struct timer_events tevt;
	struct tmigr_walk data;
	struct tmigr_cpu *tmc;
	u64 next = KTIME_MAX;
	unsigned long flags;

	tmc = per_cpu_ptr(&tmigr_cpu, cpu);

	raw_spin_lock_irqsave(&tmc->lock, flags);
	/*
	 * Remote CPU is offline or no longer idle or other cpu handles cpu
	 * timers already or next event was already expired - return!
	 */
	if (!tmc->online || tmc->remote || tmc->cpuevt.ignore ||
	    now < tmc->cpuevt.nextevt.expires) {
		raw_spin_unlock_irqrestore(&tmc->lock, flags);
		return next;
	}

	trace_tmigr_handle_remote_cpu(tmc);

	tmc->remote = 1;

	/* Drop the lock to allow the remote CPU to exit idle */
	raw_spin_unlock_irqrestore(&tmc->lock, flags);

	if (cpu != smp_processor_id())
		timer_expire_remote(cpu);

	/* next event of cpu */
	fetch_next_timer_interrupt_remote(jif, now, &tevt, cpu);

	raw_spin_lock_irqsave(&tmc->lock, flags);
	/*
	 * Nothing more to do when CPU came out of idle in the meantime - needs
	 * to be checked when holding the base lock to prevent race.
	 */
	if (!tmc->idle)
		goto unlock;

	data.evt = &tmc->cpuevt;
	data.nextexp = tevt.global;
	data.groupstate.state = atomic_read(tmc->tmgroup->migr_state);
	data.remote = true;
	tmc->cpuevt.ignore = 0;

	walk_groups(&tmigr_new_timer_up, &data, tmc);

	next = data.nextexp;

unlock:
	tmc->remote = 0;
	raw_spin_unlock_irqrestore(&tmc->lock, flags);

	return next;
}

static bool tmigr_handle_remote_up(struct tmigr_group *group,
				   struct tmigr_group *child,
				   void *ptr)
{
	struct tmigr_remote_data *data = ptr;
	u64 now, next = KTIME_MAX;
	unsigned long flags, jif;
	struct tmigr_event *evt;
	u32 childmask;

	jif = data->basej;
	now = data->now;

	childmask = data->childmask;

	trace_tmigr_handle_remote(group);
again:
	/*
	 * Handle the group only if @childmask is the migrator or if the
	 * group has no migrator. Otherwise the group is active and is
	 * handled by its own migrator.
	 */
	if (!tmigr_check_migrator(group, childmask))
		return true;

	raw_spin_lock_irqsave(&group->lock, flags);

	evt = tmigr_next_expired_groupevt(group, now);

	if (evt) {
		unsigned int remote_cpu = evt->cpu;

		raw_spin_unlock_irqrestore(&group->lock, flags);

		next = tmigr_handle_remote_cpu(remote_cpu, now, jif);

		/* check if there is another event, that needs to be handled */
		goto again;
	} else {
		raw_spin_unlock_irqrestore(&group->lock, flags);
	}

	/* Update of childmask for next level */
	data->childmask = group->childmask;
	data->wakeup = next;

	return false;
}

/**
 * tmigr_handle_remote - Handle migratable timers on remote idle CPUs
 *
 * Called from the timer soft interrupt with interrupts enabled.
 */
void tmigr_handle_remote(void)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	struct tmigr_remote_data data;
	unsigned long flags;

	if (!is_tmigr_enabled() || !tmc->tmgroup || !tmc->online)
		return;

	/*
	 * NOTE: This is a doubled check because migrator test will be done
	 * in tmigr_handle_remote_up() anyway. Keep this check to fasten
	 * the return when nothing has to be done.
	 */
	if (!tmigr_check_migrator(tmc->tmgroup, tmc->childmask))
		return;

	data.now = get_jiffies_update(&data.basej);
	data.childmask = tmc->childmask;
	data.wakeup = KTIME_MAX;

	__walk_groups(&tmigr_handle_remote_up, &data, tmc);

	raw_spin_lock_irqsave(&tmc->lock, flags);
	if (tmc->idle)
		tmc->wakeup = data.wakeup;

	raw_spin_unlock_irqrestore(&tmc->lock, flags);

	return;
}

static bool tmigr_requires_handle_remote_up(struct tmigr_group *group,
					 struct tmigr_group *child,
					 void *ptr)
{
	struct tmigr_remote_data *data = ptr;
	u32 childmask;

	childmask = data->childmask;

	/*
	 * Handle the group only if child is the migrator or if the group
	 * has no migrator. Otherwise the group is active and is handled by
	 * its own migrator.
	 */
	if (!tmigr_check_migrator(group, childmask))
		return true;

	/*
	 * Racy lockless check for next_expiry
	 */
	if (data->now >= group->next_expiry) {
		data->check = 1;
		return true;
	}

	/* Update of childmask for next level */
	data->childmask = group->childmask;
	return false;
}

int tmigr_requires_handle_remote(void)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	struct tmigr_remote_data data;

	if (!is_tmigr_enabled() || !tmc->tmgroup || !tmc->online)
		return 0;

	if (!tmigr_check_migrator(tmc->tmgroup, tmc->childmask))
		return 0;

	data.now = get_jiffies_update(&data.basej);
	data.childmask = tmc->childmask;

	__walk_groups(&tmigr_requires_handle_remote_up, &data, tmc);

	return data.check;
}

static void tmigr_init_group(struct tmigr_group *group, unsigned int lvl,
			     unsigned int node, atomic_t *migr_state)
{
	union tmigr_state s;

	raw_spin_lock_init(&group->lock);

	group->level = lvl;
	group->numa_node = lvl < tmigr_crossnode_level ? node : NUMA_NO_NODE;

	group->num_childs = 0;

	/*
	 * num_cores is required for level=0 groups only during setup and
	 * when siblings exists but it doesn't matter if this value is set
	 * in other groups as well
	 */
	group->num_cores = 1;

	s.migrator = TMIGR_NONE;
	s.active = 0;
	s.seq = 0;
	atomic_set(migr_state, s.state);

	group->migr_state = migr_state;

	timerqueue_init_head(&group->events);
	timerqueue_init(&group->groupevt.nextevt);
	group->groupevt.nextevt.expires = KTIME_MAX;
	group->next_expiry = KTIME_MAX;
	group->groupevt.ignore = 1;
}

static bool sibling_in_group(int newcpu, struct tmigr_group *group)
{
	int i, cpu;

	/* Find a sibling of newcpu in group members */
	for (i = 0; i < group->num_childs; i++) {
		cpu = group->cpus[i];

		if (cpumask_test_cpu(newcpu, topology_sibling_cpumask(cpu)))
			return true;
	}
	return false;
}

static struct tmigr_group *tmigr_get_group(unsigned int cpu, unsigned int node,
					   unsigned int lvl)
{
	struct tmigr_group *tmp, *group = NULL;
	bool first_loop = true;
	atomic_t *migr_state;

reloop:
	/* Try to attach to an exisiting group first */
	list_for_each_entry(tmp, &tmigr_level_list[lvl], list) {
		/*
		 * If @lvl is below the cross numa node level, check whether
		 * this group belongs to the same numa node.
		 */
		if (lvl < tmigr_crossnode_level && tmp->numa_node != node)
			continue;

		/* Capacity left? */
		if (tmp->num_childs >= TMIGR_CHILDS_PER_GROUP)
			continue;

		/*
		 * If this is the lowest level of the hierarchy, make sure
		 * that thread siblings share a group. It is only executed
		 * when siblings exist. ALL groups of lowest level needs to
		 * be checked for thread sibling, before thread cpu is
		 * added to a random group with capacity. When all groups
		 * are checked and no thread sibling was found, reloop of
		 * level zero groups is required to get a group with
		 * capacity.
		 */
		if (!lvl && (tmigr_cores_per_group != TMIGR_CHILDS_PER_GROUP)) {
			if (first_loop == true && !sibling_in_group(cpu, tmp)) {
				continue;
			} else if (first_loop == false) {
				if (tmp->num_cores >= tmigr_cores_per_group)
					continue;
				else
					tmp->num_cores++;
			}
		}

		group = tmp;
		break;
	}

	if (group) {
		return group;
	} else if (first_loop == true) {
		first_loop = false;
		goto reloop;
	}

	/* Allocate and	set up a new group with corresponding migr_state */
	group = kzalloc_node(sizeof(*group), GFP_KERNEL, node);
	if (!group)
		return ERR_PTR(-ENOMEM);

	migr_state = kzalloc_node(sizeof(atomic_t), GFP_KERNEL, node);
	if (!migr_state) {
		kfree(group);
		return ERR_PTR(-ENOMEM);
	}

	tmigr_init_group(group, lvl, node, migr_state);
	/* Setup successful. Add it to the hierarchy */
	list_add(&group->list, &tmigr_level_list[lvl]);
	trace_tmigr_group_set(group);
	return group;
}

static void tmigr_connect_child_parent(struct tmigr_group *child,
				       struct tmigr_group *parent)
{
	union tmigr_state childstate;
	unsigned long flags;

	raw_spin_lock_irqsave(&child->lock, flags);
	raw_spin_lock_nested(&parent->lock, SINGLE_DEPTH_NESTING);

	child->parent = parent;
	child->childmask = BIT(parent->num_childs++);

	raw_spin_unlock(&parent->lock);
	raw_spin_unlock_irqrestore(&child->lock, flags);

	trace_tmigr_connect_child_parent(child);

	/*
	 * To prevent inconsistent states, active childs needs to be active
	 * in new parent as well. Inactive childs are already marked
	 * inactive in parent group.
	 */
	childstate.state = atomic_read(child->migr_state);
	if (childstate.migrator != TMIGR_NONE) {
		struct tmigr_walk data;

		data.childmask = child->childmask;
		data.groupstate.state = atomic_read(parent->migr_state);

		/*
		 * There is only one new level per time. When connecting
		 * child and parent and set child active when parent is
		 * inactive, parent needs to be the upperst
		 * level. Otherwise there went something wrong!
		 */
		WARN_ON(!tmigr_active_up(parent, child, &data) && parent->parent);
	}
}

static int tmigr_setup_groups(unsigned int cpu, unsigned int node)
{
	struct tmigr_group *group, *child, **stack;
	int top = 0, err = 0, i = 0;
	struct list_head *lvllist;
	size_t sz;

	sz = sizeof(struct tmigr_group *) * tmigr_hierarchy_levels;
	stack = kzalloc(sz, GFP_KERNEL);
	if (!stack)
		return -ENOMEM;

	do {
		group = tmigr_get_group(cpu, node, i);
		if (IS_ERR(group)) {
			err = IS_ERR(group);
			break;
		}

		top = i;
		stack[i++] = group;

		/*
		 * When booting only less CPUs of a system than CPUs are
		 * available, not all calculated hierarchy levels are required.
		 *
		 * The loop is aborted as soon as the highest level, which might
		 * be different from tmigr_hierarchy_levels, contains only a
		 * single group.
		 */
		if (group->parent || i == tmigr_hierarchy_levels ||
		    (list_empty(&tmigr_level_list[i]) &&
		     list_is_singular(&tmigr_level_list[i - 1])))
			break;

	} while (i < tmigr_hierarchy_levels);

	do {
		group = stack[--i];

		if (err < 0) {
			list_del(&group->list);
			kfree(group);
			continue;
		}

		DBG_BUG_ON(i != group->level);

		/*
		 * Update tmc -> group / child -> group connection
		 */
		if (i == 0) {
			struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
			unsigned long flags;

			raw_spin_lock_irqsave(&group->lock, flags);

			tmc->tmgroup = group;
			tmc->childmask = BIT(group->num_childs);

			group->cpus[group->num_childs++] = cpu;

			raw_spin_unlock_irqrestore(&group->lock, flags);

			trace_tmigr_connect_cpu_parent(tmc);

			/* There are no childs that needs to be connected */
			continue;
		} else {
			child = stack[i - 1];
			tmigr_connect_child_parent(child, group);
		}

		/* check if upperst level was newly created */
		if (top != i)
			continue;

		DBG_BUG_ON(top == 0);

		lvllist = &tmigr_level_list[top];
		if (group->num_childs == 1 && list_is_singular(lvllist)) {
			lvllist = &tmigr_level_list[top - 1];
			list_for_each_entry(child, lvllist, list) {
				if (child->parent)
					continue;

				tmigr_connect_child_parent(child, group);
			}
		}
	} while (i > 0);

	kfree(stack);

	return err;
}

static int tmigr_add_cpu(unsigned int cpu)
{
	unsigned int node = cpu_to_node(cpu);
	int ret;
	mutex_lock(&tmigr_mutex);
	ret = tmigr_setup_groups(cpu, node);
	mutex_unlock(&tmigr_mutex);

	return ret;
}

static int tmigr_cpu_online(unsigned int cpu)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	unsigned long flags;
	unsigned int ret;

	/* First online attempt? Initialize CPU data */
	if (!tmc->tmgroup) {
		raw_spin_lock_init(&tmc->lock);

		ret = tmigr_add_cpu(cpu);
		if (ret < 0)
			return ret;

		if (tmc->childmask == 0)
			return -EINVAL;

		timerqueue_init(&tmc->cpuevt.nextevt);
		tmc->cpuevt.nextevt.expires = KTIME_MAX;
		tmc->cpuevt.ignore = 1;
		tmc->cpuevt.cpu = cpu;

		tmc->remote = 0;
		tmc->idle = 0;
		tmc->wakeup = KTIME_MAX;
	}
	raw_spin_lock_irqsave(&tmc->lock, flags);
	trace_tmigr_cpu_online(tmc);
	__tmigr_cpu_activate(tmc);
	tmc->online = 1;
	raw_spin_unlock_irqrestore(&tmc->lock, flags);
	return 0;
}

static int tmigr_cpu_offline(unsigned int cpu)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);

	raw_spin_lock_irq(&tmc->lock);
	tmc->online = 0;
	__tmigr_cpu_deactivate(tmc, KTIME_MAX);
	trace_tmigr_cpu_offline(tmc);
	raw_spin_unlock_irq(&tmc->lock);

	return 0;
}

static int __init tmigr_init(void)
{
	unsigned int cpulvl, nodelvl, cpus_per_node, i, ns;
	unsigned int nnodes = num_possible_nodes();
	unsigned int ncpus = num_possible_cpus();
	int ret = -ENOMEM;
	size_t sz;

	/* Nothing to do if running on UP */
	if (ncpus == 1)
		return 0;

	/*
	 * Unfortunately there is no reliable way to determine the number of SMT
	 * siblings in a generic way. tmigr_init() is called after SMP bringup,
	 * so for the normal boot case it can be assumed that all siblings have
	 * been brought up and the number of siblings of the current cpu can be
	 * used. If someone booted with 'maxcpus=N/2' on the kernel command line
	 * and (at least x86) bring up the siblings later then the siblings will
	 * end up in different groups. Bad luck.
	 */
	ns = cpumask_weight(topology_sibling_cpumask(raw_smp_processor_id()));
	tmigr_cores_per_group = TMIGR_CHILDS_PER_GROUP;
	if (ns >= 2 && ns < TMIGR_CHILDS_PER_GROUP)
		tmigr_cores_per_group /= ns;

	/*
	 * Calculate the required hierarchy levels. Unfortunately there is no
	 * reliable information available, unless all possible CPUs have been
	 * brought up and all numa nodes are populated.
	 *
	 * Estimate the number of levels with the number of possible nodes and
	 * the number of possible cpus. Assume CPUs are spread evenly accross
	 * nodes. We cannot rely on cpumask_of_node() because there only already
	 * online CPUs are considered.
	 */
	cpus_per_node = DIV_ROUND_UP(ncpus, nnodes);

	/* Calc the hierarchy levels required to hold the CPUs of a node */
	cpulvl = DIV_ROUND_UP(order_base_2(cpus_per_node),
			      ilog2(TMIGR_CHILDS_PER_GROUP));

	/* Calculate the extra levels to connect all nodes */
	nodelvl = DIV_ROUND_UP(order_base_2(nnodes),
			       ilog2(TMIGR_CHILDS_PER_GROUP));

	tmigr_hierarchy_levels = cpulvl + nodelvl;

	/*
	 * If a numa node spawns more than one CPU level group then the next
	 * level(s) of the hierarchy contains groups which handle all CPU groups
	 * of the same numa node. The level above goes accross numa nodes. Store
	 * this information for the setup code to decide when node matching is
	 * not longer required.
	 */
	tmigr_crossnode_level = cpulvl;

	sz = sizeof(struct list_head) * tmigr_hierarchy_levels;
	tmigr_level_list = kzalloc(sz, GFP_KERNEL);
	if (!tmigr_level_list)
		goto err;

	for (i = 0; i < tmigr_hierarchy_levels; i++)
		INIT_LIST_HEAD(&tmigr_level_list[i]);

	pr_info("Timer migration: %d hierarchy levels; %d childs per group;"
		" %d cores_per_group; %d crossnode level\n",
		tmigr_hierarchy_levels, TMIGR_CHILDS_PER_GROUP,
		tmigr_cores_per_group, tmigr_crossnode_level);

	ret = cpuhp_setup_state(CPUHP_AP_TMIGR_ONLINE, "tmigr:online",
				tmigr_cpu_online, tmigr_cpu_offline);
	if (ret)
		goto err;

	static_branch_enable(&tmigr_enabled);

	return 0;

err:
	pr_err("Timer migration setup failed\n");
	return ret;
}
late_initcall(tmigr_init);
