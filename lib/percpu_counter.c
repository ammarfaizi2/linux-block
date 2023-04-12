// SPDX-License-Identifier: GPL-2.0
/*
 * Fast batching percpu counters.
 */

#include <linux/percpu_counter.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/debugobjects.h>

#ifdef CONFIG_HOTPLUG_CPU
static LIST_HEAD(percpu_counters);
static DEFINE_RAW_SPINLOCK(percpu_counters_lock);
#endif

#ifdef CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER

static const struct debug_obj_descr percpu_counter_debug_descr;

static bool percpu_counter_fixup_free(void *addr, enum debug_obj_state state)
{
	struct percpu_counter *fbc = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		percpu_counter_destroy(fbc);
		debug_object_free(fbc, &percpu_counter_debug_descr);
		return true;
	default:
		return false;
	}
}

static const struct debug_obj_descr percpu_counter_debug_descr = {
	.name		= "percpu_counter",
	.fixup_free	= percpu_counter_fixup_free,
};

static inline void debug_percpu_counter_activate(struct percpu_counter *fbc)
{
	debug_object_init(fbc, &percpu_counter_debug_descr);
	debug_object_activate(fbc, &percpu_counter_debug_descr);
}

static inline void debug_percpu_counter_deactivate(struct percpu_counter *fbc)
{
	debug_object_deactivate(fbc, &percpu_counter_debug_descr);
	debug_object_free(fbc, &percpu_counter_debug_descr);
}

#else	/* CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER */
static inline void debug_percpu_counter_activate(struct percpu_counter *fbc)
{ }
static inline void debug_percpu_counter_deactivate(struct percpu_counter *fbc)
{ }
#endif	/* CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER */

void percpu_counter_set(struct percpu_counter *fbc, s64 amount)
{
	int cpu;
	unsigned long flags;

	raw_spin_lock_irqsave(&fbc->lock, flags);
	for_each_possible_cpu(cpu) {
		s32 *pcount = per_cpu_ptr(fbc->counters, cpu);
		*pcount = 0;
	}
	fbc->count = amount;
	raw_spin_unlock_irqrestore(&fbc->lock, flags);
}
EXPORT_SYMBOL(percpu_counter_set);

/*
 * local_irq_save() is needed to make the function irq safe:
 * - The slow path would be ok as protected by an irq-safe spinlock.
 * - this_cpu_add would be ok as it is irq-safe by definition.
 * But:
 * The decision slow path/fast path and the actual update must be atomic, too.
 * Otherwise a call in process context could check the current values and
 * decide that the fast path can be used. If now an interrupt occurs before
 * the this_cpu_add(), and the interrupt updates this_cpu(*fbc->counters),
 * then the this_cpu_add() that is executed after the interrupt has completed
 * can produce values larger than "batch" or even overflows.
 */
void percpu_counter_add_batch(struct percpu_counter *fbc, s64 amount, s32 batch)
{
	s64 count;
	unsigned long flags;

	local_irq_save(flags);
	count = __this_cpu_read(*fbc->counters) + amount;
	if (abs(count) >= batch) {
		raw_spin_lock(&fbc->lock);
		fbc->count += count;
		__this_cpu_sub(*fbc->counters, count - amount);
		raw_spin_unlock(&fbc->lock);
	} else {
		this_cpu_add(*fbc->counters, amount);
	}
	local_irq_restore(flags);
}
EXPORT_SYMBOL(percpu_counter_add_batch);

/*
 * For percpu_counter with a big batch, the devication of its count could
 * be big, and there is requirement to reduce the deviation, like when the
 * counter's batch could be runtime decreased to get a better accuracy,
 * which can be achieved by running this sync function on each CPU.
 */
void percpu_counter_sync(struct percpu_counter *fbc)
{
	unsigned long flags;
	s64 count;

	raw_spin_lock_irqsave(&fbc->lock, flags);
	count = __this_cpu_read(*fbc->counters);
	fbc->count += count;
	__this_cpu_sub(*fbc->counters, count);
	raw_spin_unlock_irqrestore(&fbc->lock, flags);
}
EXPORT_SYMBOL(percpu_counter_sync);

/*
 * Add up all the per-cpu counts, return the result.  This is a more accurate
 * but much slower version of percpu_counter_read_positive().
 *
 * Note: This function is inherently racy against the lockless fastpath of
 * percpu_counter_add_batch() unless externaly serialized.
 */
s64 __percpu_counter_sum(struct percpu_counter *fbc)
{
	s64 ret;
	int cpu;
	unsigned long flags;

	raw_spin_lock_irqsave(&fbc->lock, flags);
	ret = fbc->count;
	for_each_online_cpu(cpu)
		ret += *per_cpu_ptr(fbc->counters, cpu);
	raw_spin_unlock_irqrestore(&fbc->lock, flags);
	return ret;
}
EXPORT_SYMBOL(__percpu_counter_sum);

int __percpu_counter_init(struct percpu_counter *fbc, s64 amount, gfp_t gfp,
			  struct lock_class_key *key)
{
	unsigned long flags __maybe_unused;

	raw_spin_lock_init(&fbc->lock);
	lockdep_set_class(&fbc->lock, key);
	fbc->count = amount;
	fbc->counters = alloc_percpu_gfp(s32, gfp);
	if (!fbc->counters)
		return -ENOMEM;

	debug_percpu_counter_activate(fbc);

#ifdef CONFIG_HOTPLUG_CPU
	INIT_LIST_HEAD(&fbc->list);
	raw_spin_lock_irqsave(&percpu_counters_lock, flags);
	list_add(&fbc->list, &percpu_counters);
	raw_spin_unlock_irqrestore(&percpu_counters_lock, flags);
#endif
	return 0;
}
EXPORT_SYMBOL(__percpu_counter_init);

void percpu_counter_destroy(struct percpu_counter *fbc)
{
	unsigned long flags __maybe_unused;

	if (!fbc->counters)
		return;

	debug_percpu_counter_deactivate(fbc);

#ifdef CONFIG_HOTPLUG_CPU
	raw_spin_lock_irqsave(&percpu_counters_lock, flags);
	list_del(&fbc->list);
	raw_spin_unlock_irqrestore(&percpu_counters_lock, flags);
#endif
	free_percpu(fbc->counters);
	fbc->counters = NULL;
}
EXPORT_SYMBOL(percpu_counter_destroy);

int percpu_counter_batch __read_mostly = 32;
EXPORT_SYMBOL(percpu_counter_batch);

static void compute_batch_value(int offs)
{
	int nr = num_online_cpus() + offs;

	percpu_counter_batch = max(32, nr * 2);
}

static int percpu_counter_cpu_starting(unsigned int cpu)
{
	/* If invoked during hotplug @cpu is not yet marked online. */
	compute_batch_value(cpu_online(cpu) ? 0 : 1);
	return 0;
}

static int percpu_counter_cpu_dying(unsigned int cpu)
{
#ifdef CONFIG_HOTPLUG_CPU
	struct percpu_counter *fbc;
	unsigned long flags;

	compute_batch_value(0);

	raw_spin_lock_irqsave(&percpu_counters_lock, flags);
	list_for_each_entry(fbc, &percpu_counters, list) {
		s32 *pcount;

		raw_spin_lock(&fbc->lock);
		pcount = per_cpu_ptr(fbc->counters, cpu);
		fbc->count += *pcount;
		*pcount = 0;
		raw_spin_unlock(&fbc->lock);
	}
	raw_spin_unlock_irqrestore(&percpu_counters_lock, flags);
#endif
	return 0;
}

/*
 * Compare counter against given value.
 * Return 1 if greater, 0 if equal and -1 if less
 */
int __percpu_counter_compare(struct percpu_counter *fbc, s64 rhs, s32 batch)
{
	s64	count;

	count = percpu_counter_read(fbc);
	/* Check to see if rough count will be sufficient for comparison */
	if (abs(count - rhs) > (batch * num_online_cpus())) {
		if (count > rhs)
			return 1;
		else
			return -1;
	}
	/* Need to use precise count */
	count = percpu_counter_sum(fbc);
	if (count > rhs)
		return 1;
	else if (count < rhs)
		return -1;
	else
		return 0;
}
EXPORT_SYMBOL(__percpu_counter_compare);

static int __init percpu_counter_startup(void)
{
	WARN_ON(cpuhp_setup_state(CPUHP_AP_PERCPU_COUNTER_STARTING, "lib/percpu_counter:starting",
				  percpu_counter_cpu_starting, percpu_counter_cpu_dying));
	return 0;
}
module_init(percpu_counter_startup);
