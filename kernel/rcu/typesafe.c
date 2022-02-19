// SPDX-License-Identifier: GPL-2.0+
//
// Torture test for a simple SLAB_TYPESAFE_BY_RCU use case.
//
// Copyright (C) Facebook, 2022.
//
// Author: Paul E. McKenney <paulmck@kernel.org>

#define pr_fmt(fmt) fmt

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rcupdate_trace.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/stat.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/torture.h>
#include <linux/types.h>

#define TYPESAFE_TORT_STRING "typesafe_torture"
#define TYPESAFE_TORT_FLAG TYPESAFE_TORT_STRING ": "

#define VERBOSE_TYPESAFE_TORTOUT(s, x...) \
	do { if (verbose) pr_alert(TYPESAFE_TORT_FLAG s "\n", ## x); } while (0)

#define TYPESAFE_TORTOUT_ERRSTRING(s, x...) pr_alert(TYPESAFE_TORT_FLAG "!!! " s "\n", ## x)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Paul E. McKenney <paulmck@kernel.org>");

// Wait until there are multiple CPUs before starting test.
torture_param(int, holdoff, IS_BUILTIN(CONFIG_TYPESAFE_TORTURE_TEST) ? 10 : 0,
	      "Holdoff time before test start (s)");
torture_param(int, nreaders, -1, "# reader threads, defaults to -1 for all CPUs.");
torture_param(int, nupdaters, 1, "# updater threads, defaults to 1 for a single CPU.");
torture_param(int, shutdown_secs, 0, "Shutdown time (ms), <= zero to disable.");
torture_param(int, stat_interval, 60, "Number of seconds between stats printk()s.");
torture_param(int, stutter, 5, "Number of jiffies to run/halt test, 0=disable");
torture_param(int, verbose, 0, "Enable verbose debugging printk()s");

char *torture_type = "";

#ifdef MODULE
# define TYPESAFE_TORT_SHUTDOWN 0
#else
# define TYPESAFE_TORT_SHUTDOWN 1
#endif

torture_param(bool, shutdown, TYPESAFE_TORT_SHUTDOWN, "Shutdown at end of torture test.");

struct typesafe_statistics {
	struct task_struct *task;
	int cpu;
	void (*ts_func)(struct typesafe_statistics *tsp, struct torture_random_state *trsp);
	char *ts_name;
	int ts_count;
	long long n_lookup;
	long long n_insert;
	long long n_remove;
	long long n_get_key;
	long long n_get_key_fail1; // Not present.
	long long n_get_key_fail2; // Present, but freed en passant.
	long long n_get_key_fail3; // Present, but reallocated en passant.
	long long n_put;
	long long n_put_final;
	long long n_alloc;
	long long n_alloc_fail;
};

static struct typesafe_statistics *typesafe_stats_p;
static struct task_struct *typesafe_torture_stats_task;

// Use to wait for all threads to start.
static atomic_t n_started;
static atomic_t n_errs;
static atomic_t n_ref_errs; // Ref count went to zero in reader.
static atomic_t n_lookupi_errs; // Item not found after insertion.
static atomic_t n_lookupr_errs; // Item not found before removal.
static bool typesafedone;
static char *bangstr = "";

// Print torture statistics.  Caller must ensure serialization.
static void typesafe_torture_stats_print(void)
{
	int i;
	bool isdone = READ_ONCE(typesafedone);
	struct typesafe_statistics tss = {};

	for (i = 0; i < nreaders + nupdaters; i++) {
		tss.n_lookup += typesafe_stats_p[i].n_lookup;
		tss.n_insert += typesafe_stats_p[i].n_insert;
		tss.n_remove += typesafe_stats_p[i].n_remove;
		tss.n_get_key += typesafe_stats_p[i].n_get_key;
		tss.n_get_key_fail1 += typesafe_stats_p[i].n_get_key_fail1;
		tss.n_get_key_fail2 += typesafe_stats_p[i].n_get_key_fail2;
		tss.n_get_key_fail3 += typesafe_stats_p[i].n_get_key_fail3;
		tss.n_put += typesafe_stats_p[i].n_put;
		tss.n_put_final += typesafe_stats_p[i].n_put_final;
		tss.n_alloc += typesafe_stats_p[i].n_alloc;
		tss.n_alloc_fail += typesafe_stats_p[i].n_alloc_fail;
	}
	if (atomic_read(&n_errs))
		bangstr = "!!! ";
	pr_alert("%s %stypesafe_invoked_count %s: %lld lookup: %lld insert: %lld remove: %lld get_key: %lld/%lld/%lld/%lld put: %lld/%lld alloc: %lld/%lld ",
		 TYPESAFE_TORT_FLAG, bangstr, isdone ? "VER" : "ver", tss.n_insert + tss.n_remove,
		 tss.n_lookup, tss.n_insert, tss.n_remove,
		 tss.n_get_key, tss.n_get_key_fail1, tss.n_get_key_fail2, tss.n_get_key_fail3,
		 tss.n_put, tss.n_put_final,
		 tss.n_alloc, tss.n_alloc_fail);
	pr_cont("ne: %d nre: %d nlie: %d nlre: %d\n", atomic_read(&n_errs),
		atomic_read(&n_ref_errs), atomic_read(&n_lookupi_errs),
		atomic_read(&n_lookupr_errs));
}

// Periodically prints torture statistics, if periodic statistics printing
// was specified via the stat_interval module parameter.
static int
typesafe_torture_stats(void *arg)
{
	VERBOSE_TOROUT_STRING("typesafe_torture_stats task started");
	do {
		schedule_timeout_interruptible(stat_interval * HZ);
		typesafe_torture_stats_print();
		torture_shutdown_absorb("typesafe_torture_stats");
	} while (!torture_must_stop());
	torture_kthread_stopping("typesafe_torture_stats");
	return 0;
}

// Test structure for type safety.
struct foo {
	struct list_head lh;
	atomic_t ref;
	int key;
};

static struct kmem_cache *foo_cache;
static LIST_HEAD(foo_list);
static DEFINE_SPINLOCK(foo_lock);

// Dump the list
static void __maybe_unused foo_dump(void)
{
	int i = 0;
	struct foo *p;

	list_for_each_entry_rcu(p, &foo_list, lh, lockdep_is_held(&foo_lock))
		pr_info("foo_list %2d: key: %2d ref: %d\n", ++i, p->key, atomic_read(&p->ref));
	pr_info("foo_list has %d entries.\n", i);
}

// Empty the list
static void foo_empty(void)
{
	struct foo *p;

	list_for_each_entry_rcu(p, &foo_list, lh, lockdep_is_held(&foo_lock)) {
		list_del_rcu(&p->lh);
		kmem_cache_free(foo_cache, p);
	}
}

// Attempt to look up a foo structure in the list, finding first.
static struct foo *foo_lookup(int key, struct typesafe_statistics *tsp)
{
	struct foo *p;

	tsp->n_lookup++;
	list_for_each_entry_rcu(p, &foo_list, lh, lockdep_is_held(&foo_lock))
		if (p->key == key)
			return p;
	return NULL;
}

// Insert a foo structure into the list, duplicates allowed.
static void foo_insert(struct foo *p, struct typesafe_statistics *tsp)
{
	tsp->n_insert++;
	spin_lock(&foo_lock);
	list_add_rcu(&p->lh, &foo_list);
	spin_unlock(&foo_lock);
}

// Remove the specified foo structure from the list.
static void foo_remove(struct foo *p, struct typesafe_statistics *tsp)
{
	tsp->n_remove++;
	spin_lock(&foo_lock);
	list_del_rcu(&p->lh);
	spin_unlock(&foo_lock);
}

// Put a reference to the specified foo structure, freeing if last.
static void foo_put(struct foo *p, struct typesafe_statistics *tsp)
{
	tsp->n_put++;
	if (atomic_dec_and_test(&p->ref)) {
		tsp->n_put_final++;
		kmem_cache_free(foo_cache, p);
	}
}

// Get a reference to the first foo structure with the specified key.
static struct foo *foo_get_key(int key, struct typesafe_statistics *tsp)
{
	struct foo *p;

	tsp->n_get_key++;
	rcu_read_lock();
	p = foo_lookup(key, tsp);
	if (!p) {
		tsp->n_get_key_fail1++;
	} else if (!atomic_add_unless(&p->ref, 1, 0)) {
		tsp->n_get_key_fail2++;
		p = NULL;
	} else if (p->key != key) {
		tsp->n_get_key_fail3++;
		foo_put(p, tsp);
		p = NULL;
	}
	rcu_read_unlock();
	return p;
}

// Allocate and insert a foo structure with the specified key.  Again,
// duplicates are allowed.
static struct foo *foo_alloc(int key, struct typesafe_statistics *tsp)
{
	struct foo *p;

	tsp->n_alloc++;
	p = kmem_cache_alloc(foo_cache, GFP_KERNEL);
	if (!p) {
		tsp->n_alloc_fail++;
		return NULL;
	}
	p->key = key;
	atomic_set_release(&p->ref, 1);
	return p;
}

// Typesafe reader test function.  Looks up and locks its element.
static void typesafe_torture_reader(struct typesafe_statistics *tsp,
				    struct torture_random_state *trsp)
{
	struct foo *p;

	p = foo_get_key(tsp->cpu, tsp);
	if (p)
		if (WARN_ON_ONCE(!atomic_read(&p->ref)))
			atomic_inc(&n_ref_errs);
	if (!(torture_random(trsp) & 0xff)) {
		schedule_timeout_interruptible(1);
		if (p && WARN_ON_ONCE(!atomic_read(&p->ref)))
			atomic_inc(&n_ref_errs);
	}
	if (p)
		foo_put(p, tsp);
}

// Typesafe updater test kthread.  Mutates the list.
static void typesafe_torture_updater(struct typesafe_statistics *tsp,
				     struct torture_random_state *trsp)
{
	int key;
	struct foo *p;

	key = torture_random(trsp) % nreaders;
	if (typesafe_stats_p[key].ts_count) {
		p = foo_lookup(key, tsp);
		if (WARN_ON_ONCE(!p)) {
			atomic_inc(&n_lookupr_errs);
		} else {
			foo_remove(p, tsp);
			foo_put(p, tsp);
			typesafe_stats_p[key].ts_count--;
			// pr_info("foo_list removed key %d\n", key); // @@@
		}
	} else {
		p = foo_alloc(key, tsp);
		foo_insert(p, tsp);
		typesafe_stats_p[key].ts_count++;
		// pr_info("foo_list added key %d\n", key); // @@@
		if (WARN_ON_ONCE(!foo_lookup(key, tsp)))
			atomic_inc(&n_lookupi_errs);
	}
	// foo_dump(); // @@@
	// schedule_timeout_uninterruptible(HZ); // @@@
}

static int typesafe_torture_child(void *arg)
{
	int cpu;
	int curcpu;
	DEFINE_TORTURE_RANDOM(rand);
	struct typesafe_statistics *tsp = (struct typesafe_statistics *)arg;

	VERBOSE_TYPESAFE_TORTOUT("%s %d: task started", tsp->ts_name, tsp->cpu);
	cpu = tsp->cpu % nr_cpu_ids;
	WARN_ON_ONCE(set_cpus_allowed_ptr(current, cpumask_of(cpu)));
	set_user_nice(current, MAX_NICE);
	if (holdoff)
		schedule_timeout_interruptible(holdoff * HZ);

	VERBOSE_TYPESAFE_TORTOUT("%s %d: Waiting for all typesafe torturers from cpu %d", tsp->ts_name, tsp->cpu, raw_smp_processor_id());

	// Make sure that the CPU is affinitized appropriately during testing.
	curcpu = raw_smp_processor_id();
	WARN_ONCE(curcpu != tsp->cpu % nr_cpu_ids,
		  "%s: Wanted CPU %d, running on %d, nr_cpu_ids = %d\n",
		  __func__, tsp->cpu, curcpu, nr_cpu_ids);

	if (!atomic_dec_return(&n_started))
		while (atomic_read_acquire(&n_started)) {
			if (torture_must_stop()) {
				VERBOSE_TYPESAFE_TORTOUT("%s %d ended before starting", tsp->ts_name, tsp->cpu);
				goto end;
			}
			schedule_timeout_uninterruptible(1);
		}

	VERBOSE_TYPESAFE_TORTOUT("%s %d started", tsp->ts_name, tsp->cpu);

	do {
		tsp->ts_func(tsp, &rand);
		cond_resched();
		stutter_wait(tsp->ts_name);
	} while (!torture_must_stop());

	VERBOSE_TYPESAFE_TORTOUT("%s %d ended", tsp->ts_name, tsp->cpu);
end:
	torture_kthread_stopping(tsp->ts_name);
	return 0;
}

static void
typesafe_torture_print_module_parms(const char *tag)
{
	pr_alert(TYPESAFE_TORT_FLAG
		 "--- %s:  verbose=%d holdoff=%d nreaders=%d nupdaters=%d shutdown_secs=%d stat_interval=%d stutter=%d\n", tag,
		 verbose, holdoff, nreaders, nupdaters, shutdown, stat_interval, stutter);
}

static void typesafe_torture_cleanup(void)
{
	int i;
	int nthreads = nreaders + nupdaters;

	if (torture_cleanup_begin())
		return;

	WRITE_ONCE(typesafedone, true);
	if (!nthreads || !typesafe_stats_p)
		goto end;
	for (i = 0; i < nthreads; i++)
		torture_stop_kthread(typesafe_stats_p[i].ts_name, typesafe_stats_p[i].task);
	torture_stop_kthread(typesafe_torture_stats, typesafe_torture_stats_task);
	typesafe_torture_stats_print();  // -After- the stats thread is stopped!
	kfree(typesafe_stats_p);  // -After- the last stats print has completed!
	typesafe_stats_p = NULL;

	if (atomic_read(&n_errs) || atomic_read(&n_ref_errs) ||
			atomic_read(&n_lookupi_errs) || atomic_read(&n_lookupr_errs))
		typesafe_torture_print_module_parms("End of test: FAILURE");
	else if (torture_onoff_failures())
		typesafe_torture_print_module_parms("End of test: LOCK_HOTPLUG");
	else
		typesafe_torture_print_module_parms("End of test: SUCCESS");

	foo_dump();
	foo_empty();
	kmem_cache_destroy(foo_cache);
	foo_cache = NULL;

end:
	torture_cleanup_end();
}

static int __init typesafe_torture_init(void)
{
	long i;
	int firsterr = 0;
	int nthreads;

	if (!torture_init_begin(TYPESAFE_TORT_STRING, verbose))
		return -EBUSY;

	typesafe_torture_print_module_parms("Start of test");

	foo_cache = kmem_cache_create("foo", sizeof(struct foo), sizeof(void *),
				      SLAB_TYPESAFE_BY_RCU, NULL);
	if (WARN_ON_ONCE(!foo_cache))
		goto unwind;

	if (shutdown_secs > 0) {
		firsterr = torture_shutdown_init(shutdown_secs, typesafe_torture_cleanup);
		if (torture_init_error(firsterr))
			goto unwind;
	}
	if (stutter > 0) {
		firsterr = torture_stutter_init(stutter, stutter);
		if (torture_init_error(firsterr))
			goto unwind;
	}

	// Typesafe reader and updater tasks.
	if (nreaders < 0)
		nreaders = num_online_cpus();
	nthreads = nreaders + nupdaters;
	typesafe_stats_p = kcalloc(nthreads, sizeof(typesafe_stats_p[0]), GFP_KERNEL);
	if (!typesafe_stats_p) {
		TYPESAFE_TORTOUT_ERRSTRING("out of memory");
		firsterr = -ENOMEM;
		goto unwind;
	}

	VERBOSE_TYPESAFE_TORTOUT("Starting %d typesafe_torture_reader() threads", nthreads);

	atomic_set(&n_started, nthreads);
	for (i = 0; i < nthreads; i++) {
		typesafe_stats_p[i].cpu = i;
		if (i < nreaders) {
			typesafe_stats_p[i].ts_func = typesafe_torture_reader;
			typesafe_stats_p[i].ts_name = "typesafe_torture_reader";
		} else {
			typesafe_stats_p[i].ts_func = typesafe_torture_updater;
			typesafe_stats_p[i].ts_name = "typesafe_torture_updater";
		}
		firsterr = torture_create_kthread(typesafe_torture_child,
						  (void *)&typesafe_stats_p[i],
						  typesafe_stats_p[i].task);
		if (torture_init_error(firsterr))
			goto unwind;
	}
	if (stat_interval > 0) {
		firsterr = torture_create_kthread(typesafe_torture_stats, NULL,
						  typesafe_torture_stats_task);
		if (torture_init_error(firsterr))
			goto unwind;
	}

	torture_init_end();
	return 0;

unwind:
	torture_init_end();
	typesafe_torture_cleanup();
	if (shutdown_secs) {
		WARN_ON(!IS_MODULE(CONFIG_TYPESAFE_TORTURE_TEST));
		kernel_power_off();
	}
	return firsterr;
}

module_init(typesafe_torture_init);
module_exit(typesafe_torture_cleanup);
