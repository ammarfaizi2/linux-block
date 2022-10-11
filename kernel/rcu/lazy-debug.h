#include <linux/string.h>
#include <linux/spinlock.h>

#ifdef CONFIG_RCU_LAZY_DEBUG
#include <linux/preempt.h>
#include <trace/events/sched.h>

static DEFINE_PER_CPU(bool, rcu_lazy_cb_exec) = false;
static DEFINE_PER_CPU(void *, rcu_lazy_ip) = NULL;

static DEFINE_RAW_SPINLOCK(lazy_funcs_lock);

#define FUNC_SIZE 1024
static unsigned long lazy_funcs[FUNC_SIZE];
static int nr_funcs;

static void __find_func(unsigned long ip, int *B, int *E, int *N)
{
	unsigned long *p;
	int b, e, n;

	b = n = 0;
	e = nr_funcs - 1;

	while (b <= e) {
		n = (b + e) / 2;
		p = &lazy_funcs[n];
		if (ip > *p) {
			b = n + 1;
		} else if (ip < *p) {
			e = n - 1;
		} else
			break;
	}

	*B = b;
	*E = e;
	*N = n;

	return;
}

static bool lazy_func_exists(void* ip_ptr)
{
	int b, e, n;
	unsigned long flags;
	unsigned long ip = (unsigned long)ip_ptr;

	raw_spin_lock_irqsave(&lazy_funcs_lock, flags);
	__find_func(ip, &b, &e, &n);
	raw_spin_unlock_irqrestore(&lazy_funcs_lock, flags);

	return b <= e;
}

static int lazy_func_add(void* ip_ptr)
{
	int b, e, n;
	unsigned long flags;
	unsigned long ip = (unsigned long)ip_ptr;

	raw_spin_lock_irqsave(&lazy_funcs_lock, flags);
	if (nr_funcs >= FUNC_SIZE) {
		raw_spin_unlock_irqrestore(&lazy_funcs_lock, flags);
		return -1;
	}

	__find_func(ip, &b, &e, &n);

	if (b > e) {
		if (n != nr_funcs)
			memmove(&lazy_funcs[n+1], &lazy_funcs[n],
				(sizeof(*lazy_funcs) * (nr_funcs - n)));

		lazy_funcs[n] = ip;
		nr_funcs++;
	}

	raw_spin_unlock_irqrestore(&lazy_funcs_lock, flags);
	return 0;
}

static void rcu_set_lazy_context(void *ip_ptr)
{
	bool *flag = this_cpu_ptr(&rcu_lazy_cb_exec);
	*flag = lazy_func_exists(ip_ptr);

	if (*flag) {
		*this_cpu_ptr(&rcu_lazy_ip) = ip_ptr;
	} else {
		*this_cpu_ptr(&rcu_lazy_ip) = NULL;
	}
}

static void rcu_reset_lazy_context(void)
{
	bool *flag = this_cpu_ptr(&rcu_lazy_cb_exec);
	*flag = false;
}

static bool rcu_is_lazy_context(void)
{
	return *(this_cpu_ptr(&rcu_lazy_cb_exec));
}

static void
probe_waking(void *ignore, struct task_struct *p)
{
	// kworker wake ups don't appear to cause performance issues.
	// Ignore for now.
	if (!strncmp(p->comm, "kworker", 7))
		return;

	if (WARN_ON(!in_nmi() && !in_hardirq() && rcu_is_lazy_context())) {
		pr_err("*****************************************************\n");
		pr_err("RCU: A wake up has been detected from a lazy callback!\n");
		pr_err("The callback name is: %ps\n", *this_cpu_ptr(&rcu_lazy_ip));
		pr_err("The task it woke up is: %s (%d)\n", p->comm, p->pid);
		pr_err("This could cause performance issues! Check the stack.\n");
		pr_err("*****************************************************\n");
	}
}

static void rcu_lazy_debug_init(void)
{
	int ret;
	pr_info("RCU Lazy CB debugging is turned on, system may be slow.\n");

	ret = register_trace_sched_waking(probe_waking, NULL);
	if (ret)
		pr_info("RCU: Lazy debug ched_waking probe could not be registered.");
}

#else

static int lazy_func_add(void* ip_ptr)
{
	return -1;
}


static void rcu_set_lazy_context(void *ip_ptr)
{
}

static void rcu_reset_lazy_context(void)
{
}

static void rcu_lazy_debug_init(void)
{
}

#endif
