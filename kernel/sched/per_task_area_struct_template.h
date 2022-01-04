
/*
 * This is the primary definition of per_task() fields,
 * which gets turned into the 'struct task_struct_per_task'
 * structure definition, and into offset definitions,
 * in per_task_area_struct.h and per_task_area_struct_defs.h:
 */

#ifdef CONFIG_THREAD_INFO_IN_TASK
	/*
	 * For reasons of header soup (see current_thread_info()), this
	 * must be the first element of task_struct.
	 */
	DEF(	struct thread_info,		ti						);
#endif
	DEF(	void *,				stack						);
	DEF(	refcount_t,			usage						);

	/* Per task flags (PF_*), defined further below: */
	DEF(	unsigned int,			flags						);
	DEF(	unsigned int,			ptrace						);

#ifdef CONFIG_SMP
	DEF(	int,				on_cpu						);
	DEF(	struct __call_single_node,	wake_entry					);
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/* Current CPU: */
	DEF(	unsigned int,			cpu						);
#endif
	DEF(	unsigned int,			wakee_flips					);
	DEF(	unsigned long,			wakee_flip_decay_ts				);
	DEF(	struct task_struct *,		last_wakee					);
	DEF(	int,				recent_used_cpu					);
	DEF(	int,				wake_cpu					);
#endif
	DEF(	int,				on_rq						);
	DEF(	struct sched_class *,		sched_class					);
	DEF(	struct sched_entity,		se						);
	DEF(	struct sched_rt_entity,		rt						);
	DEF(	struct sched_dl_entity,		dl						);

#ifdef CONFIG_SCHED_CORE
	DEF(	struct rb_node,			core_node					);
	DEF(	unsigned long,			core_cookie					);
	DEF(	unsigned int,			core_occupation					);
#endif

#ifdef CONFIG_CGROUP_SCHED
	DEF(	struct task_group *,		sched_task_group				);
#endif

#ifdef CONFIG_UCLAMP_TASK
	/*
	 * Clamp values requested for a scheduling entity.
	 * Must be updated with task_rq_lock() held.
	 */
	DEF_A(	struct uclamp_se,		uclamp_req, [UCLAMP_CNT]			);
	/*
	 * Effective clamp values used for a scheduling entity.
	 * Must be updated with task_rq_lock() held.
	 */
	DEF_A(	struct uclamp_se,		uclamp, [UCLAMP_CNT]				);
#endif

#ifdef CONFIG_PREEMPT_NOTIFIERS
	/* List of struct preempt_notifier: */
	DEF(	struct hlist_head,		preempt_notifiers				);
#endif

#ifdef CONFIG_BLK_DEV_IO_TRACE
	DEF(	unsigned int,			btrace_seq					);
#endif

	DEF(	const cpumask_t *,		cpus_ptr					);
	DEF(	cpumask_t *,			user_cpus_ptr					);
	DEF(	cpumask_t,			cpus_mask					);
#ifdef CONFIG_TASKS_RCU
	DEF(	unsigned long,			rcu_tasks_nvcsw					);
	DEF(	u8,				rcu_tasks_holdout				);
	DEF(	u8,				rcu_tasks_idx					);
	DEF(	int,				rcu_tasks_idle_cpu				);
	DEF(	struct list_head,		rcu_tasks_holdout_list				);
#endif /* #ifdef CONFIG_TASKS_RCU */
	DEF(	struct sched_info,		sched_info					);

#ifdef CONFIG_SMP
	DEF(	struct plist_node,		pushable_tasks					);
	DEF(	struct rb_node,			pushable_dl_tasks				);
#endif
	/* Per-thread vma caching: */
	DEF(	struct vmacache,		vmacache					);

#ifdef SPLIT_RSS_COUNTING
	DEF(	struct task_rss_stat,		rss_stat					);
#endif
	DEF(	struct restart_block,		restart_block					);
	DEF(	struct prev_cputime,		prev_cputime					);
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	DEF(	struct vtime,			vtime						);
#endif
#ifdef CONFIG_NO_HZ_FULL
	DEF(	atomic_t,			tick_dep_mask					);
#endif
	/* Empty if CONFIG_POSIX_CPUTIMERS=n */
	DEF(	struct posix_cputimers,		posix_cputimers					);

#ifdef CONFIG_POSIX_CPU_TIMERS_TASK_WORK
	DEF(	struct posix_cputimers_work,	posix_cputimers_work				);
#endif

#ifdef CONFIG_SYSVIPC
	DEF(	struct sysv_sem,		sysvsem						);
	DEF(	struct sysv_shm,		sysvshm						);
#endif
	DEF(	sigset_t,			blocked						);
	DEF(	sigset_t,			real_blocked					);
	/* Restored if set_restore_sigmask() was used: */
	DEF(	sigset_t,			saved_sigmask					);
	DEF(	struct sigpending,		pending						);
	DEF(	kuid_t,				loginuid					);
	DEF(	struct seccomp,			seccomp						);
	/* Protection against (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed, mempolicy: */
	DEF(	spinlock_t,			alloc_lock					);

	/* Protection of the PI data structures: */
	DEF(	raw_spinlock_t,			pi_lock						);

#ifdef CONFIG_RT_MUTEXES
	/* PI waiters blocked on a rt_mutex held by this task: */
	DEF(	struct rb_root_cached,		pi_waiters					);
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	/* Mutex deadlock detection: */
	DEF(	struct mutex_waiter *,		blocked_on					);
#endif
	DEF(	kernel_siginfo_t *,		last_siginfo					);
#ifdef CONFIG_CPUSETS
	/* Protected by ->alloc_lock: */
	DEF(	nodemask_t,			mems_allowed					);
	/* Sequence number to catch updates: */
	DEF(	seqcount_spinlock_t,		mems_allowed_seq				);
	DEF(	int,				cpuset_mem_spread_rotor				);
	DEF(	int,				cpuset_slab_spread_rotor			);
#endif
	DEF(	struct mutex,			futex_exit_mutex				);
#ifdef CONFIG_PERF_EVENTS
	DEF_A(	struct perf_event_context *,	perf_event_ctxp, [perf_nr_task_contexts]	);
	DEF(	struct mutex,			perf_event_mutex				);
	DEF(	struct list_head,		perf_event_list					);
#endif
#ifdef CONFIG_RSEQ
	DEF(	struct rseq __user *,		rseq						);
#endif
	DEF(	struct tlbflush_unmap_batch,	tlb_ubc						);

	DEF(	refcount_t,			rcu_users					);
	DEF(	struct rcu_head,		rcu						);

	DEF(	struct page_frag,		task_frag					);

#ifdef CONFIG_KCSAN
	DEF(	struct kcsan_ctx,		kcsan_ctx					);
#ifdef CONFIG_TRACE_IRQFLAGS
	DEF(	struct irqtrace_events,		kcsan_save_irqtrace				);
#endif
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

	/*
	 * Number of functions that haven't been traced
	 * because of depth overrun:
	 */
	DEF(	atomic_t,			trace_overrun					);

	/* Pause tracing: */
	DEF(	atomic_t,			tracing_graph_pause				);
#endif
#ifdef CONFIG_KMAP_LOCAL
	DEF(	struct kmap_ctrl,		kmap_ctrl					);
#endif
	DEF(	int,				pagefault_disabled				);
#ifdef CONFIG_VMAP_STACK
	DEF(	struct vm_struct *,		stack_vm_area					);
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/* A live task holds one reference: */
	DEF(	refcount_t,			stack_refcount					);
#endif
#ifdef CONFIG_KRETPROBES
	DEF(	struct llist_head,		kretprobe_instances				);
#endif

	/* CPU-specific state of this task: */
	DEF(	struct thread_struct,		thread						);

	DEF(	char,				_end						);
