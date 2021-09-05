/*
 * We generate the PER_TASK_OFFSET_ offsets early during the build, using this file.
 */

#include <linux/kbuild.h>

#define DEF_PER_TASK(name) DEFINE(PER_TASK_OFFSET__##name, offsetof(struct task_struct_per_task, name))

void __used per_task_common(void)
{
#ifdef CONFIG_THREAD_INFO_IN_TASK
	DEF_PER_TASK(ti);
#endif
	DEF_PER_TASK(stack);
	DEF_PER_TASK(usage);
	DEF_PER_TASK(flags);
	DEF_PER_TASK(ptrace);

#ifdef CONFIG_SMP
	DEF_PER_TASK(on_cpu);
	DEF_PER_TASK(wake_entry);
#ifdef CONFIG_THREAD_INFO_IN_TASK
	DEF_PER_TASK(cpu);
#endif
	DEF_PER_TASK(wakee_flips);
	DEF_PER_TASK(wakee_flip_decay_ts);
	DEF_PER_TASK(last_wakee);
	DEF_PER_TASK(recent_used_cpu);
	DEF_PER_TASK(wake_cpu);
#endif
	DEF_PER_TASK(on_rq);
	DEF_PER_TASK(sched_class);
	DEF_PER_TASK(se);
	DEF_PER_TASK(rt);
	DEF_PER_TASK(dl);

#ifdef CONFIG_SCHED_CORE
	DEF_PER_TASK(core_node);
	DEF_PER_TASK(core_cookie);
	DEF_PER_TASK(core_occupation);
#endif

#ifdef CONFIG_CGROUP_SCHED
	DEF_PER_TASK(sched_task_group);
#endif

#ifdef CONFIG_UCLAMP_TASK
	DEF_PER_TASK(uclamp_req);
	DEF_PER_TASK(uclamp);
#endif

#ifdef CONFIG_PREEMPT_NOTIFIERS
	DEF_PER_TASK(preempt_notifiers);
#endif

#ifdef CONFIG_BLK_DEV_IO_TRACE
	DEF_PER_TASK(btrace_seq);
#endif

	DEF_PER_TASK(cpus_ptr);
	DEF_PER_TASK(user_cpus_ptr);
	DEF_PER_TASK(cpus_mask);
#ifdef CONFIG_TASKS_RCU
	DEF_PER_TASK(rcu_tasks_nvcsw);
	DEF_PER_TASK(rcu_tasks_holdout);
	DEF_PER_TASK(rcu_tasks_idx);
	DEF_PER_TASK(rcu_tasks_idle_cpu);
	DEF_PER_TASK(rcu_tasks_holdout_list);
#endif
	DEF_PER_TASK(sched_info);

#ifdef CONFIG_SMP
	DEF_PER_TASK(pushable_tasks);
	DEF_PER_TASK(pushable_dl_tasks);
#endif
	DEF_PER_TASK(vmacache);

#ifdef SPLIT_RSS_COUNTING
	DEF_PER_TASK(rss_stat);
#endif
	DEF_PER_TASK(restart_block);
	DEF_PER_TASK(prev_cputime);
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	DEF_PER_TASK(vtime);
#endif
#ifdef CONFIG_NO_HZ_FULL
	DEF_PER_TASK(tick_dep_mask);
#endif
	DEF_PER_TASK(posix_cputimers);

#ifdef CONFIG_POSIX_CPU_TIMERS_TASK_WORK
	DEF_PER_TASK(posix_cputimers_work);
#endif

#ifdef CONFIG_SYSVIPC
	DEF_PER_TASK(sysvsem);
	DEF_PER_TASK(sysvshm);
#endif
	DEF_PER_TASK(blocked);
	DEF_PER_TASK(real_blocked);
	DEF_PER_TASK(saved_sigmask);
	DEF_PER_TASK(pending);
	DEF_PER_TASK(loginuid);
	DEF_PER_TASK(seccomp);
	DEF_PER_TASK(alloc_lock);

	DEF_PER_TASK(pi_lock);

#ifdef CONFIG_RT_MUTEXES
	DEF_PER_TASK(pi_waiters);
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	DEF_PER_TASK(blocked_on);
#endif
	DEF_PER_TASK(last_siginfo);
#ifdef CONFIG_CPUSETS
	DEF_PER_TASK(mems_allowed);
	DEF_PER_TASK(mems_allowed_seq);
	DEF_PER_TASK(cpuset_mem_spread_rotor);
	DEF_PER_TASK(cpuset_slab_spread_rotor);
#endif
	DEF_PER_TASK(futex_exit_mutex);
#ifdef CONFIG_PERF_EVENTS
	DEF_PER_TASK(perf_event_ctxp);
	DEF_PER_TASK(perf_event_mutex);
	DEF_PER_TASK(perf_event_list);
#endif
#ifdef CONFIG_RSEQ
	DEF_PER_TASK(rseq);
#endif
	DEF_PER_TASK(tlb_ubc);

	DEF_PER_TASK(rcu_users);
	DEF_PER_TASK(rcu);

	DEF_PER_TASK(task_frag);

#ifdef CONFIG_KCSAN
	DEF_PER_TASK(kcsan_ctx);
#ifdef CONFIG_TRACE_IRQFLAGS
	DEF_PER_TASK(kcsan_save_irqtrace);
#endif
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	DEF_PER_TASK(trace_overrun);
	DEF_PER_TASK(tracing_graph_pause);
#endif
#ifdef CONFIG_KMAP_LOCAL
	DEF_PER_TASK(kmap_ctrl);
#endif
	DEF_PER_TASK(pagefault_disabled);
#ifdef CONFIG_VMAP_STACK
	DEF_PER_TASK(stack_vm_area);
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
	DEF_PER_TASK(stack_refcount);
#endif
#ifdef CONFIG_KRETPROBES
	DEF_PER_TASK(kretprobe_instances);
#endif
	DEF_PER_TASK(thread);
	DEF_PER_TASK(_end);
}
