#ifdef CONFIG_CGROUP_CPUACCT

extern void cpuacct_charge(struct task_struct *tsk, u64 cputime);
extern void cpuacct_account_field(struct task_struct *tsk, int index, u64 val);
extern void cpuacct_cpu_stats_show(struct seq_file *sf);

#else

static inline void cpuacct_charge(struct task_struct *tsk, u64 cputime)
{
}

static inline void
cpuacct_account_field(struct task_struct *tsk, int index, u64 val)
{
}

static inline void cpuacct_cpu_stats_show(struct seq_file *sf)
{
}

#endif
