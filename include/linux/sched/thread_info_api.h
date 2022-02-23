/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_THREAD_INFO_API_H
#define _LINUX_SCHED_THREAD_INFO_API_H

#include <linux/sched.h>
#include <linux/sched/thread.h>
#include <linux/thread_info.h>

union thread_union {
#ifndef CONFIG_ARCH_TASK_STRUCT_ON_STACK
	struct task_struct task;
#endif
#ifndef CONFIG_THREAD_INFO_IN_TASK
	struct thread_info thread_info;
#endif
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

#ifndef CONFIG_THREAD_INFO_IN_TASK
extern struct thread_info init_thread_info;
#endif

extern unsigned long init_stack[THREAD_SIZE / sizeof(unsigned long)];

#ifdef CONFIG_THREAD_INFO_IN_TASK

DECLARE_PER_TASK(struct thread_info, ti);

# define task_thread_info(task) (&per_task(task, ti))
#elif !defined(__HAVE_THREAD_FUNCTIONS)
# define task_thread_info(task)	((struct thread_info *)per_task(task, stack))
#endif

#include <asm/current.h>

#ifndef current_thread_info
static inline struct thread_info *current_thread_info(void)
{
	return task_thread_info(current);
}
#endif

/*
 * Set thread flags in other task's structures.
 * See asm/thread_info.h for TIF_xxxx flags available:
 */
static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void update_tsk_thread_flag(struct task_struct *tsk, int flag,
					  bool value)
{
	update_ti_thread_flag(task_thread_info(tsk), flag, value);
}

static inline int test_and_set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_and_clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void set_tsk_need_resched(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline void clear_tsk_need_resched(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline int test_tsk_need_resched(struct task_struct *tsk)
{
	return unlikely(test_tsk_thread_flag(tsk,TIF_NEED_RESCHED));
}

/*
 * Wrappers for p->thread_info->cpu access. No-op on UP.
 */
#ifdef CONFIG_SMP

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return READ_ONCE(task_thread_info(p)->cpu);
}

extern void set_task_cpu(struct task_struct *p, unsigned int cpu);

#else

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return 0;
}

static inline void set_task_cpu(struct task_struct *p, unsigned int cpu)
{
}

#endif /* CONFIG_SMP */

#endif /* _LINUX_SCHED_THREAD_INFO_API_H */
