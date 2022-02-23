/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TASK_STACK_H
#define _LINUX_SCHED_TASK_STACK_H

/*
 * task->stack (kernel stack) handling interfaces:
 */

#include <linux/sched/thread_info_api.h>
#include <asm/page.h>
#include <linux/sched.h>
#include <linux/magic.h>
#include <linux/refcount.h>
#include <linux/sched/thread.h>

#ifdef CONFIG_VMAP_STACK

DECLARE_PER_TASK(struct vm_struct *, stack_vm_area);

static inline struct vm_struct *task_stack_vm_area(const struct task_struct *t)
{
	return per_task(t, stack_vm_area);
}
#else
static inline struct vm_struct *task_stack_vm_area(const struct task_struct *t)
{
	return NULL;
}
#endif


#ifdef CONFIG_THREAD_INFO_IN_TASK

DECLARE_PER_TASK(refcount_t, stack_refcount);

/*
 * When accessing the stack of a non-current task that might exit, use
 * try_get_task_stack() instead.  task_stack_page will return a pointer
 * that could get freed out from under you.
 */
static inline void *task_stack_page(const struct task_struct *task)
{
	return per_task(task, stack);
}

#define setup_thread_stack(new,old)	do { } while(0)

static inline unsigned long *end_of_stack(const struct task_struct *task)
{
#ifdef CONFIG_STACK_GROWSUP
	return (unsigned long *)((unsigned long)per_task(task, stack) + THREAD_SIZE) - 1;
#else
	return per_task(task, stack);
#endif
}

#elif !defined(__HAVE_THREAD_FUNCTIONS)

#define task_stack_page(task)	((void *)per_task(task, stack))

static inline void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
	*task_thread_info(p) = *task_thread_info(org);
	task_thread_info(p)->task = p;
}

/*
 * Return the address of the last usable long on the stack.
 *
 * When the stack grows down, this is just above the thread
 * info struct. Going any lower will corrupt the threadinfo.
 *
 * When the stack grows up, this is the highest address.
 * Beyond that position, we corrupt data on the next page.
 */
static inline unsigned long *end_of_stack(struct task_struct *p)
{
#ifdef CONFIG_STACK_GROWSUP
	return (unsigned long *)((unsigned long)task_thread_info(p) + THREAD_SIZE) - 1;
#else
	return (unsigned long *)(task_thread_info(p) + 1);
#endif
}

#endif

#ifdef CONFIG_THREAD_INFO_IN_TASK
static inline void *try_get_task_stack(struct task_struct *tsk)
{
	return refcount_inc_not_zero(&per_task(tsk, stack_refcount)) ?
		task_stack_page(tsk) : NULL;
}

extern void put_task_stack(struct task_struct *tsk);
#else
static inline void *try_get_task_stack(struct task_struct *tsk)
{
	return task_stack_page(tsk);
}

static inline void put_task_stack(struct task_struct *tsk) {}
#endif

#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)

static inline int object_is_on_stack(const void *obj)
{
	void *stack = task_stack_page(current);

	return (obj >= stack) && (obj < (stack + THREAD_SIZE));
}

extern void thread_stack_cache_init(void);

#ifdef CONFIG_DEBUG_STACK_USAGE
static inline unsigned long stack_not_used(struct task_struct *p)
{
	unsigned long *n = end_of_stack(p);

	do { 	/* Skip over canary */
# ifdef CONFIG_STACK_GROWSUP
		n--;
# else
		n++;
# endif
	} while (!*n);

# ifdef CONFIG_STACK_GROWSUP
	return (unsigned long)end_of_stack(p) - (unsigned long)n;
# else
	return (unsigned long)n - (unsigned long)end_of_stack(p);
# endif
}
#endif
extern void set_task_stack_end_magic(struct task_struct *tsk);

#ifndef __HAVE_ARCH_KSTACK_END
static inline int kstack_end(void *addr)
{
	/* Reliable end of stack detection:
	 * Some APM bios versions misalign the stack
	 */
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}
#endif

#endif /* _LINUX_SCHED_TASK_STACK_H */
