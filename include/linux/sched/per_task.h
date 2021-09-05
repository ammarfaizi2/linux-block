/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_PER_TASK_H
#define _LINUX_SCHED_PER_TASK_H

/*
 * Per-task variables, isolated from the 'struct task_struct' definition
 * in sched.h.
 *
 * These can be allocated & used via DEFINE_PER_TASK, without any modification
 * to <linux/sched.h>.
 *
 * The following pattern:
 *
 *	DEFINE_PER_TASK(long, my_task_var);
 *
 *	...
 *
 *	long x = per_task(current, my_task_var);
 *
 * Is equivalent to adding 'my_task_var' to task_struct and using:
 *
 *	long x = current->my_task_var;
 *
 * There's no runtime penalty to using per-task variables.
 *
 * WARNING:
 *
 *   Note that while the per-task interface is very flexible, the space
 *   in task_struct is limited and you need to get acks from upstream
 *   task_struct stakeholders.
 *
 * This greatly increases type isolation and reduces header file dependencies.
 *
 * The implementation uses a pretty straightforward section trick to get unique
 * offsets of each variable, similar to percpu variables.
 *
 * A build-time check ensures that we haven't run out of available space.
 */

#include <linux/sched/per_task_types.h>
#include <linux/compiler.h>

#ifndef __PER_TASK_GEN
/*
 * These offsets get generated via the scripts/gen-pertask.sh script,
 * and the pertask rules in the top level Kbuild file:
 */
# include <generated/asm-offsets.h>
#endif

#define DECLARE_PER_TASK(type, name)		extern __typeof__(type) per_task__##name
#define DEFINE_PER_TASK(type, name)		DECLARE_PER_TASK(type, name)

#ifndef __PER_TASK_GEN
# define per_task_offset(name)			((unsigned long)PER_TASK_OFFSET__##name)
#else
# define per_task_offset(name)			0UL
#endif

#define per_task(task, name)			(*((__typeof__(per_task__##name) *)((task)->per_task_area + per_task_offset(name))))

#define per_task_container_of(var, name)	container_of((void *)(var) - per_task_offset(name), struct task_struct, per_task_area[0])

#endif /* _LINUX_SCHED_PER_TASK_H */
