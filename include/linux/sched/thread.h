/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_THREAD_H
#define _LINUX_SCHED_THREAD_H

/*
 * Note, this is a low level utility header, included by <asm/processor.h>
 * after thread_struct has been defined.
 *
 * Don't add new dependencies to it!
 */

#include <linux/sched/per_task.h>

DECLARE_PER_TASK(struct thread_struct, thread);

#define task_thread(t) per_task(t, thread)

#endif /* _LINUX_SCHED_THREAD_H */
