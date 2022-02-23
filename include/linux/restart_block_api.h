/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common syscall restarting data
 */
#ifndef __LINUX_RESTART_BLOCK_API_H
#define __LINUX_RESTART_BLOCK_API_H

#include <linux/restart_block_types.h>

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/time64.h>
#include <linux/errno.h>

#include <linux/sched/thread_info_api.h>

extern long do_no_restart_syscall(struct restart_block *parm);

#ifndef arch_set_restart_data
#define arch_set_restart_data(restart) do { } while (0)
#endif

static inline long set_restart_fn(struct restart_block *restart,
					long (*fn)(struct restart_block *))
{
	restart->fn = fn;
	arch_set_restart_data(restart);
	return -ERESTART_RESTARTBLOCK;
}

#endif /* __LINUX_RESTART_BLOCK_API_H */
