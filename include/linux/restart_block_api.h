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

#include <linux/thread_info.h>

extern long do_no_restart_syscall(struct restart_block *parm);

#endif /* __LINUX_RESTART_BLOCK_API_H */
