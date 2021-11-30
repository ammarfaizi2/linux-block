/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_POLL_TIME_H
#define _LINUX_POLL_TIME_H

#include <linux/poll.h>

#include <linux/time64_types.h>
#include <linux/ktime.h>


extern u64 select_estimate_accuracy(struct timespec64 *tv);

#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)

extern int core_sys_select(int n, fd_set __user *inp, fd_set __user *outp,
			   fd_set __user *exp, struct timespec64 *end_time);

extern int poll_select_set_timeout(struct timespec64 *to, time64_t sec,
				   long nsec);
#endif /* _LINUX_POLL_TIME_H */
