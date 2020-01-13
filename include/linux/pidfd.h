/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PIDFD_H
#define _LINUX_PIDFD_H

#include <linux/bug.h>
#include <linux/sched.h>
#include <linux/types.h>

struct pid;

struct pidfd_struct {
	struct pid *pid;
};

static inline struct pid *pidfd_pid(const struct pidfd_struct *pidfd)
{
	WARN_ON_ONCE(!pidfd->pid);
	return pidfd->pid;
}
static inline struct pid *pidfd_get_pid(struct pidfd_struct *pidfd)
{
	return get_pid(pidfd_pid(pidfd));
}
extern struct pidfd_struct *pidfd_file(const struct file *file);

struct pidfd_struct *pidfd_alloc(struct pid *pid);
void pidfd_put(struct pidfd_struct *pidfd);

#endif /* _LINUX_PIDFD_H */
