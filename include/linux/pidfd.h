/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PIDFD_H
#define _LINUX_PIDFD_H

#include <linux/bug.h>
#include <linux/sched.h>
#include <linux/types.h>

struct pid;

struct pidfd_struct {
	struct pid *pid;
	const struct cred *creator_cred;
	u32 flags;
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

static inline bool pidfd_has_flag(const struct pidfd_struct *pidfd, u32 flags)
{
	return (pidfd->flags & flags) == flags;
}

int pidfd_flags_allowed(u32 flags, const struct task_struct *child);

struct pidfd_struct *pidfd_alloc(struct pid *pid);
void pidfd_put(struct pidfd_struct *pidfd);

#endif /* _LINUX_PIDFD_H */
