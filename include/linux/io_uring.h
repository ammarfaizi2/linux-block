/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_H
#define _LINUX_IO_URING_H

#include <linux/sched.h>
#include <linux/xarray.h>

/*
 * Note that the first member here must be a struct file, as the
 * io_uring command layout depends on that.
 */
struct io_uring_cmd {
	struct file	*file;
	__u16		op;
	__u16		unused;
	__u32		len;
	__u64		pdu[5];	/* 40 bytes available inline for free use */
};

#if defined(CONFIG_IO_URING)
void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret);
struct sock *io_uring_get_socket(struct file *file);
void __io_uring_cancel(bool cancel_all);
void __io_uring_free(struct task_struct *tsk);

static inline void io_uring_files_cancel(void)
{
	if (current->io_uring)
		__io_uring_cancel(false);
}
static inline void io_uring_task_cancel(void)
{
	if (current->io_uring)
		__io_uring_cancel(true);
}
static inline void io_uring_free(struct task_struct *tsk)
{
	if (tsk->io_uring)
		__io_uring_free(tsk);
}
#else
static inline void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret)
{
}
static inline struct sock *io_uring_get_socket(struct file *file)
{
	return NULL;
}
static inline void io_uring_task_cancel(void)
{
}
static inline void io_uring_files_cancel(void)
{
}
static inline void io_uring_free(struct task_struct *tsk)
{
}
#endif

#endif
