/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_API_F_COUNT_H
#define _LINUX_FS_API_F_COUNT_H

#include <linux/fs_api.h>

#include <linux/atomic_api.h>

static inline struct file *get_file(struct file *f)
{
	atomic_long_inc(&f->f_count);
	return f;
}
#define get_file_rcu_many(x, cnt)	\
	atomic_long_add_unless(&(x)->f_count, (cnt), 0)

#define get_file_rcu(x) get_file_rcu_many((x), 1)

#define file_count(x)	atomic_long_read(&(x)->f_count)

#endif /* _LINUX_FS_API_F_COUNT_H */
