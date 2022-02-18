/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_H
#define _LINUX_FS_H

#include <linux/fs_types.h>

#endif /* _LINUX_FS_H */

#ifndef CONFIG_FAST_HEADERS
# include <linux/fs_api.h>
# include <linux/sched.h>
# include <linux/rcuwait.h>
# include <linux/sched/jobctl.h>
# include <linux/sched/signal.h>
# include <linux/sched/rt.h>
# include <linux/sched/task.h>
# include <linux/sched/user.h>
# include <linux/bit_spinlock.h>
# include <linux/delayed_call.h>
# include <linux/hash.h>
# include <linux/iocontext.h>
# include <linux/ioprio.h>
# include <linux/list_bl.h>
# include <linux/list_lru.h>
# include <linux/local_lock.h>
# include <linux/memory_hotplug.h>
# include <linux/mmzone.h>
# include <linux/notifier.h>
# include <linux/quota.h>
# include <linux/radix-tree.h>
# include <linux/rculist_bl.h>
# include <linux/rcu_sync.h>
# include <linux/seccomp.h>
# include <linux/semaphore.h>
# include <linux/shrinker.h>
# include <linux/srcu.h>
# include <linux/sysctl.h>
# include <linux/uuid.h>
# include <linux/wait_bit.h>
# include <linux/xarray.h>
# include <linux/dcache.h>
# include <linux/stringhash.h>
#endif
