/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <linux/mm_types.h>

#endif /* _LINUX_MM_H */

#ifndef CONFIG_FAST_HEADERS
# include <linux/mm_api.h>
# include <linux/fs.h>
# include <linux/sched.h>
# include <linux/mmzone_api.h>
# include <linux/rcuwait.h>
# include <linux/huge_mm.h>
# include <linux/pgtable.h>
# include <linux/pgtable_api.h>
# include <linux/memory_hotplug.h>
# include <linux/memremap.h>
# include <linux/vmstat.h>
# include <linux/mmap_lock.h>
#endif
