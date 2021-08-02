/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_VFS_PRESSURE_H
#define __LINUX_VFS_PRESSURE_H

#include <linux/math.h>

extern int sysctl_vfs_cache_pressure;

static inline unsigned long vfs_pressure_ratio(unsigned long val)
{
	return mult_frac(val, sysctl_vfs_cache_pressure, 100);
}

#endif	/* __LINUX_VFS_PRESSURE_H */
