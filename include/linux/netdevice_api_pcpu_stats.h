/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_NETDEVICE_API_PCPU_STATS_H
#define _LINUX_NETDEVICE_API_PCPU_STATS_H

#include <linux/device_api.h>
#include <linux/percpu.h>
#include <linux/netdevice_api.h>

#include <linux/u64_stats_sync_api.h>
#include <linux/cpumask_api.h>

#define __netdev_alloc_pcpu_stats(type, gfp)				\
({									\
	typeof(type) __percpu *pcpu_stats = alloc_percpu_gfp(type, gfp);\
	if (pcpu_stats)	{						\
		int __cpu;						\
		for_each_possible_cpu(__cpu) {				\
			typeof(type) *stat;				\
			stat = per_cpu_ptr(pcpu_stats, __cpu);		\
			u64_stats_init(&stat->syncp);			\
		}							\
	}								\
	pcpu_stats;							\
})

#define netdev_alloc_pcpu_stats(type)					\
	__netdev_alloc_pcpu_stats(type, GFP_KERNEL)

#define devm_netdev_alloc_pcpu_stats(dev, type)				\
({									\
	typeof(type) __percpu *pcpu_stats = devm_alloc_percpu(dev, type);\
	if (pcpu_stats) {						\
		int __cpu;						\
		for_each_possible_cpu(__cpu) {				\
			typeof(type) *stat;				\
			stat = per_cpu_ptr(pcpu_stats, __cpu);		\
			u64_stats_init(&stat->syncp);			\
		}							\
	}								\
	pcpu_stats;							\
})

#endif	/* _LINUX_NETDEVICE_API_PCPU_STATS_H */
