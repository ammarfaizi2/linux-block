/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_NETDEVICE_API_DEV_STATS_H
#define _LINUX_NETDEVICE_API_DEV_STATS_H

#include <linux/netdevice_api.h>

#include <linux/u64_stats_sync_api.h>

static inline void dev_sw_netstats_rx_add(struct net_device *dev, unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_bytes += len;
	tstats->rx_packets++;
	u64_stats_update_end(&tstats->syncp);
}

static inline void dev_sw_netstats_tx_add(struct net_device *dev,
					  unsigned int packets,
					  unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->tx_bytes += len;
	tstats->tx_packets += packets;
	u64_stats_update_end(&tstats->syncp);
}

static inline void dev_lstats_add(struct net_device *dev, unsigned int len)
{
	struct pcpu_lstats *lstats = this_cpu_ptr(dev->lstats);

	u64_stats_update_begin(&lstats->syncp);
	u64_stats_add(&lstats->bytes, len);
	u64_stats_inc(&lstats->packets);
	u64_stats_update_end(&lstats->syncp);
}

#endif	/* _LINUX_NETDEVICE_API_DEV_STATS_H */
