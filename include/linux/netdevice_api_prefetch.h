/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_NETDEVICE_API_PREFETCH_H
#define _LINUX_NETDEVICE_API_PREFETCH_H

#include <linux/netdevice_types.h>

#include <linux/prefetch.h>

static inline void net_prefetch(void *p)
{
	prefetch(p);
#if L1_CACHE_BYTES < 128
	prefetch((u8 *)p + L1_CACHE_BYTES);
#endif
}

static inline void net_prefetchw(void *p)
{
	prefetchw(p);
#if L1_CACHE_BYTES < 128
	prefetchw((u8 *)p + L1_CACHE_BYTES);
#endif
}

/**
 *	netdev_txq_bql_enqueue_prefetchw - prefetch bql data for write
 *	@dev_queue: pointer to transmit queue
 *
 * BQL enabled drivers might use this helper in their ndo_start_xmit(),
 * to give appropriate hint to the CPU.
 */
static inline void netdev_txq_bql_enqueue_prefetchw(struct netdev_queue *dev_queue)
{
#ifdef CONFIG_BQL
	prefetchw(&dev_queue->dql.num_queued);
#endif
}

/**
 *	netdev_txq_bql_complete_prefetchw - prefetch bql data for write
 *	@dev_queue: pointer to transmit queue
 *
 * BQL enabled drivers might use this helper in their TX completion path,
 * to give appropriate hint to the CPU.
 */
static inline void netdev_txq_bql_complete_prefetchw(struct netdev_queue *dev_queue)
{
#ifdef CONFIG_BQL
	prefetchw(&dev_queue->dql.limit);
#endif
}
#endif	/* _LINUX_NETDEVICE_API_PREFETCH_H */
