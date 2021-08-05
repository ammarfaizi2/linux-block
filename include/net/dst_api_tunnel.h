/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net/dst.h	Protocol independent destination cache definitions.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#ifndef _NET_DST_API_TUNNEL_H
#define _NET_DST_API_TUNNEL_H

#include <net/dst_api.h>

#include <linux/netdevice_types.h>

/**
 *	__skb_tunnel_rx - prepare skb for rx reinsert
 *	@skb: buffer
 *	@dev: tunnel device
 *	@net: netns for packet i/o
 *
 *	After decapsulation, packet is going to re-enter (netif_rx()) our stack,
 *	so make some cleanups. (no accounting done)
 */
static inline void __skb_tunnel_rx(struct sk_buff *skb, struct net_device *dev,
				   struct net *net)
{
	skb->dev = dev;

	/*
	 * Clear hash so that we can recalulate the hash for the
	 * encapsulated packet, unless we have already determine the hash
	 * over the L4 4-tuple.
	 */
	skb_clear_hash_if_not_l4(skb);
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, !net_eq(net, dev_net(dev)));
}

/**
 *	skb_tunnel_rx - prepare skb for rx reinsert
 *	@skb: buffer
 *	@dev: tunnel device
 *	@net: netns for packet i/o
 *
 *	After decapsulation, packet is going to re-enter (netif_rx()) our stack,
 *	so make some cleanups, and perform accounting.
 *	Note: this accounting is not SMP safe.
 */
static inline void skb_tunnel_rx(struct sk_buff *skb, struct net_device *dev,
				 struct net *net)
{
	/* TODO : stats should be SMP safe */
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;
	__skb_tunnel_rx(skb, dev, net);
}

#endif /* _NET_DST_API_TUNNEL_H */
