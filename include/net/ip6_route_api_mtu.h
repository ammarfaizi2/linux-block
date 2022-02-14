/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_IP6_ROUTE_API_MTU_H
#define _NET_IP6_ROUTE_API_MTU_H

#include <net/dst_api.h>
#include <net/ip6_route.h>
#include <linux/netdevice_api.h>

static inline unsigned int ip6_skb_dst_mtu(const struct sk_buff *skb)
{
	const struct ipv6_pinfo *np = skb->sk && !dev_recursion_level() ?
				inet6_sk(skb->sk) : NULL;
	const struct dst_entry *dst = skb_dst(skb);
	unsigned int mtu;

	if (np && np->pmtudisc >= IPV6_PMTUDISC_PROBE) {
		mtu = READ_ONCE(dst->dev->mtu);
		mtu -= lwtunnel_headroom(dst->lwtstate, mtu);
	} else {
		mtu = dst_mtu(dst);
	}
	return mtu;
}

#endif /* _NET_IP6_ROUTE_API_MTU_H */
