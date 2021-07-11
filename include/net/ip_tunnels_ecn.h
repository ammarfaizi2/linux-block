/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_IP_TUNNELS_ECN_H
#define __NET_IP_TUNNELS_ECN_H 1

#include <net/ip_tunnels.h>
#include <net/inet_ecn.h>

/* Propogate ECN bits out */
static inline u8 ip_tunnel_ecn_encap(u8 tos, const struct iphdr *iph,
				     const struct sk_buff *skb)
{
	u8 inner = ip_tunnel_get_dsfield(iph, skb);

	return INET_ECN_encapsulate(tos, inner);
}

#endif /* __NET_IP_TUNNELS_ECN_H */
