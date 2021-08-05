/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_UDP_API_H
#define _LINUX_UDP_API_H

#include <linux/udp.h>

#include <linux/skbuff_api.h>

static inline void udp_cmsg_recv(struct msghdr *msg, struct sock *sk,
				 struct sk_buff *skb)
{
	int gso_size;

	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
		gso_size = skb_shinfo(skb)->gso_size;
		put_cmsg(msg, SOL_UDP, UDP_GRO, sizeof(gso_size), &gso_size);
	}
}

static inline bool udp_unexpected_gso(struct sock *sk, struct sk_buff *skb)
{
	if (!skb_is_gso(skb))
		return false;

	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4 && !udp_sk(sk)->accept_udp_l4)
		return true;

	if (skb_shinfo(skb)->gso_type & SKB_GSO_FRAGLIST && !udp_sk(sk)->accept_udp_fraglist)
		return true;

	return false;
}

#endif	/* _LINUX_UDP_API_H */
