/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_NETLINK_API_SKB_CLONE_H
#define __LINUX_NETLINK_API_SKB_CLONE_H

#include <linux/skbuff_api.h>
#include <linux/netlink.h>
#include <linux/mm_page_address.h>

static inline struct sk_buff *
netlink_skb_clone(struct sk_buff *skb, gfp_t gfp_mask)
{
	struct sk_buff *nskb;

	nskb = skb_clone(skb, gfp_mask);
	if (!nskb)
		return NULL;

	/* This is a large skb, set destructor callback to release head */
	if (is_vmalloc_addr(skb->head))
		nskb->destructor = skb->destructor;

	return nskb;
}

#endif	/* __LINUX_NETLINK_API_SKB_CLONE_H */
