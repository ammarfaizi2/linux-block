/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *	Definitions for the 'struct sk_buff' memory handlers.
 *
 *	Authors:
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Florian La Roche, <rzsfl@rz.uni-sb.de>
 */

#ifndef _LINUX_SKBUFF_API_PAGE_POOL
#define _LINUX_SKBUFF_API_PAGE_POOL

#include <linux/skbuff_api.h>
#include <linux/mmzone.h>
#include <linux/mm_page_address.h>

#include <net/page_pool.h>

#ifdef CONFIG_PAGE_POOL
static inline void skb_mark_for_recycle(struct sk_buff *skb)
{
	skb->pp_recycle = 1;
}
#endif

static inline bool skb_pp_recycle(struct sk_buff *skb, void *data)
{
	if (!IS_ENABLED(CONFIG_PAGE_POOL) || !skb->pp_recycle)
		return false;
	return page_pool_return_skb_page(virt_to_page(data));
}

#endif	/* _LINUX_SKBUFF_API_PAGE_POOL */
