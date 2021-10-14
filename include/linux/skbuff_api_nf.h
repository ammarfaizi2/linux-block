/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_SKBUFF_API_NF_H
#define _LINUX_SKBUFF_API_NF_H

#include <linux/netfilter/nf_conntrack_common_api.h>
#include <linux/skbuff_api.h>

/* Note: This doesn't put any conntrack info in dst. */
static inline void __nf_copy(struct sk_buff *dst, const struct sk_buff *src,
			     bool copy)
{
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	dst->_nfct = src->_nfct;
	nf_conntrack_get(skb_nfct(src));
#endif
#if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_TRACE) || defined(CONFIG_NF_TABLES)
	if (copy)
		dst->nf_trace = src->nf_trace;
#endif
}

static inline void nf_copy(struct sk_buff *dst, const struct sk_buff *src)
{
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	nf_conntrack_put(skb_nfct(dst));
#endif
	dst->slow_gro = src->slow_gro;
	__nf_copy(dst, src, true);
}

static inline void nf_reset_ct(struct sk_buff *skb)
{
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	nf_conntrack_put(skb_nfct(skb));
	skb->_nfct = 0;
#endif
}

static inline void nf_reset_trace(struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_TRACE) || defined(CONFIG_NF_TABLES)
	skb->nf_trace = 0;
#endif
}
#endif	/* _LINUX_SKBUFF_API_NF_H */
