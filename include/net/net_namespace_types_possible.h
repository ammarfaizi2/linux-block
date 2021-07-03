/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_NET_NAMESPACE_TYPES_POSSIBLE_H
#define __NET_NET_NAMESPACE_TYPES_POSSIBLE_H

struct net;

typedef struct {
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
} possible_net_t;

/* Init's network namespace */
extern struct net init_net;

static inline struct net *read_pnet(const possible_net_t *pnet)
{
#ifdef CONFIG_NET_NS
	return pnet->net;
#else
	return &init_net;
#endif
}

#endif /* __NET_NET_NAMESPACE_TYPES_POSSIBLE_H */
