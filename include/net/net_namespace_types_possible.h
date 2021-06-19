/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_NET_NAMESPACE_TYPES_POSSIBLE_H
#define __NET_NET_NAMESPACE_TYPES_POSSIBLE_H

struct net;

typedef struct {
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
} possible_net_t;

#endif /* __NET_NET_NAMESPACE_TYPES_POSSIBLE_H */
