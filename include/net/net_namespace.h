/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Operations on the network namespace
 */
#ifndef __NET_NET_NAMESPACE_H
#define __NET_NET_NAMESPACE_H

#include <net/net_namespace_types.h>

#ifdef CONFIG_NET
void net_ns_init(void);
#else
static inline void net_ns_init(void) {}
#endif

#endif /* __NET_NET_NAMESPACE_H */
