/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/cgroup_types.h - basic definitions for cgroup
 *
 * This file provides basic type and interface.  Include this file directly
 * only if necessary to avoid cyclic dependencies.
 */
#ifndef _LINUX_CGROUP_TYPES_SOCK_H
#define _LINUX_CGROUP_TYPES_SOCK_H

#include <linux/types.h>

#ifdef CONFIG_SOCK_CGROUP_DATA

/*
 * sock_cgroup_data is embedded at sock->sk_cgrp_data and contains
 * per-socket cgroup information except for memcg association.
 *
 * On legacy hierarchies, net_prio and net_cls controllers directly
 * set attributes on each sock which can then be tested by the network
 * layer. On the default hierarchy, each sock is associated with the
 * cgroup it was created in and the networking layer can match the
 * cgroup directly.
 */
struct sock_cgroup_data {
	struct cgroup	*cgroup; /* v2 */
#ifdef CONFIG_CGROUP_NET_CLASSID
	u32		classid; /* v1 */
#endif
#ifdef CONFIG_CGROUP_NET_PRIO
	u16		prioidx; /* v1 */
#endif
};

#else	/* CONFIG_SOCK_CGROUP_DATA */

struct sock_cgroup_data {
};

#endif	/* CONFIG_SOCK_CGROUP_DATA */

#endif	/* _LINUX_CGROUP_TYPES_SOCK_H */
