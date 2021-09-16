/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_GENERIC_NETLINK_H
#define __LINUX_GENERIC_NETLINK_H

#include <uapi/linux/genetlink.h>


/* All generic netlink requests are serialized by a global lock.  */
extern void genl_lock(void);
extern void genl_unlock(void);

struct wait_queue_head;

/* for synchronisation between af_netlink and genetlink */
extern atomic_t genl_sk_destructing_cnt;
extern struct wait_queue_head genl_sk_destructing_waitq;

#define MODULE_ALIAS_GENL_FAMILY(family)\
 MODULE_ALIAS_NET_PF_PROTO_NAME(PF_NETLINK, NETLINK_GENERIC, "-family-" family)

#endif	/* __LINUX_GENERIC_NETLINK_H */
