/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Operations on the network namespace
 */
#ifndef __NET_NET_NAMESPACE_TYPES_H
#define __NET_NET_NAMESPACE_TYPES_H

#include <linux/refcount.h>
#include <linux/sysctl.h>

#include <uapi/linux/in6.h>

#include <net/netns/core.h>
#include <net/netns/mib.h>
#include <net/netns/unix.h>
#include <net/netns/packet.h>
#include <net/netns/ipv4.h>
#include <net/netns/ipv6.h>
#include <net/netns/nexthop.h>
#include <net/netns/ieee802154_6lowpan.h>
#include <net/netns/sctp.h>
#include <net/netns/netfilter.h>
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#include <net/netns/conntrack.h>
#endif
#include <net/netns/nftables.h>
#include <net/netns/xfrm.h>
#include <net/netns/mpls.h>
#include <net/netns/can.h>
#include <net/netns/xdp.h>
#include <net/netns/smc.h>
#include <net/netns/bpf.h>
#include <net/netns/mctp.h>
#include <net/net_trackers.h>

#include <linux/ns_common.h>
#include <linux/idr.h>
#include <linux/skbuff_types.h>

struct user_namespace;
struct proc_dir_entry;
struct net_device;
struct sock;
struct ctl_table_header;
struct net_generic;
struct uevent_sock;
struct netns_ipvs;
struct bpf_prog;


#define NETDEV_HASHBITS    8
#define NETDEV_HASHENTRIES (1 << NETDEV_HASHBITS)

struct net {
	/* First cache line can be often dirtied.
	 * Do not place here read-mostly fields.
	 */
	refcount_t		passive;	/* To decide when the network
						 * namespace should be freed.
						 */
	spinlock_t		rules_mod_lock;

	atomic_t		dev_unreg_count;

	unsigned int		dev_base_seq;	/* protected by rtnl_mutex */
	int			ifindex;

	spinlock_t		nsid_lock;
	atomic_t		fnhe_genid;

	struct list_head	list;		/* list of network namespaces */
	struct list_head	exit_list;	/* To linked to call pernet exit
						 * methods on dead net (
						 * pernet_ops_rwsem read locked),
						 * or to unregister pernet ops
						 * (pernet_ops_rwsem write locked).
						 */
	struct llist_node	cleanup_list;	/* namespaces on death row */

#ifdef CONFIG_KEYS
	struct key_tag		*key_domain;	/* Key domain of operation tag */
#endif
	struct user_namespace   *user_ns;	/* Owning user namespace */
	struct ucounts		*ucounts;
	struct idr		netns_ids;

	struct ns_common	ns;
	struct ref_tracker_dir  refcnt_tracker;

	struct list_head 	dev_base_head;
	struct proc_dir_entry 	*proc_net;
	struct proc_dir_entry 	*proc_net_stat;

#ifdef CONFIG_SYSCTL
	struct ctl_table_set	sysctls;
#endif

	struct sock 		*rtnl;			/* rtnetlink socket */
	struct sock		*genl_sock;

	struct uevent_sock	*uevent_sock;		/* uevent socket */

	struct hlist_head 	*dev_name_head;
	struct hlist_head	*dev_index_head;
	struct raw_notifier_head	netdev_chain;

	/* Note that @hash_mix can be read millions times per second,
	 * it is critical that it is on a read_mostly cache line.
	 */
	u32			hash_mix;

	struct net_device       *loopback_dev;          /* The loopback */

	/* core fib_rules */
	struct list_head	rules_ops;

	struct netns_core	core;
	struct netns_mib	mib;
	struct netns_packet	packet;
	struct netns_unix	unx;
	struct netns_nexthop	nexthop;
	struct netns_ipv4	ipv4;
#if IS_ENABLED(CONFIG_IPV6)
	struct netns_ipv6	ipv6;
#endif
#if IS_ENABLED(CONFIG_IEEE802154_6LOWPAN)
	struct netns_ieee802154_lowpan	ieee802154_lowpan;
#endif
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
	struct netns_sctp	sctp;
#endif
#ifdef CONFIG_NETFILTER
	struct netns_nf		nf;
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct netns_ct		ct;
#endif
#if defined(CONFIG_NF_TABLES) || defined(CONFIG_NF_TABLES_MODULE)
	struct netns_nftables	nft;
#endif
#endif
#ifdef CONFIG_WEXT_CORE
	struct sk_buff_head	wext_nlevents;
#endif
	struct net_generic __rcu	*gen;

	/* Used to store attached BPF programs */
	struct netns_bpf	bpf;

	/* Note : following structs are cache line aligned */
#ifdef CONFIG_XFRM
	struct netns_xfrm	xfrm;
#endif

	u64			net_cookie; /* written once */

#if IS_ENABLED(CONFIG_IP_VS)
	struct netns_ipvs	*ipvs;
#endif
#if IS_ENABLED(CONFIG_MPLS)
	struct netns_mpls	mpls;
#endif
#if IS_ENABLED(CONFIG_CAN)
	struct netns_can	can;
#endif
#ifdef CONFIG_XDP_SOCKETS
	struct netns_xdp	xdp;
#endif
#if IS_ENABLED(CONFIG_MCTP)
	struct netns_mctp	mctp;
#endif
#if IS_ENABLED(CONFIG_CRYPTO_USER)
	struct sock		*crypto_nlsk;
#endif
	struct sock		*diag_nlsk;
#if IS_ENABLED(CONFIG_SMC)
	struct netns_smc	smc;
#endif
} __randomize_layout;

/* Init's network namespace */
extern struct net init_net;

typedef struct {
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
} possible_net_t;

#ifdef CONFIG_NET_NS
#define __net_init
#define __net_exit
#define __net_initdata
#define __net_initconst
#else
#define __net_init	__init
#define __net_exit	__ref
#define __net_initdata	__initdata
#define __net_initconst	__initconst
#endif

struct pernet_operations {
	struct list_head list;
	/*
	 * Below methods are called without any exclusive locks.
	 * More than one net may be constructed and destructed
	 * in parallel on several cpus. Every pernet_operations
	 * have to keep in mind all other pernet_operations and
	 * to introduce a locking, if they share common resources.
	 *
	 * The only time they are called with exclusive lock is
	 * from register_pernet_subsys(), unregister_pernet_subsys()
	 * register_pernet_device() and unregister_pernet_device().
	 *
	 * Exit methods using blocking RCU primitives, such as
	 * synchronize_rcu(), should be implemented via exit_batch.
	 * Then, destruction of a group of net requires single
	 * synchronize_rcu() related to these pernet_operations,
	 * instead of separate synchronize_rcu() for every net.
	 * Please, avoid synchronize_rcu() at all, where it's possible.
	 *
	 * Note that a combination of pre_exit() and exit() can
	 * be used, since a synchronize_rcu() is guaranteed between
	 * the calls.
	 */
	int (*init)(struct net *net);
	void (*pre_exit)(struct net *net);
	void (*exit)(struct net *net);
	void (*exit_batch)(struct list_head *net_exit_list);
	unsigned int *id;
	size_t size;
};

#endif /* __NET_NET_NAMESPACE_TYPES_H */
