/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#ifndef _NET_IP_FIB_TYPES_H
#define _NET_IP_FIB_TYPES_H

#include <net/net_trackers.h>
#include <net/net_namespace_types.h>
#include <linux/skbuff_api.h>
#include <net/flow.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <net/fib_notifier.h>
#include <net/fib_rules.h>
#include <net/inetpeer.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/refcount.h>

struct fib_config {
	u8			fc_dst_len;
	u8			fc_tos;
	u8			fc_protocol;
	u8			fc_scope;
	u8			fc_type;
	u8			fc_gw_family;
	/* 2 bytes unused */
	u32			fc_table;
	__be32			fc_dst;
	union {
		__be32		fc_gw4;
		struct in6_addr	fc_gw6;
	};
	int			fc_oif;
	u32			fc_flags;
	u32			fc_priority;
	__be32			fc_prefsrc;
	u32			fc_nh_id;
	struct nlattr		*fc_mx;
	struct rtnexthop	*fc_mp;
	int			fc_mx_len;
	int			fc_mp_len;
	u32			fc_flow;
	u32			fc_nlflags;
	struct nl_info		fc_nlinfo;
	struct nlattr		*fc_encap;
	u16			fc_encap_type;
};

struct fib_info;
struct rtable;

struct fib_nh_exception {
	struct fib_nh_exception __rcu	*fnhe_next;
	int				fnhe_genid;
	__be32				fnhe_daddr;
	u32				fnhe_pmtu;
	bool				fnhe_mtu_locked;
	__be32				fnhe_gw;
	unsigned long			fnhe_expires;
	struct rtable __rcu		*fnhe_rth_input;
	struct rtable __rcu		*fnhe_rth_output;
	unsigned long			fnhe_stamp;
	struct rcu_head			rcu;
};

struct fnhe_hash_bucket {
	struct fib_nh_exception __rcu	*chain;
};

#define FNHE_HASH_SHIFT		11
#define FNHE_HASH_SIZE		(1 << FNHE_HASH_SHIFT)
#define FNHE_RECLAIM_DEPTH	5

struct fib_nh_common {
	struct net_device	*nhc_dev;
	netdevice_tracker	nhc_dev_tracker;
	int			nhc_oif;
	unsigned char		nhc_scope;
	u8			nhc_family;
	u8			nhc_gw_family;
	unsigned char		nhc_flags;
	struct lwtunnel_state	*nhc_lwtstate;

	union {
		__be32          ipv4;
		struct in6_addr ipv6;
	} nhc_gw;

	int			nhc_weight;
	atomic_t		nhc_upper_bound;

	/* v4 specific, but allows fib6_nh with v4 routes */
	struct rtable __rcu * __percpu *nhc_pcpu_rth_output;
	struct rtable __rcu     *nhc_rth_input;
	struct fnhe_hash_bucket	__rcu *nhc_exceptions;
};

struct fib_nh {
	struct fib_nh_common	nh_common;
	struct hlist_node	nh_hash;
	struct fib_info		*nh_parent;
#ifdef CONFIG_IP_ROUTE_CLASSID
	__u32			nh_tclassid;
#endif
	__be32			nh_saddr;
	int			nh_saddr_genid;
#define fib_nh_family		nh_common.nhc_family
#define fib_nh_dev		nh_common.nhc_dev
#define fib_nh_dev_tracker	nh_common.nhc_dev_tracker
#define fib_nh_oif		nh_common.nhc_oif
#define fib_nh_flags		nh_common.nhc_flags
#define fib_nh_lws		nh_common.nhc_lwtstate
#define fib_nh_scope		nh_common.nhc_scope
#define fib_nh_gw_family	nh_common.nhc_gw_family
#define fib_nh_gw4		nh_common.nhc_gw.ipv4
#define fib_nh_gw6		nh_common.nhc_gw.ipv6
#define fib_nh_weight		nh_common.nhc_weight
#define fib_nh_upper_bound	nh_common.nhc_upper_bound
};

/*
 * This structure contains data shared by many of routes.
 */

struct nexthop;

struct fib_info {
	struct hlist_node	fib_hash;
	struct hlist_node	fib_lhash;
	struct list_head	nh_list;
	struct net		*fib_net;
	refcount_t		fib_treeref;
	refcount_t		fib_clntref;
	unsigned int		fib_flags;
	unsigned char		fib_dead;
	unsigned char		fib_protocol;
	unsigned char		fib_scope;
	unsigned char		fib_type;
	__be32			fib_prefsrc;
	u32			fib_tb_id;
	u32			fib_priority;
	struct dst_metrics	*fib_metrics;
#define fib_mtu fib_metrics->metrics[RTAX_MTU-1]
#define fib_window fib_metrics->metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics->metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics->metrics[RTAX_ADVMSS-1]
	int			fib_nhs;
	bool			fib_nh_is_v6;
	bool			nh_updated;
	struct nexthop		*nh;
	struct rcu_head		rcu;
	struct fib_nh		fib_nh[];
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_table;
struct fib_result {
	__be32			prefix;
	unsigned char		prefixlen;
	unsigned char		nh_sel;
	unsigned char		type;
	unsigned char		scope;
	u32			tclassid;
	struct fib_nh_common	*nhc;
	struct fib_info		*fi;
	struct fib_table	*table;
	struct hlist_head	*fa_head;
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;
};

#define FIB_RES_NHC(res)		((res).nhc)
#define FIB_RES_DEV(res)	(FIB_RES_NHC(res)->nhc_dev)
#define FIB_RES_OIF(res)	(FIB_RES_NHC(res)->nhc_oif)

struct fib_dump_filter {
	u32			table_id;
	/* filter_set is an optimization that an entry is set */
	bool			filter_set;
	bool			dump_routes;
	bool			dump_exceptions;
	unsigned char		protocol;
	unsigned char		rt_type;
	unsigned int		flags;
	struct net_device	*dev;
};

#endif /* _NET_IP_FIB_TYPES_H */
