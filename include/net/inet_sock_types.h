/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 *		Arnaldo Carvalho de Melo <acme@mandriva.com>
 */
#ifndef _INET_SOCK_TYPES_H
#define _INET_SOCK_TYPES_H

#include <net/request_sock.h>
#include <net/flow.h>

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @nexthop - Saved nexthop address in LSRR and SSRR
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	__be32		faddr;
	__be32		nexthop;
	unsigned char	optlen;
	unsigned char	srr;
	unsigned char	rr;
	unsigned char	ts;
	unsigned char	is_strictroute:1,
			srr_is_hit:1,
			is_changed:1,
			rr_needaddr:1,
			ts_needtime:1,
			ts_needaddr:1;
	unsigned char	router_alert;
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[];
};

struct ip_options_rcu {
	struct rcu_head rcu;
	struct ip_options opt;
};

struct ip_options_data {
	struct ip_options_rcu	opt;
	char			data[40];
};

struct inet_request_sock {
	struct request_sock	req;
#define ir_loc_addr		req.__req_common.skc_rcv_saddr
#define ir_rmt_addr		req.__req_common.skc_daddr
#define ir_num			req.__req_common.skc_num
#define ir_rmt_port		req.__req_common.skc_dport
#define ir_v6_rmt_addr		req.__req_common.skc_v6_daddr
#define ir_v6_loc_addr		req.__req_common.skc_v6_rcv_saddr
#define ir_iif			req.__req_common.skc_bound_dev_if
#define ir_cookie		req.__req_common.skc_cookie
#define ireq_net		req.__req_common.skc_net
#define ireq_state		req.__req_common.skc_state
#define ireq_family		req.__req_common.skc_family

	u16			snd_wscale : 4,
				rcv_wscale : 4,
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1,
				no_srccheck: 1,
				smc_ok	   : 1;
	u32                     ir_mark;
	union {
		struct ip_options_rcu __rcu	*ireq_opt;
#if IS_ENABLED(CONFIG_IPV6)
		struct {
			struct ipv6_txoptions	*ipv6_opt;
			struct sk_buff		*pktopts;
		};
#endif
	};
};

struct inet_cork {
	unsigned int		flags;
	__be32			addr;
	struct ip_options	*opt;
	unsigned int		fragsize;
	int			length; /* Total length of all frames */
	struct dst_entry	*dst;
	u8			tx_flags;
	__u8			ttl;
	__s16			tos;
	char			priority;
	__u16			gso_size;
	u64			transmit_time;
	u32			mark;
};

struct inet_cork_full {
	struct inet_cork	base;
	struct flowi		fl;
};

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @inet_daddr - Foreign IPv4 addr
 * @inet_rcv_saddr - Bound local IPv4 addr
 * @inet_dport - Destination port
 * @inet_num - Local port
 * @inet_saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @inet_sport - Source port
 * @inet_id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @uc_index - Unicast outgoing device index
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
#define inet_daddr		sk.__sk_common.skc_daddr
#define inet_rcv_saddr		sk.__sk_common.skc_rcv_saddr
#define inet_dport		sk.__sk_common.skc_dport
#define inet_num		sk.__sk_common.skc_num

	__be32			inet_saddr;
	__s16			uc_ttl;
	__u16			cmsg_flags;
	struct ip_options_rcu __rcu	*inet_opt;
	__be16			inet_sport;
	__u16			inet_id;

	__u8			tos;
	__u8			min_ttl;
	__u8			mc_ttl;
	__u8			pmtudisc;
	__u8			recverr:1,
				is_icsk:1,
				freebind:1,
				hdrincl:1,
				mc_loop:1,
				transparent:1,
				mc_all:1,
				nodefrag:1;
	__u8			bind_address_no_port:1,
				recverr_rfc4884:1,
				defer_connect:1; /* Indicates that fastopen_connect is set
						  * and cookie exists so we defer connect
						  * until first data frame is written
						  */
	__u8			rcv_tos;
	__u8			convert_csum;
	int			uc_index;
	int			mc_index;
	__be32			mc_addr;
	struct ip_mc_socklist __rcu	*mc_list;
	struct inet_cork_full	cork;
};

#endif	/* _INET_SOCK_TYPES_H */
