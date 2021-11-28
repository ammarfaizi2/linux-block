/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP module.
 *
 * Version:	@(#)ip.h	1.0.2	05/07/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *
 * Changes:
 *		Mike McLagan    :       Routing by source
 */
#ifndef _IP_H
#define _IP_H

#include <net/checksum.h>
#include <linux/cpumask_api.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/sockptr.h>
#include <linux/static_key.h>

#include <net/inet_sock.h>
#include <net/route_types.h>
#include <net/snmp.h>
#include <net/flow.h>
#include <net/flow_dissector.h>
#include <net/netns/hash.h>
#include <net/lwtunnel.h>

#define IPV4_MAX_PMTU		65535U		/* RFC 2675, Section 5.1 */
#define IPV4_MIN_MTU		68			/* RFC 791 */

extern unsigned int sysctl_fib_sync_mem;
extern unsigned int sysctl_fib_sync_mem_min;
extern unsigned int sysctl_fib_sync_mem_max;

struct sock;

struct inet_skb_parm {
	int			iif;
	struct ip_options	opt;		/* Compiled IP options		*/
	u16			flags;

#define IPSKB_FORWARDED		BIT(0)
#define IPSKB_XFRM_TUNNEL_SIZE	BIT(1)
#define IPSKB_XFRM_TRANSFORMED	BIT(2)
#define IPSKB_FRAG_COMPLETE	BIT(3)
#define IPSKB_REROUTED		BIT(4)
#define IPSKB_DOREDIRECT	BIT(5)
#define IPSKB_FRAG_PMTU		BIT(6)
#define IPSKB_L3SLAVE		BIT(7)

	u16			frag_max_size;
};

static inline bool ipv4_l3mdev_skb(u16 flags)
{
	return !!(flags & IPSKB_L3SLAVE);
}

static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}

struct ipcm_cookie {
	struct sockcm_cookie	sockc;
	__be32			addr;
	int			oif;
	struct ip_options_rcu	*opt;
	__u8			ttl;
	__s16			tos;
	char			priority;
	__u16			gso_size;
};

static inline void ipcm_init(struct ipcm_cookie *ipcm)
{
	*ipcm = (struct ipcm_cookie) { .tos = -1 };
}

static inline void ipcm_init_sk(struct ipcm_cookie *ipcm,
				const struct inet_sock *inet)
{
	ipcm_init(ipcm);

	ipcm->sockc.mark = inet->sk.sk_mark;
	ipcm->sockc.tsflags = inet->sk.sk_tsflags;
	ipcm->oif = inet->sk.sk_bound_dev_if;
	ipcm->addr = inet->inet_saddr;
}

#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))
#define PKTINFO_SKB_CB(skb) ((struct in_pktinfo *)((skb)->cb))

/* return enslaved device index if relevant */
static inline int inet_sdif(const struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_NET_L3_MASTER_DEV)
	if (skb && ipv4_l3mdev_skb(IPCB(skb)->flags))
		return IPCB(skb)->iif;
#endif
	return 0;
}

/* Special input handler for packets caught by router alert option.
   They are selected only by protocol field, and then processed likely
   local ones; but only if someone wants them! Otherwise, router
   not running rsvpd will kill RSVP.

   It is user level problem, what it will make with them.
   I have no idea, how it will masquearde or NAT them (it is joke, joke :-)),
   but receiver should be enough clever f.e. to forward mtrace requests,
   sent to multicast group to reach destination designated router.
 */

struct ip_ra_chain {
	struct ip_ra_chain __rcu *next;
	struct sock		*sk;
	union {
		void			(*destructor)(struct sock *);
		struct sock		*saved_sk;
	};
	struct rcu_head		rcu;
};

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define IP_FRAG_TIME	(30 * HZ)		/* fragment lifetime	*/

struct msghdr;
struct net_device;
struct packet_type;
struct rtable;
struct sockaddr;

int igmp_mc_init(void);

/*
 *	Functions provided by ip.c
 */

int ip_build_and_send_pkt(struct sk_buff *skb, const struct sock *sk,
			  __be32 saddr, __be32 daddr,
			  struct ip_options_rcu *opt, u8 tos);
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev);
void ip_list_rcv(struct list_head *head, struct packet_type *pt,
		 struct net_device *orig_dev);
int ip_local_deliver(struct sk_buff *skb);
void ip_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int proto);
int ip_mr_input(struct sk_buff *skb);
int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb);
int ip_mc_output(struct net *net, struct sock *sk, struct sk_buff *skb);
int ip_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		   int (*output)(struct net *, struct sock *, struct sk_buff *));

struct ip_fraglist_iter {
	struct sk_buff	*frag;
	struct iphdr	*iph;
	int		offset;
	unsigned int	hlen;
};

void ip_fraglist_init(struct sk_buff *skb, struct iphdr *iph,
		      unsigned int hlen, struct ip_fraglist_iter *iter);
void ip_fraglist_prepare(struct sk_buff *skb, struct ip_fraglist_iter *iter);

static inline struct sk_buff *ip_fraglist_next(struct ip_fraglist_iter *iter)
{
	struct sk_buff *skb = iter->frag;

	iter->frag = skb->next;
	skb_mark_not_on_list(skb);

	return skb;
}

struct ip_frag_state {
	bool		DF;
	unsigned int	hlen;
	unsigned int	ll_rs;
	unsigned int	mtu;
	unsigned int	left;
	int		offset;
	int		ptr;
	__be16		not_last_frag;
};

void ip_frag_init(struct sk_buff *skb, unsigned int hlen, unsigned int ll_rs,
		  unsigned int mtu, bool DF, struct ip_frag_state *state);
struct sk_buff *ip_frag_next(struct sk_buff *skb,
			     struct ip_frag_state *state);

void ip_send_check(struct iphdr *ip);
int __ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);
int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);

int __ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl,
		    __u8 tos);
void ip_init(void);
int ip_append_data(struct sock *sk, struct flowi4 *fl4,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int len, int protolen,
		   struct ipcm_cookie *ipc,
		   struct rtable **rt,
		   unsigned int flags);
int ip_generic_getfrag(void *from, char *to, int offset, int len, int odd,
		       struct sk_buff *skb);
ssize_t ip_append_page(struct sock *sk, struct flowi4 *fl4, struct page *page,
		       int offset, size_t size, int flags);
struct sk_buff *__ip_make_skb(struct sock *sk, struct flowi4 *fl4,
			      struct sk_buff_head *queue,
			      struct inet_cork *cork);
int ip_send_skb(struct net *net, struct sk_buff *skb);
int ip_push_pending_frames(struct sock *sk, struct flowi4 *fl4);
void ip_flush_pending_frames(struct sock *sk);
struct sk_buff *ip_make_skb(struct sock *sk, struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags);

int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl);

static inline struct sk_buff *ip_finish_skb(struct sock *sk, struct flowi4 *fl4)
{
	return __ip_make_skb(sk, fl4, &sk->sk_write_queue, &inet_sk(sk)->cork.base);
}

__u8 get_rttos(struct ipcm_cookie* ipc, struct inet_sock *inet);

/* datagram.c */
int __ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

void ip4_datagram_release_cb(struct sock *sk);

struct ip_reply_arg {
	struct kvec iov[1];
	int	    flags;
	__wsum 	    csum;
	int	    csumoffset; /* u16 offset of csum in iov[0].iov_base */
				/* -1 if not needed */
	int	    bound_dev_if;
	u8  	    tos;
	kuid_t	    uid;
};

#define IP_REPLY_ARG_NOSRCCHECK 1

static inline __u8 ip_reply_arg_flowi_flags(const struct ip_reply_arg *arg)
{
	return (arg->flags & IP_REPLY_ARG_NOSRCCHECK) ? FLOWI_FLAG_ANYSRC : 0;
}

void ip_send_unicast_reply(struct sock *sk, struct sk_buff *skb,
			   const struct ip_options *sopt,
			   __be32 daddr, __be32 saddr,
			   const struct ip_reply_arg *arg,
			   unsigned int len, u64 transmit_time);

#define IP_INC_STATS(net, field)	SNMP_INC_STATS64((net)->mib.ip_statistics, field)
#define __IP_INC_STATS(net, field)	__SNMP_INC_STATS64((net)->mib.ip_statistics, field)
#define IP_ADD_STATS(net, field, val)	SNMP_ADD_STATS64((net)->mib.ip_statistics, field, val)
#define __IP_ADD_STATS(net, field, val) __SNMP_ADD_STATS64((net)->mib.ip_statistics, field, val)
#define IP_UPD_PO_STATS(net, field, val) SNMP_UPD_PO_STATS64((net)->mib.ip_statistics, field, val)
#define __IP_UPD_PO_STATS(net, field, val) __SNMP_UPD_PO_STATS64((net)->mib.ip_statistics, field, val)
#define NET_INC_STATS(net, field)	SNMP_INC_STATS((net)->mib.net_statistics, field)
#define __NET_INC_STATS(net, field)	__SNMP_INC_STATS((net)->mib.net_statistics, field)
#define NET_ADD_STATS(net, field, adnd)	SNMP_ADD_STATS((net)->mib.net_statistics, field, adnd)
#define __NET_ADD_STATS(net, field, adnd) __SNMP_ADD_STATS((net)->mib.net_statistics, field, adnd)

void inet_get_local_port_range(struct net *net, int *low, int *high);

#ifdef CONFIG_SYSCTL
static inline bool inet_is_local_reserved_port(struct net *net, unsigned short port)
{
	if (!net->ipv4.sysctl_local_reserved_ports)
		return false;
	return test_bit(port, net->ipv4.sysctl_local_reserved_ports);
}

static inline bool sysctl_dev_name_is_allowed(const char *name)
{
	return strcmp(name, "default") != 0  && strcmp(name, "all") != 0;
}

static inline bool inet_port_requires_bind_service(struct net *net, unsigned short port)
{
	return port < net->ipv4.sysctl_ip_prot_sock;
}

#else
static inline bool inet_is_local_reserved_port(struct net *net, unsigned short port)
{
	return false;
}

static inline bool inet_port_requires_bind_service(struct net *net, unsigned short port)
{
	return port < PROT_SOCK;
}
#endif

__be32 inet_current_timestamp(void);

/* From inetpeer.c */
extern int inet_peer_threshold;
extern int inet_peer_minttl;
extern int inet_peer_maxttl;

void ipfrag_init(void);

void ip_static_sysctl_init(void);

#define IP4_REPLY_MARK(net, mark) \
	((net)->ipv4.sysctl_fwmark_reflect ? (mark) : 0)

static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

static inline unsigned int ipv4_addr_hash(__be32 ip)
{
	return (__force unsigned int) ip;
}

static inline u32 ipv4_portaddr_hash(const struct net *net,
				     __be32 saddr,
				     unsigned int port)
{
	return jhash_1word((__force u32)saddr, net_hash_mix(net)) ^ port;
}

bool ip_call_ra_chain(struct sk_buff *skb);

/*
 *	Functions provided by ip_fragment.c
 */

enum ip_defrag_users {
	IP_DEFRAG_LOCAL_DELIVER,
	IP_DEFRAG_CALL_RA_CHAIN,
	IP_DEFRAG_CONNTRACK_IN,
	__IP_DEFRAG_CONNTRACK_IN_END	= IP_DEFRAG_CONNTRACK_IN + USHRT_MAX,
	IP_DEFRAG_CONNTRACK_OUT,
	__IP_DEFRAG_CONNTRACK_OUT_END	= IP_DEFRAG_CONNTRACK_OUT + USHRT_MAX,
	IP_DEFRAG_CONNTRACK_BRIDGE_IN,
	__IP_DEFRAG_CONNTRACK_BRIDGE_IN = IP_DEFRAG_CONNTRACK_BRIDGE_IN + USHRT_MAX,
	IP_DEFRAG_VS_IN,
	IP_DEFRAG_VS_OUT,
	IP_DEFRAG_VS_FWD,
	IP_DEFRAG_AF_PACKET,
	IP_DEFRAG_MACVLAN,
};

/* Return true if the value of 'user' is between 'lower_bond'
 * and 'upper_bond' inclusively.
 */
static inline bool ip_defrag_user_in_between(u32 user,
					     enum ip_defrag_users lower_bond,
					     enum ip_defrag_users upper_bond)
{
	return user >= lower_bond && user <= upper_bond;
}

int ip_defrag(struct net *net, struct sk_buff *skb, u32 user);
#ifdef CONFIG_INET
struct sk_buff *ip_check_defrag(struct net *net, struct sk_buff *skb, u32 user);
#else
static inline struct sk_buff *ip_check_defrag(struct net *net, struct sk_buff *skb, u32 user)
{
	return skb;
}
#endif

/*
 *	Functions provided by ip_forward.c
 */

int ip_forward(struct sk_buff *skb);

/*
 *	Functions provided by ip_options.c
 */

void ip_options_build(struct sk_buff *skb, struct ip_options *opt,
		      __be32 daddr, struct rtable *rt, int is_frag);

int __ip_options_echo(struct net *net, struct ip_options *dopt,
		      struct sk_buff *skb, const struct ip_options *sopt);
static inline int ip_options_echo(struct net *net, struct ip_options *dopt,
				  struct sk_buff *skb)
{
	return __ip_options_echo(net, dopt, skb, &IPCB(skb)->opt);
}

void ip_options_fragment(struct sk_buff *skb);
int __ip_options_compile(struct net *net, struct ip_options *opt,
			 struct sk_buff *skb, __be32 *info);
int ip_options_compile(struct net *net, struct ip_options *opt,
		       struct sk_buff *skb);
int ip_options_get(struct net *net, struct ip_options_rcu **optp,
		   sockptr_t data, int optlen);
void ip_options_undo(struct ip_options *opt);
void ip_forward_options(struct sk_buff *skb);
int ip_options_rcv_srr(struct sk_buff *skb, struct net_device *dev);

/*
 *	Functions provided by ip_sockglue.c
 */

void ipv4_pktinfo_prepare(const struct sock *sk, struct sk_buff *skb);
void ip_cmsg_recv_offset(struct msghdr *msg, struct sock *sk,
			 struct sk_buff *skb, int tlen, int offset);
int ip_cmsg_send(struct sock *sk, struct msghdr *msg,
		 struct ipcm_cookie *ipc, bool allow_ipv6);
DECLARE_STATIC_KEY_FALSE(ip4_min_ttl);
int ip_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
		  unsigned int optlen);
int ip_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		  int __user *optlen);
int ip_ra_control(struct sock *sk, unsigned char on,
		  void (*destructor)(struct sock *));

int ip_recv_error(struct sock *sk, struct msghdr *msg, int len, int *addr_len);
void ip_icmp_error(struct sock *sk, struct sk_buff *skb, int err, __be16 port,
		   u32 info, u8 *payload);
void ip_local_error(struct sock *sk, int err, __be32 daddr, __be16 dport,
		    u32 info);

static inline void ip_cmsg_recv(struct msghdr *msg, struct sk_buff *skb)
{
	ip_cmsg_recv_offset(msg, skb->sk, skb, 0, 0);
}

bool icmp_global_allow(void);
extern int sysctl_icmp_msgs_per_sec;
extern int sysctl_icmp_msgs_burst;

#ifdef CONFIG_PROC_FS
int ip_misc_proc_init(void);
#endif

int rtm_getroute_parse_ip_proto(struct nlattr *attr, u8 *ip_proto, u8 family,
				struct netlink_ext_ack *extack);

static inline bool inetdev_valid_mtu(unsigned int mtu)
{
	return likely(mtu >= IPV4_MIN_MTU);
}

void ip_sock_set_freebind(struct sock *sk);
int ip_sock_set_mtu_discover(struct sock *sk, int val);
void ip_sock_set_pktinfo(struct sock *sk);
void ip_sock_set_recverr(struct sock *sk);
void ip_sock_set_tos(struct sock *sk, int val);
void  __ip_sock_set_tos(struct sock *sk, int val);

#endif	/* _IP_H */
