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
#ifndef _INET_SOCK_API_H
#define _INET_SOCK_API_H

#include <net/inet_sock_types.h>

#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/jhash.h>
#include <linux/netdevice.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>
#include <net/netns/hash.h>
#include <net/tcp_states.h>
#include <net/l3mdev.h>

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

static inline u32 inet_request_mark(const struct sock *sk, struct sk_buff *skb)
{
	if (!sk->sk_mark && sock_net(sk)->ipv4.sysctl_tcp_fwmark_accept)
		return skb->mark;

	return sk->sk_mark;
}

static inline int inet_request_bound_dev_if(const struct sock *sk,
					    struct sk_buff *skb)
{
#ifdef CONFIG_NET_L3_MASTER_DEV
	struct net *net = sock_net(sk);

	if (!sk->sk_bound_dev_if && net->ipv4.sysctl_tcp_l3mdev_accept)
		return l3mdev_master_ifindex_by_index(net, skb->skb_iif);
#endif

	return sk->sk_bound_dev_if;
}

static inline int inet_sk_bound_l3mdev(const struct sock *sk)
{
#ifdef CONFIG_NET_L3_MASTER_DEV
	struct net *net = sock_net(sk);

	if (!net->ipv4.sysctl_tcp_l3mdev_accept)
		return l3mdev_master_ifindex_by_index(net,
						      sk->sk_bound_dev_if);
#endif

	return 0;
}

static inline bool inet_bound_dev_eq(bool l3mdev_accept, int bound_dev_if,
				     int dif, int sdif)
{
	if (!bound_dev_if)
		return !sdif || l3mdev_accept;
	return bound_dev_if == dif || bound_dev_if == sdif;
}

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */

/* cmsg flags for inet */
#define IP_CMSG_PKTINFO		BIT(0)
#define IP_CMSG_TTL		BIT(1)
#define IP_CMSG_TOS		BIT(2)
#define IP_CMSG_RECVOPTS	BIT(3)
#define IP_CMSG_RETOPTS		BIT(4)
#define IP_CMSG_PASSSEC		BIT(5)
#define IP_CMSG_ORIGDSTADDR	BIT(6)
#define IP_CMSG_CHECKSUM	BIT(7)
#define IP_CMSG_RECVFRAGSIZE	BIT(8)

/**
 * sk_to_full_sk - Access to a full socket
 * @sk: pointer to a socket
 *
 * SYNACK messages might be attached to request sockets.
 * Some places want to reach the listener in this case.
 */
static inline struct sock *sk_to_full_sk(struct sock *sk)
{
#ifdef CONFIG_INET
	if (sk && sk->sk_state == TCP_NEW_SYN_RECV)
		sk = inet_reqsk(sk)->rsk_listener;
#endif
	return sk;
}

/* sk_to_full_sk() variant with a const argument */
static inline const struct sock *sk_const_to_full_sk(const struct sock *sk)
{
#ifdef CONFIG_INET
	if (sk && sk->sk_state == TCP_NEW_SYN_RECV)
		sk = ((const struct request_sock *)sk)->rsk_listener;
#endif
	return sk;
}

static inline struct sock *skb_to_full_sk(const struct sk_buff *skb)
{
	return sk_to_full_sk(skb->sk);
}

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}

int inet_sk_rebuild_header(struct sock *sk);

/**
 * inet_sk_state_load - read sk->sk_state for lockless contexts
 * @sk: socket pointer
 *
 * Paired with inet_sk_state_store(). Used in places we don't hold socket lock:
 * tcp_diag_get_info(), tcp_get_info(), tcp_poll(), get_tcp4_sock() ...
 */
static inline int inet_sk_state_load(const struct sock *sk)
{
	/* state change might impact lockless readers. */
	return smp_load_acquire(&sk->sk_state);
}

/**
 * inet_sk_state_store - update sk->sk_state
 * @sk: socket pointer
 * @newstate: new state
 *
 * Paired with inet_sk_state_load(). Should be used in contexts where
 * state change might impact lockless readers.
 */
void inet_sk_state_store(struct sock *sk, int newstate);

void inet_sk_set_state(struct sock *sk, int state);

static inline unsigned int __inet_ehashfn(const __be32 laddr,
					  const __u16 lport,
					  const __be32 faddr,
					  const __be16 fport,
					  u32 initval)
{
	return jhash_3words((__force __u32) laddr,
			    (__force __u32) faddr,
			    ((__u32) lport) << 16 | (__force __u32)fport,
			    initval);
}

struct request_sock *inet_reqsk_alloc(const struct request_sock_ops *ops,
				      struct sock *sk_listener,
				      bool attach_listener);

static inline __u8 inet_sk_flowi_flags(const struct sock *sk)
{
	__u8 flags = 0;

	if (inet_sk(sk)->transparent || inet_sk(sk)->hdrincl)
		flags |= FLOWI_FLAG_ANYSRC;
	return flags;
}

static inline void inet_inc_convert_csum(struct sock *sk)
{
	inet_sk(sk)->convert_csum++;
}

static inline void inet_dec_convert_csum(struct sock *sk)
{
	if (inet_sk(sk)->convert_csum > 0)
		inet_sk(sk)->convert_csum--;
}

static inline bool inet_get_convert_csum(struct sock *sk)
{
	return !!inet_sk(sk)->convert_csum;
}


static inline bool inet_can_nonlocal_bind(struct net *net,
					  struct inet_sock *inet)
{
	return net->ipv4.sysctl_ip_nonlocal_bind ||
		inet->freebind || inet->transparent;
}

static inline bool inet_addr_valid_or_nonlocal(struct net *net,
					       struct inet_sock *inet,
					       __be32 addr,
					       int addr_type)
{
	return inet_can_nonlocal_bind(net, inet) ||
		addr == htonl(INADDR_ANY) ||
		addr_type == RTN_LOCAL ||
		addr_type == RTN_MULTICAST ||
		addr_type == RTN_BROADCAST;
}

#endif	/* _INET_SOCK_API_H */
