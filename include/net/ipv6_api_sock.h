/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _NET_IPV6_API_SOCK_H
#define _NET_IPV6_API_SOCK_H

#include <net/ipv6.h>
#include <net/sock_api.h>

int ipv6_sock_mc_join(struct sock *sk, int ifindex,
		      const struct in6_addr *addr);
int ipv6_sock_mc_join_ssm(struct sock *sk, int ifindex,
			  const struct in6_addr *addr, unsigned int mode);
int ipv6_sock_mc_drop(struct sock *sk, int ifindex,
		      const struct in6_addr *addr);

static inline int ip6_sock_set_v6only(struct sock *sk)
{
	if (inet_sk(sk)->inet_num)
		return -EINVAL;
	lock_sock(sk);
	sk->sk_ipv6only = true;
	release_sock(sk);
	return 0;
}

static inline void ip6_sock_set_recverr(struct sock *sk)
{
	lock_sock(sk);
	inet6_sk(sk)->recverr = true;
	release_sock(sk);
}

static inline int __ip6_sock_set_addr_preferences(struct sock *sk, int val)
{
	unsigned int pref = 0;
	unsigned int prefmask = ~0;

	/* check PUBLIC/TMP/PUBTMP_DEFAULT conflicts */
	switch (val & (IPV6_PREFER_SRC_PUBLIC |
		       IPV6_PREFER_SRC_TMP |
		       IPV6_PREFER_SRC_PUBTMP_DEFAULT)) {
	case IPV6_PREFER_SRC_PUBLIC:
		pref |= IPV6_PREFER_SRC_PUBLIC;
		prefmask &= ~(IPV6_PREFER_SRC_PUBLIC |
			      IPV6_PREFER_SRC_TMP);
		break;
	case IPV6_PREFER_SRC_TMP:
		pref |= IPV6_PREFER_SRC_TMP;
		prefmask &= ~(IPV6_PREFER_SRC_PUBLIC |
			      IPV6_PREFER_SRC_TMP);
		break;
	case IPV6_PREFER_SRC_PUBTMP_DEFAULT:
		prefmask &= ~(IPV6_PREFER_SRC_PUBLIC |
			      IPV6_PREFER_SRC_TMP);
		break;
	case 0:
		break;
	default:
		return -EINVAL;
	}

	/* check HOME/COA conflicts */
	switch (val & (IPV6_PREFER_SRC_HOME | IPV6_PREFER_SRC_COA)) {
	case IPV6_PREFER_SRC_HOME:
		prefmask &= ~IPV6_PREFER_SRC_COA;
		break;
	case IPV6_PREFER_SRC_COA:
		pref |= IPV6_PREFER_SRC_COA;
		break;
	case 0:
		break;
	default:
		return -EINVAL;
	}

	/* check CGA/NONCGA conflicts */
	switch (val & (IPV6_PREFER_SRC_CGA|IPV6_PREFER_SRC_NONCGA)) {
	case IPV6_PREFER_SRC_CGA:
	case IPV6_PREFER_SRC_NONCGA:
	case 0:
		break;
	default:
		return -EINVAL;
	}

	inet6_sk(sk)->srcprefs = (inet6_sk(sk)->srcprefs & prefmask) | pref;
	return 0;
}

static inline int ip6_sock_set_addr_preferences(struct sock *sk, bool val)
{
	int ret;

	lock_sock(sk);
	ret = __ip6_sock_set_addr_preferences(sk, val);
	release_sock(sk);
	return ret;
}

static inline void ip6_sock_set_recvpktinfo(struct sock *sk)
{
	lock_sock(sk);
	inet6_sk(sk)->rxopt.bits.rxinfo = true;
	release_sock(sk);
}

#endif /* _NET_IPV6_API_SOCK_H */
