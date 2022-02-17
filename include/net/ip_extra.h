/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _IP_EXTRA_H
#define _IP_EXTRA_H

#include <net/ip.h>

#ifdef CONFIG_INET
#include <net/dst.h>

/* The function in 2.2 was invalid, producing wrong result for
 * check=0xFEFF. It was noticed by Arthur Skawina _year_ ago. --ANK(000625) */
static inline
int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;
	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check>=0xFFFF));
	return --iph->ttl;
}

static inline int ip_mtu_locked(const struct dst_entry *dst)
{
	const struct rtable *rt = (const struct rtable *)dst;

	return rt->rt_mtu_locked || dst_metric_locked(dst, RTAX_MTU);
}

static inline
int ip_dont_fragment(const struct sock *sk, const struct dst_entry *dst)
{
	u8 pmtudisc = READ_ONCE(inet_sk(sk)->pmtudisc);

	return  pmtudisc == IP_PMTUDISC_DO ||
		(pmtudisc == IP_PMTUDISC_WANT &&
		 !ip_mtu_locked(dst));
}

static inline bool ip_sk_accept_pmtu(const struct sock *sk)
{
	return inet_sk(sk)->pmtudisc != IP_PMTUDISC_INTERFACE &&
	       inet_sk(sk)->pmtudisc != IP_PMTUDISC_OMIT;
}

static inline bool ip_sk_use_pmtu(const struct sock *sk)
{
	return inet_sk(sk)->pmtudisc < IP_PMTUDISC_PROBE;
}

static inline bool ip_sk_ignore_df(const struct sock *sk)
{
	return inet_sk(sk)->pmtudisc < IP_PMTUDISC_DO ||
	       inet_sk(sk)->pmtudisc == IP_PMTUDISC_OMIT;
}

static inline unsigned int ip_dst_mtu_maybe_forward(const struct dst_entry *dst,
						    bool forwarding)
{
	const struct rtable *rt = container_of(dst, struct rtable, dst);
	struct net *net = dev_net(dst->dev);
	unsigned int mtu;

	if (net->ipv4.sysctl_ip_fwd_use_pmtu ||
	    ip_mtu_locked(dst) ||
	    !forwarding) {
		mtu = rt->rt_pmtu;
		if (mtu && time_before(jiffies, rt->dst.expires))
			goto out;
	}

	/* 'forwarding = true' case should always honour route mtu */
	mtu = dst_metric_raw(dst, RTAX_MTU);
	if (mtu)
		goto out;

	mtu = READ_ONCE(dst->dev->mtu);

	if (unlikely(ip_mtu_locked(dst))) {
		if (rt->rt_uses_gateway && mtu > 576)
			mtu = 576;
	}

out:
	mtu = min_t(unsigned int, mtu, IP_MAX_MTU);

	return mtu - lwtunnel_headroom(dst->lwtstate, mtu);
}

static inline unsigned int ip_skb_dst_mtu(struct sock *sk,
					  const struct sk_buff *skb)
{
	unsigned int mtu;

	if (!sk || !sk_fullsock(sk) || ip_sk_use_pmtu(sk)) {
		bool forwarding = IPCB(skb)->flags & IPSKB_FORWARDED;

		return ip_dst_mtu_maybe_forward(skb_dst(skb), forwarding);
	}

	mtu = min(READ_ONCE(skb_dst(skb)->dev->mtu), IP_MAX_MTU);
	return mtu - lwtunnel_headroom(skb_dst(skb)->lwtstate, mtu);
}

struct dst_metrics *ip_fib_metrics_init(struct net *net, struct nlattr *fc_mx,
					int fc_mx_len,
					struct netlink_ext_ack *extack);
static inline void ip_fib_metrics_put(struct dst_metrics *fib_metrics)
{
	if (fib_metrics != &dst_default_metrics &&
	    refcount_dec_and_test(&fib_metrics->refcnt))
		kfree(fib_metrics);
}

/* ipv4 and ipv6 both use refcounted metrics if it is not the default */
static inline
void ip_dst_init_metrics(struct dst_entry *dst, struct dst_metrics *fib_metrics)
{
	dst_init_metrics(dst, fib_metrics->metrics, true);

	if (fib_metrics != &dst_default_metrics) {
		dst->_metrics |= DST_METRICS_REFCOUNTED;
		refcount_inc(&fib_metrics->refcnt);
	}
}

static inline
void ip_dst_metrics_put(struct dst_entry *dst)
{
	struct dst_metrics *p = (struct dst_metrics *)DST_METRICS_PTR(dst);

	if (p != &dst_default_metrics && refcount_dec_and_test(&p->refcnt))
		kfree(p);
}

u32 ip_idents_reserve(u32 hash, int segs);
void __ip_select_ident(struct net *net, struct iphdr *iph, int segs);

static inline void ip_select_ident_segs(struct net *net, struct sk_buff *skb,
					struct sock *sk, int segs)
{
	struct iphdr *iph = ip_hdr(skb);

	/* We had many attacks based on IPID, use the private
	 * generator as much as we can.
	 */
	if (sk && inet_sk(sk)->inet_daddr) {
		iph->id = htons(inet_sk(sk)->inet_id);
		inet_sk(sk)->inet_id += segs;
		return;
	}
	if ((iph->frag_off & htons(IP_DF)) && !skb->ignore_df) {
		iph->id = 0;
	} else {
		/* Unfortunately we need the big hammer to get a suitable IPID */
		__ip_select_ident(net, iph, segs);
	}
}

static inline void ip_select_ident(struct net *net, struct sk_buff *skb,
				   struct sock *sk)
{
	ip_select_ident_segs(net, skb, sk, 1);
}

static inline __wsum inet_compute_pseudo(struct sk_buff *skb, int proto)
{
	return csum_tcpudp_nofold(ip_hdr(skb)->saddr, ip_hdr(skb)->daddr,
				  skb->len, proto, 0);
}

/* copy IPv4 saddr & daddr to flow_keys, possibly using 64bit load/store
 * Equivalent to :	flow->v4addrs.src = iph->saddr;
 *			flow->v4addrs.dst = iph->daddr;
 */
static inline void iph_to_flow_copy_v4addrs(struct flow_keys *flow,
					    const struct iphdr *iph)
{
	BUILD_BUG_ON(offsetof(typeof(flow->addrs), v4addrs.dst) !=
		     offsetof(typeof(flow->addrs), v4addrs.src) +
			      sizeof(flow->addrs.v4addrs.src));
	memcpy(&flow->addrs.v4addrs, &iph->saddr, sizeof(flow->addrs.v4addrs));
	flow->control.addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
}

/*
 *	Map a multicast IP onto multicast MAC for type ethernet.
 */

static inline void ip_eth_mc_map(__be32 naddr, char *buf)
{
	__u32 addr=ntohl(naddr);
	buf[0]=0x01;
	buf[1]=0x00;
	buf[2]=0x5e;
	buf[5]=addr&0xFF;
	addr>>=8;
	buf[4]=addr&0xFF;
	addr>>=8;
	buf[3]=addr&0x7F;
}

/*
 *	Map a multicast IP onto multicast MAC for type IP-over-InfiniBand.
 *	Leave P_Key as 0 to be filled in by driver.
 */

static inline void ip_ib_mc_map(__be32 naddr, const unsigned char *broadcast, char *buf)
{
	__u32 addr;
	unsigned char scope = broadcast[5] & 0xF;

	buf[0]  = 0;		/* Reserved */
	buf[1]  = 0xff;		/* Multicast QPN */
	buf[2]  = 0xff;
	buf[3]  = 0xff;
	addr    = ntohl(naddr);
	buf[4]  = 0xff;
	buf[5]  = 0x10 | scope;	/* scope from broadcast address */
	buf[6]  = 0x40;		/* IPv4 signature */
	buf[7]  = 0x1b;
	buf[8]  = broadcast[8];		/* P_Key */
	buf[9]  = broadcast[9];
	buf[10] = 0;
	buf[11] = 0;
	buf[12] = 0;
	buf[13] = 0;
	buf[14] = 0;
	buf[15] = 0;
	buf[19] = addr & 0xff;
	addr  >>= 8;
	buf[18] = addr & 0xff;
	addr  >>= 8;
	buf[17] = addr & 0xff;
	addr  >>= 8;
	buf[16] = addr & 0x0f;
}

static inline void ip_ipgre_mc_map(__be32 naddr, const unsigned char *broadcast, char *buf)
{
	if ((broadcast[0] | broadcast[1] | broadcast[2] | broadcast[3]) != 0)
		memcpy(buf, broadcast, 4);
	else
		memcpy(buf, &naddr, sizeof(naddr));
}

#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#endif

static __inline__ void inet_reset_saddr(struct sock *sk)
{
	inet_sk(sk)->inet_rcv_saddr = inet_sk(sk)->inet_saddr = 0;
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == PF_INET6) {
		struct ipv6_pinfo *np = inet6_sk(sk);

		memset(&np->saddr, 0, sizeof(np->saddr));
		memset(&sk->sk_v6_rcv_saddr, 0, sizeof(sk->sk_v6_rcv_saddr));
	}
#endif
}

#endif

#endif	/* _IP_EXTRA_H */
