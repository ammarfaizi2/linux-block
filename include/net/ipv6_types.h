/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *	Linux INET6 implementation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 */

#ifndef _NET_IPV6_TYPES_H
#define _NET_IPV6_TYPES_H

#include <linux/refcount_types.h>
#include <linux/uidgid.h>

#include <uapi/linux/in6.h>

struct ip_tunnel_info;

#define SIN6_LEN_RFC2133	24

#define IPV6_MAXPLEN		65535

/*
 *	NextHeader field of IPv6 header
 */

#define NEXTHDR_HOP		0	/* Hop-by-hop option header. */
#define NEXTHDR_IPV4		4	/* IPv4 in IPv6 */
#define NEXTHDR_TCP		6	/* TCP segment. */
#define NEXTHDR_UDP		17	/* UDP message. */
#define NEXTHDR_IPV6		41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_GRE		47	/* GRE header. */
#define NEXTHDR_ESP		50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP		58	/* ICMP for IPv6. */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */
#define NEXTHDR_SCTP		132	/* SCTP message. */
#define NEXTHDR_MOBILITY	135	/* Mobility header. */

#define NEXTHDR_MAX		255

#define IPV6_DEFAULT_HOPLIMIT   64
#define IPV6_DEFAULT_MCASTHOPS	1

/* Limits on Hop-by-Hop and Destination options.
 *
 * Per RFC8200 there is no limit on the maximum number or lengths of options in
 * Hop-by-Hop or Destination options other then the packet must fit in an MTU.
 * We allow configurable limits in order to mitigate potential denial of
 * service attacks.
 *
 * There are three limits that may be set:
 *   - Limit the number of options in a Hop-by-Hop or Destination options
 *     extension header
 *   - Limit the byte length of a Hop-by-Hop or Destination options extension
 *     header
 *   - Disallow unknown options
 *
 * The limits are expressed in corresponding sysctls:
 *
 * ipv6.sysctl.max_dst_opts_cnt
 * ipv6.sysctl.max_hbh_opts_cnt
 * ipv6.sysctl.max_dst_opts_len
 * ipv6.sysctl.max_hbh_opts_len
 *
 * max_*_opts_cnt is the number of TLVs that are allowed for Destination
 * options or Hop-by-Hop options. If the number is less than zero then unknown
 * TLVs are disallowed and the number of known options that are allowed is the
 * absolute value. Setting the value to INT_MAX indicates no limit.
 *
 * max_*_opts_len is the length limit in bytes of a Destination or
 * Hop-by-Hop options extension header. Setting the value to INT_MAX
 * indicates no length limit.
 *
 * If a limit is exceeded when processing an extension header the packet is
 * silently discarded.
 */

/* Default limits for Hop-by-Hop and Destination options */
#define IP6_DEFAULT_MAX_DST_OPTS_CNT	 8
#define IP6_DEFAULT_MAX_HBH_OPTS_CNT	 8
#define IP6_DEFAULT_MAX_DST_OPTS_LEN	 INT_MAX /* No limit */
#define IP6_DEFAULT_MAX_HBH_OPTS_LEN	 INT_MAX /* No limit */

/*
 *	Addr type
 *	
 *	type	-	unicast | multicast
 *	scope	-	local	| site	    | global
 *	v4	-	compat
 *	v4mapped
 *	any
 *	loopback
 */

#define IPV6_ADDR_ANY		0x0000U

#define IPV6_ADDR_UNICAST	0x0001U
#define IPV6_ADDR_MULTICAST	0x0002U

#define IPV6_ADDR_LOOPBACK	0x0010U
#define IPV6_ADDR_LINKLOCAL	0x0020U
#define IPV6_ADDR_SITELOCAL	0x0040U

#define IPV6_ADDR_COMPATv4	0x0080U

#define IPV6_ADDR_SCOPE_MASK	0x00f0U

#define IPV6_ADDR_MAPPED	0x1000U

/*
 *	Addr scopes
 */
#define IPV6_ADDR_MC_SCOPE(a)	\
	((a)->s6_addr[1] & 0x0f)	/* nonstandard */
#define __IPV6_ADDR_SCOPE_INVALID	-1
#define IPV6_ADDR_SCOPE_NODELOCAL	0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL	0x02
#define IPV6_ADDR_SCOPE_SITELOCAL	0x05
#define IPV6_ADDR_SCOPE_ORGLOCAL	0x08
#define IPV6_ADDR_SCOPE_GLOBAL		0x0e

/*
 *	Addr flags
 */
#define IPV6_ADDR_MC_FLAG_TRANSIENT(a)	\
	((a)->s6_addr[1] & 0x10)
#define IPV6_ADDR_MC_FLAG_PREFIX(a)	\
	((a)->s6_addr[1] & 0x20)
#define IPV6_ADDR_MC_FLAG_RENDEZVOUS(a)	\
	((a)->s6_addr[1] & 0x40)

/*
 *	fragmentation header
 */

struct frag_hdr {
	__u8	nexthdr;
	__u8	reserved;
	__be16	frag_off;
	__be32	identification;
};

#define	IP6_MF		0x0001
#define	IP6_OFFSET	0xFFF8

struct ip6_fraglist_iter {
	struct ipv6hdr	*tmp_hdr;
	struct sk_buff	*frag;
	int		offset;
	unsigned int	hlen;
	__be32		frag_id;
	u8		nexthdr;
};

struct ip6_frag_state {
	u8		*prevhdr;
	unsigned int	hlen;
	unsigned int	mtu;
	unsigned int	left;
	int		offset;
	int		ptr;
	int		hroom;
	int		troom;
	__be32		frag_id;
	u8		nexthdr;
};

struct ip6_ra_chain {
	struct ip6_ra_chain	*next;
	struct sock		*sk;
	int			sel;
	void			(*destructor)(struct sock *);
};

/*
   This structure is prepared by protocol, when parsing
   ancillary data and passed to IPv6.
 */

struct ipv6_txoptions {
	refcount_t		refcnt;
	/* Length of this structure */
	int			tot_len;

	/* length of extension headers   */

	__u16			opt_flen;	/* after fragment hdr */
	__u16			opt_nflen;	/* before fragment hdr */

	struct ipv6_opt_hdr	*hopopt;
	struct ipv6_opt_hdr	*dst0opt;
	struct ipv6_rt_hdr	*srcrt;	/* Routing Header */
	struct ipv6_opt_hdr	*dst1opt;
	struct rcu_head		rcu;
	/* Option buffer, as read by IPV6_PKTOPTIONS, starts here. */
};

/* flowlabel_reflect sysctl values */
enum flowlabel_reflect {
	FLOWLABEL_REFLECT_ESTABLISHED		= 1,
	FLOWLABEL_REFLECT_TCP_RESET		= 2,
	FLOWLABEL_REFLECT_ICMPV6_ECHO_REPLIES	= 4,
};

struct ip6_flowlabel {
	struct ip6_flowlabel __rcu *next;
	__be32			label;
	atomic_t		users;
	struct in6_addr		dst;
	struct ipv6_txoptions	*opt;
	unsigned long		linger;
	struct rcu_head		rcu;
	u8			share;
	union {
		struct pid *pid;
		kuid_t uid;
	} owner;
	unsigned long		lastuse;
	unsigned long		expires;
	struct net		*fl_net;
};

#define IPV6_FLOWINFO_MASK		cpu_to_be32(0x0FFFFFFF)
#define IPV6_FLOWLABEL_MASK		cpu_to_be32(0x000FFFFF)
#define IPV6_FLOWLABEL_STATELESS_FLAG	cpu_to_be32(0x00080000)

#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define IPV6_TCLASS_SHIFT	20

struct ipv6_fl_socklist {
	struct ipv6_fl_socklist	__rcu	*next;
	struct ip6_flowlabel		*fl;
	struct rcu_head			rcu;
};

enum {
	IP6_FH_F_FRAG		= (1 << 0),
	IP6_FH_F_AUTH		= (1 << 1),
	IP6_FH_F_SKIP_RH	= (1 << 2),
};

#endif /* _NET_IPV6_TYPES_H */
