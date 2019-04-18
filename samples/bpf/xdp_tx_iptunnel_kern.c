/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program shows how to use bpf_xdp_adjust_head() by
 * encapsulating the incoming packet in an IPv4/v6 header
 * and then XDP_TX it out.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include "xdp_tx_iptunnel_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 256);
} rxcnt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct vip);
	__type(value, struct iptnl_info);
	__uint(max_entries, MAX_IPTNL_ENTRIES);
} vip2tnl SEC(".maps");

static __always_inline void count_tx(u32 protocol)
{
	u64 *rxcnt_count;

	rxcnt_count = bpf_map_lookup_elem(&rxcnt, &protocol);
	if (rxcnt_count)
		*rxcnt_count += 1;
}

static __always_inline int get_dport(void *trans_data, void *data_end,
				     u8 protocol)
{
	struct tcphdr *th;
	struct udphdr *uh;

	switch (protocol) {
	case IPPROTO_TCP:
		th = (struct tcphdr *)trans_data;
		if (th + 1 > data_end)
			return -1;
		return th->dest;
	case IPPROTO_UDP:
		uh = (struct udphdr *)trans_data;
		if (uh + 1 > data_end)
			return -1;
		return uh->dest;
	default:
		return 0;
	}
}

static __always_inline void set_ethhdr(struct ethhdr *new_eth,
				       const struct ethhdr *old_eth,
				       const struct iptnl_info *tnl,
				       __be16 h_proto)
{
	memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));
	memcpy(new_eth->h_dest, tnl->dmac, sizeof(new_eth->h_dest));
	new_eth->h_proto = h_proto;
}

static __always_inline struct iptnl_info *
find_tnl_ipv4(struct xdp_md *xdp, __u8 *proto, __u16 *payload_len)
{
	void         *data_end = (void *)(long)xdp->data_end;
	void         *data     = (void *)(long)xdp->data;
	struct iphdr *iph      = data + sizeof(struct ethhdr);
	struct vip vip = {};
	int dport;

	if (iph + 1 > data_end)
		return NULL;

	dport = get_dport(iph + 1, data_end, iph->protocol);
	if (dport == -1)
		return NULL;

	vip.protocol = iph->protocol;
	vip.family = AF_INET;
	vip.daddr.v4 = iph->daddr;
	vip.dport = dport;
	*payload_len = ntohs(iph->tot_len);
	*proto = vip.protocol;

	return bpf_map_lookup_elem(&vip2tnl, &vip);
}

static __always_inline int
fwd_tnl_ipv4(struct xdp_md *xdp, struct iptnl_info *tnl, __u8 proto, __u16 payload_len)
{
	void  *data_end, *data;
	struct ethhdr *new_eth;
	struct ethhdr *old_eth;
	struct iphdr *iph;
	u16 *next_iph_u16;
	u32 csum = 0;
	int i;

	/* It only does v4-in-v4 */
	if (!tnl || tnl->family != AF_INET)
		return XDP_PASS;

	/* The vip key is found.  Add an IP header and send it out */

	if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr)))
		return XDP_DROP;

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;

	new_eth = data;
	iph = data + sizeof(*new_eth);
	old_eth = data + sizeof(*iph);

	if (new_eth + 1 > data_end ||
	    old_eth + 1 > data_end ||
	    iph + 1 > data_end)
		return XDP_DROP;

	set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IP));

	iph->version = 4;
	iph->ihl = sizeof(*iph) >> 2;
	iph->frag_off =	0;
	iph->protocol = IPPROTO_IPIP;
	iph->check = 0;
	iph->tos = 0;
	iph->tot_len = htons(payload_len + sizeof(*iph));
	iph->daddr = tnl->daddr.v4;
	iph->saddr = tnl->saddr.v4;
	iph->ttl = 8;

	next_iph_u16 = (u16 *)iph;
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(*iph) >> 1; i++)
		csum += *next_iph_u16++;

	iph->check = ~((csum & 0xffff) + (csum >> 16));

	count_tx(proto);

	return XDP_TX;
}

static __always_inline int handle_ipv4(struct xdp_md *xdp)
{
	struct iptnl_info *tnl;
	__u16 payload_len;
	__u8 proto;

	tnl = find_tnl_ipv4(xdp, &proto, &payload_len);
	return fwd_tnl_ipv4(xdp, tnl, proto, payload_len);
}

static __always_inline struct iptnl_info *
find_tnl_ipv6(struct xdp_md *xdp, __u8 *proto, __u16 *payload_len)
{
	void           *data_end = (void *)(long)xdp->data_end;
	void           *data     = (void *)(long)xdp->data;
	struct ipv6hdr *ip6h     = data + sizeof(struct ethhdr);
	struct vip vip = {};
	int dport;

	if (ip6h + 1 > data_end)
		return NULL;

	dport = get_dport(ip6h + 1, data_end, ip6h->nexthdr);
	if (dport == -1)
		return NULL;

	vip.protocol = ip6h->nexthdr;
	vip.family = AF_INET6;
	memcpy(vip.daddr.v6, ip6h->daddr.s6_addr32, sizeof(vip.daddr));
	vip.dport = dport;
	*payload_len = ip6h->payload_len;
	*proto = vip.protocol;

	return bpf_map_lookup_elem(&vip2tnl, &vip);
}

static __always_inline int
fwd_tnl_ipv6(struct xdp_md *xdp, struct iptnl_info *tnl, __u8 proto, __u16 payload_len)
{
	void  *data_end, *data;
	struct ethhdr *new_eth;
	struct ethhdr *old_eth;
	struct ipv6hdr *ip6h;

	/* It only does v6-in-v6 */
	if (!tnl || tnl->family != AF_INET6)
		return XDP_PASS;

	/* The vip key is found.  Add an IP header and send it out */
	if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct ipv6hdr)))
		return XDP_DROP;

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;

	new_eth = data;
	ip6h = data + sizeof(*new_eth);
	old_eth = data + sizeof(*ip6h);

	if (new_eth + 1 > data_end ||
	    old_eth + 1 > data_end ||
	    ip6h + 1 > data_end)
		return XDP_DROP;

	set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IPV6));

	ip6h->version = 6;
	ip6h->priority = 0;
	memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
	ip6h->payload_len = htons(ntohs(payload_len) + sizeof(*ip6h));
	ip6h->nexthdr = IPPROTO_IPV6;
	ip6h->hop_limit = 8;
	memcpy(ip6h->saddr.s6_addr32, tnl->saddr.v6, sizeof(tnl->saddr.v6));
	memcpy(ip6h->daddr.s6_addr32, tnl->daddr.v6, sizeof(tnl->daddr.v6));

	count_tx(proto);

	return XDP_TX;
}

static __always_inline int handle_ipv6(struct xdp_md *xdp)
{
	struct iptnl_info *tnl;
	__u16 payload_len;
	__u8 proto;

	tnl = find_tnl_ipv6(xdp, &proto, &payload_len);
	return fwd_tnl_ipv6(xdp, tnl, proto, payload_len);
}

static __always_inline int __xdp_tx_iptunnel(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;
	__u16 h_proto;

	if (eth + 1 > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_IP))
		return handle_ipv4(xdp);
	else if (h_proto == htons(ETH_P_IPV6))

		return handle_ipv6(xdp);
	else
		return XDP_PASS;
}

SEC("xdp_tx_iptunnel")
int _xdp_tx_iptunnel(struct xdp_md *xdp)
{
	return __xdp_tx_iptunnel(xdp);
}

#ifdef XDP_MD_BTF
#include "xdp_md_btf.h"

struct bpf_map_def SEC("maps") flow2tnl = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct iptnl_info),
	.max_entries = MAX_IPTNL_ENTRIES,
};

static __always_inline int
fwd_tnl(struct xdp_md *xdp, struct iptnl_info *tnl)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;

	if (tnl->family == AF_INET) {
		struct iphdr *iph = data + sizeof(struct ethhdr);

		if (iph + 1 > data_end)
			return XDP_PASS;

		return fwd_tnl_ipv4(xdp, tnl, iph->protocol, ntohs(iph->tot_len));
	}

	if (tnl->family == AF_INET6) {
		struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

		if (ip6h + 1 > data_end)
			return XDP_PASS;

		return fwd_tnl_ipv6(xdp, tnl, ip6h->nexthdr, ip6h->payload_len);
	}

	return XDP_DROP;
}

SEC("xdp_tx_iptunnel_md_flow_mark")
int _xdp_tx_iptunnel_md_flow_mark(struct xdp_md *xdp)
{
	struct xdp_md_desc *md = (void *)(long)xdp->data_meta;
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;
	__u16 h_proto;

	if (eth + 1 > data_end)
		return XDP_DROP;

	if (md + 1 <= data) {
		struct iptnl_info *tnl = bpf_map_lookup_elem(&flow2tnl, &md->flow_mark);

		/* Remove md to avoid memcpy on bpf_xdp_adjust_head */
		bpf_xdp_adjust_meta(xdp, sizeof(*md));
		if (tnl)
			return fwd_tnl(xdp, tnl);
	}

	/* Fallback to slow path */
	count_tx(0);
	return __xdp_tx_iptunnel(xdp);
}
#endif

char _license[] SEC("license") = "GPL";
