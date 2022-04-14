/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *	Definitions for the 'struct sk_buff' memory handlers.
 *
 *	Authors:
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Florian La Roche, <rzsfl@rz.uni-sb.de>
 */

#ifndef _LINUX_SKBUFF_TYPES_H
#define _LINUX_SKBUFF_TYPES_H

#include <linux/bvec.h>
#include <linux/socket.h>

#include <net/checksum.h>
#include <linux/dma-mapping.h>
#include <linux/netdev_features.h>
#include <net/flow_dissector.h>
#include <linux/llist.h>
#include <linux/if_packet.h>
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <linux/netfilter/nf_conntrack_common.h>
#endif

/* The interface for checksum offload between the stack and networking drivers
 * is as follows...
 *
 * A. IP checksum related features
 *
 * Drivers advertise checksum offload capabilities in the features of a device.
 * From the stack's point of view these are capabilities offered by the driver.
 * A driver typically only advertises features that it is capable of offloading
 * to its device.
 *
 * The checksum related features are:
 *
 *	NETIF_F_HW_CSUM	- The driver (or its device) is able to compute one
 *			  IP (one's complement) checksum for any combination
 *			  of protocols or protocol layering. The checksum is
 *			  computed and set in a packet per the CHECKSUM_PARTIAL
 *			  interface (see below).
 *
 *	NETIF_F_IP_CSUM - Driver (device) is only able to checksum plain
 *			  TCP or UDP packets over IPv4. These are specifically
 *			  unencapsulated packets of the form IPv4|TCP or
 *			  IPv4|UDP where the Protocol field in the IPv4 header
 *			  is TCP or UDP. The IPv4 header may contain IP options.
 *			  This feature cannot be set in features for a device
 *			  with NETIF_F_HW_CSUM also set. This feature is being
 *			  DEPRECATED (see below).
 *
 *	NETIF_F_IPV6_CSUM - Driver (device) is only able to checksum plain
 *			  TCP or UDP packets over IPv6. These are specifically
 *			  unencapsulated packets of the form IPv6|TCP or
 *			  IPv6|UDP where the Next Header field in the IPv6
 *			  header is either TCP or UDP. IPv6 extension headers
 *			  are not supported with this feature. This feature
 *			  cannot be set in features for a device with
 *			  NETIF_F_HW_CSUM also set. This feature is being
 *			  DEPRECATED (see below).
 *
 *	NETIF_F_RXCSUM - Driver (device) performs receive checksum offload.
 *			 This flag is only used to disable the RX checksum
 *			 feature for a device. The stack will accept receive
 *			 checksum indication in packets received on a device
 *			 regardless of whether NETIF_F_RXCSUM is set.
 *
 * B. Checksumming of received packets by device. Indication of checksum
 *    verification is set in skb->ip_summed. Possible values are:
 *
 * CHECKSUM_NONE:
 *
 *   Device did not checksum this packet e.g. due to lack of capabilities.
 *   The packet contains full (though not verified) checksum in packet but
 *   not in skb->csum. Thus, skb->csum is undefined in this case.
 *
 * CHECKSUM_UNNECESSARY:
 *
 *   The hardware you're dealing with doesn't calculate the full checksum
 *   (as in CHECKSUM_COMPLETE), but it does parse headers and verify checksums
 *   for specific protocols. For such packets it will set CHECKSUM_UNNECESSARY
 *   if their checksums are okay. skb->csum is still undefined in this case
 *   though. A driver or device must never modify the checksum field in the
 *   packet even if checksum is verified.
 *
 *   CHECKSUM_UNNECESSARY is applicable to following protocols:
 *     TCP: IPv6 and IPv4.
 *     UDP: IPv4 and IPv6. A device may apply CHECKSUM_UNNECESSARY to a
 *       zero UDP checksum for either IPv4 or IPv6, the networking stack
 *       may perform further validation in this case.
 *     GRE: only if the checksum is present in the header.
 *     SCTP: indicates the CRC in SCTP header has been validated.
 *     FCOE: indicates the CRC in FC frame has been validated.
 *
 *   skb->csum_level indicates the number of consecutive checksums found in
 *   the packet minus one that have been verified as CHECKSUM_UNNECESSARY.
 *   For instance if a device receives an IPv6->UDP->GRE->IPv4->TCP packet
 *   and a device is able to verify the checksums for UDP (possibly zero),
 *   GRE (checksum flag is set) and TCP, skb->csum_level would be set to
 *   two. If the device were only able to verify the UDP checksum and not
 *   GRE, either because it doesn't support GRE checksum or because GRE
 *   checksum is bad, skb->csum_level would be set to zero (TCP checksum is
 *   not considered in this case).
 *
 * CHECKSUM_COMPLETE:
 *
 *   This is the most generic way. The device supplied checksum of the _whole_
 *   packet as seen by netif_rx() and fills in skb->csum. This means the
 *   hardware doesn't need to parse L3/L4 headers to implement this.
 *
 *   Notes:
 *   - Even if device supports only some protocols, but is able to produce
 *     skb->csum, it MUST use CHECKSUM_COMPLETE, not CHECKSUM_UNNECESSARY.
 *   - CHECKSUM_COMPLETE is not applicable to SCTP and FCoE protocols.
 *
 * CHECKSUM_PARTIAL:
 *
 *   A checksum is set up to be offloaded to a device as described in the
 *   output description for CHECKSUM_PARTIAL. This may occur on a packet
 *   received directly from another Linux OS, e.g., a virtualized Linux kernel
 *   on the same host, or it may be set in the input path in GRO or remote
 *   checksum offload. For the purposes of checksum verification, the checksum
 *   referred to by skb->csum_start + skb->csum_offset and any preceding
 *   checksums in the packet are considered verified. Any checksums in the
 *   packet that are after the checksum being offloaded are not considered to
 *   be verified.
 *
 * C. Checksumming on transmit for non-GSO. The stack requests checksum offload
 *    in the skb->ip_summed for a packet. Values are:
 *
 * CHECKSUM_PARTIAL:
 *
 *   The driver is required to checksum the packet as seen by hard_start_xmit()
 *   from skb->csum_start up to the end, and to record/write the checksum at
 *   offset skb->csum_start + skb->csum_offset. A driver may verify that the
 *   csum_start and csum_offset values are valid values given the length and
 *   offset of the packet, but it should not attempt to validate that the
 *   checksum refers to a legitimate transport layer checksum -- it is the
 *   purview of the stack to validate that csum_start and csum_offset are set
 *   correctly.
 *
 *   When the stack requests checksum offload for a packet, the driver MUST
 *   ensure that the checksum is set correctly. A driver can either offload the
 *   checksum calculation to the device, or call skb_checksum_help (in the case
 *   that the device does not support offload for a particular checksum).
 *
 *   NETIF_F_IP_CSUM and NETIF_F_IPV6_CSUM are being deprecated in favor of
 *   NETIF_F_HW_CSUM. New devices should use NETIF_F_HW_CSUM to indicate
 *   checksum offload capability.
 *   skb_csum_hwoffload_help() can be called to resolve CHECKSUM_PARTIAL based
 *   on network device checksumming capabilities: if a packet does not match
 *   them, skb_checksum_help or skb_crc32c_help (depending on the value of
 *   csum_not_inet, see item D.) is called to resolve the checksum.
 *
 * CHECKSUM_NONE:
 *
 *   The skb was already checksummed by the protocol, or a checksum is not
 *   required.
 *
 * CHECKSUM_UNNECESSARY:
 *
 *   This has the same meaning as CHECKSUM_NONE for checksum offload on
 *   output.
 *
 * CHECKSUM_COMPLETE:
 *   Not used in checksum output. If a driver observes a packet with this value
 *   set in skbuff, it should treat the packet as if CHECKSUM_NONE were set.
 *
 * D. Non-IP checksum (CRC) offloads
 *
 *   NETIF_F_SCTP_CRC - This feature indicates that a device is capable of
 *     offloading the SCTP CRC in a packet. To perform this offload the stack
 *     will set csum_start and csum_offset accordingly, set ip_summed to
 *     CHECKSUM_PARTIAL and set csum_not_inet to 1, to provide an indication in
 *     the skbuff that the CHECKSUM_PARTIAL refers to CRC32c.
 *     A driver that supports both IP checksum offload and SCTP CRC32c offload
 *     must verify which offload is configured for a packet by testing the
 *     value of skb->csum_not_inet; skb_crc32c_csum_help is provided to resolve
 *     CHECKSUM_PARTIAL on skbs where csum_not_inet is set to 1.
 *
 *   NETIF_F_FCOE_CRC - This feature indicates that a device is capable of
 *     offloading the FCOE CRC in a packet. To perform this offload the stack
 *     will set ip_summed to CHECKSUM_PARTIAL and set csum_start and csum_offset
 *     accordingly. Note that there is no indication in the skbuff that the
 *     CHECKSUM_PARTIAL refers to an FCOE checksum, so a driver that supports
 *     both IP checksum offload and FCOE CRC offload must verify which offload
 *     is configured for a packet, presumably by inspecting packet headers.
 *
 * E. Checksumming on output with GSO.
 *
 * In the case of a GSO packet (skb_is_gso(skb) is true), checksum offload
 * is implied by the SKB_GSO_* flags in gso_type. Most obviously, if the
 * gso_type is SKB_GSO_TCPV4 or SKB_GSO_TCPV6, TCP checksum offload as
 * part of the GSO operation is implied. If a checksum is being offloaded
 * with GSO then ip_summed is CHECKSUM_PARTIAL, and both csum_start and
 * csum_offset are set to refer to the outermost checksum being offloaded
 * (two offloaded checksums are possible with UDP encapsulation).
 */

/* Don't change this without changing skb_csum_unnecessary! */
#define CHECKSUM_NONE		0
#define CHECKSUM_UNNECESSARY	1
#define CHECKSUM_COMPLETE	2
#define CHECKSUM_PARTIAL	3

/* Maximum value in skb->csum_level */
#define SKB_MAX_CSUM_LEVEL	3

#define SKB_DATA_ALIGN(X)	ALIGN(X, SMP_CACHE_BYTES)
#define SKB_WITH_OVERHEAD(X)	\
	((X) - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#define SKB_MAX_ORDER(X, ORDER) \
	SKB_WITH_OVERHEAD((PAGE_SIZE << (ORDER)) - (X))
#define SKB_MAX_HEAD(X)		(SKB_MAX_ORDER((X), 0))
#define SKB_MAX_ALLOC		(SKB_MAX_ORDER(0, 2))

/* return minimum truesize of one skb containing X bytes of data */
#define SKB_TRUESIZE(X) ((X) +						\
			 SKB_DATA_ALIGN(sizeof(struct sk_buff)) +	\
			 SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

struct ahash_request;
struct net_device;
struct scatterlist;
struct pipe_inode_info;
struct iov_iter;
struct napi_struct;
struct bpf_prog;
union bpf_attr;
struct skb_ext;
struct page_frag;

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
struct nf_bridge_info {
	enum {
		BRNF_PROTO_UNCHANGED,
		BRNF_PROTO_8021Q,
		BRNF_PROTO_PPPOE
	} orig_proto:8;
	u8			pkt_otherhost:1;
	u8			in_prerouting:1;
	u8			bridged_dnat:1;
	__u16			frag_max_size;
	struct net_device	*physindev;

	/* always valid & non-NULL from FORWARD on, for physdev match */
	struct net_device	*physoutdev;
	union {
		/* prerouting: detect dnat in orig/reply direction */
		__be32          ipv4_daddr;
		struct in6_addr ipv6_daddr;

		/* after prerouting + nat detected: store original source
		 * mac since neigh resolution overwrites it, only used while
		 * skb is out in neigh layer.
		 */
		char neigh_header[8];
	};
};
#endif

#if IS_ENABLED(CONFIG_NET_TC_SKB_EXT)
/* Chain in tc_skb_ext will be used to share the tc chain with
 * ovs recirc_id. It will be set to the current chain by tc
 * and read by ovs to recirc_id.
 */
struct tc_skb_ext {
	__u32 chain;
	__u16 mru;
	__u16 zone;
	u8 post_ct:1;
	u8 post_ct_snat:1;
	u8 post_ct_dnat:1;
};
#endif

struct sk_buff_head {
	/* These two members must be first to match sk_buff. */
	struct_group_tagged(sk_buff_list, list,
		struct sk_buff	*next;
		struct sk_buff	*prev;
	);

	__u32		qlen;
	spinlock_t	lock;
};

struct sk_buff;

/* The reason of skb drop, which is used in kfree_skb_reason().
 * en...maybe they should be splited by group?
 *
 * Each item here should also be in 'TRACE_SKB_DROP_REASON', which is
 * used to translate the reason to string.
 */
enum skb_drop_reason {
	SKB_NOT_DROPPED_YET = 0,
	SKB_DROP_REASON_NOT_SPECIFIED,	/* drop reason is not specified */
	SKB_DROP_REASON_NO_SOCKET,	/* socket not found */
	SKB_DROP_REASON_PKT_TOO_SMALL,	/* packet size is too small */
	SKB_DROP_REASON_TCP_CSUM,	/* TCP checksum error */
	SKB_DROP_REASON_SOCKET_FILTER,	/* dropped by socket filter */
	SKB_DROP_REASON_UDP_CSUM,	/* UDP checksum error */
	SKB_DROP_REASON_NETFILTER_DROP,	/* dropped by netfilter */
	SKB_DROP_REASON_OTHERHOST,	/* packet don't belong to current
					 * host (interface is in promisc
					 * mode)
					 */
	SKB_DROP_REASON_IP_CSUM,	/* IP checksum error */
	SKB_DROP_REASON_IP_INHDR,	/* there is something wrong with
					 * IP header (see
					 * IPSTATS_MIB_INHDRERRORS)
					 */
	SKB_DROP_REASON_IP_RPFILTER,	/* IP rpfilter validate failed.
					 * see the document for rp_filter
					 * in ip-sysctl.rst for more
					 * information
					 */
	SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST, /* destination address of L2
						  * is multicast, but L3 is
						  * unicast.
						  */
	SKB_DROP_REASON_XFRM_POLICY,	/* xfrm policy check failed */
	SKB_DROP_REASON_IP_NOPROTO,	/* no support for IP protocol */
	SKB_DROP_REASON_SOCKET_RCVBUFF,	/* socket receive buff is full */
	SKB_DROP_REASON_PROTO_MEM,	/* proto memory limition, such as
					 * udp packet drop out of
					 * udp_memory_allocated.
					 */
	SKB_DROP_REASON_TCP_MD5NOTFOUND,	/* no MD5 hash and one
						 * expected, corresponding
						 * to LINUX_MIB_TCPMD5NOTFOUND
						 */
	SKB_DROP_REASON_TCP_MD5UNEXPECTED,	/* MD5 hash and we're not
						 * expecting one, corresponding
						 * to LINUX_MIB_TCPMD5UNEXPECTED
						 */
	SKB_DROP_REASON_TCP_MD5FAILURE,	/* MD5 hash and its wrong,
					 * corresponding to
					 * LINUX_MIB_TCPMD5FAILURE
					 */
	SKB_DROP_REASON_SOCKET_BACKLOG,	/* failed to add skb to socket
					 * backlog (see
					 * LINUX_MIB_TCPBACKLOGDROP)
					 */
	SKB_DROP_REASON_TCP_FLAGS,	/* TCP flags invalid */
	SKB_DROP_REASON_TCP_ZEROWINDOW,	/* TCP receive window size is zero,
					 * see LINUX_MIB_TCPZEROWINDOWDROP
					 */
	SKB_DROP_REASON_TCP_OLD_DATA,	/* the TCP data reveived is already
					 * received before (spurious retrans
					 * may happened), see
					 * LINUX_MIB_DELAYEDACKLOST
					 */
	SKB_DROP_REASON_TCP_OVERWINDOW,	/* the TCP data is out of window,
					 * the seq of the first byte exceed
					 * the right edges of receive
					 * window
					 */
	SKB_DROP_REASON_TCP_OFOMERGE,	/* the data of skb is already in
					 * the ofo queue, corresponding to
					 * LINUX_MIB_TCPOFOMERGE
					 */
	SKB_DROP_REASON_IP_OUTNOROUTES,	/* route lookup failed */
	SKB_DROP_REASON_BPF_CGROUP_EGRESS,	/* dropped by
						 * BPF_PROG_TYPE_CGROUP_SKB
						 * eBPF program
						 */
	SKB_DROP_REASON_IPV6DISABLED,	/* IPv6 is disabled on the device */
	SKB_DROP_REASON_NEIGH_CREATEFAIL,	/* failed to create neigh
						 * entry
						 */
	SKB_DROP_REASON_NEIGH_FAILED,	/* neigh entry in failed state */
	SKB_DROP_REASON_NEIGH_QUEUEFULL,	/* arp_queue for neigh
						 * entry is full
						 */
	SKB_DROP_REASON_NEIGH_DEAD,	/* neigh entry is dead */
	SKB_DROP_REASON_TC_EGRESS,	/* dropped in TC egress HOOK */
	SKB_DROP_REASON_QDISC_DROP,	/* dropped by qdisc when packet
					 * outputting (failed to enqueue to
					 * current qdisc)
					 */
	SKB_DROP_REASON_CPU_BACKLOG,	/* failed to enqueue the skb to
					 * the per CPU backlog queue. This
					 * can be caused by backlog queue
					 * full (see netdev_max_backlog in
					 * net.rst) or RPS flow limit
					 */
	SKB_DROP_REASON_XDP,		/* dropped by XDP in input path */
	SKB_DROP_REASON_TC_INGRESS,	/* dropped in TC ingress HOOK */
	SKB_DROP_REASON_PTYPE_ABSENT,	/* not packet_type found to handle
					 * the skb. For an etner packet,
					 * this means that L3 protocol is
					 * not supported
					 */
	SKB_DROP_REASON_SKB_CSUM,	/* sk_buff checksum computation
					 * error
					 */
	SKB_DROP_REASON_SKB_GSO_SEG,	/* gso segmentation error */
	SKB_DROP_REASON_SKB_UCOPY_FAULT,	/* failed to copy data from
						 * user space, e.g., via
						 * zerocopy_sg_from_iter()
						 * or skb_orphan_frags_rx()
						 */
	SKB_DROP_REASON_DEV_HDR,	/* device driver specific
					 * header/metadata is invalid
					 */
	/* the device is not ready to xmit/recv due to any of its data
	 * structure that is not up/ready/initialized, e.g., the IFF_UP is
	 * not set, or driver specific tun->tfiles[txq] is not initialized
	 */
	SKB_DROP_REASON_DEV_READY,
	SKB_DROP_REASON_FULL_RING,	/* ring buffer is full */
	SKB_DROP_REASON_NOMEM,		/* error due to OOM */
	SKB_DROP_REASON_HDR_TRUNC,      /* failed to trunc/extract the header
					 * from networking data, e.g., failed
					 * to pull the protocol header from
					 * frags via pskb_may_pull()
					 */
	SKB_DROP_REASON_TAP_FILTER,     /* dropped by (ebpf) filter directly
					 * attached to tun/tap, e.g., via
					 * TUNSETFILTEREBPF
					 */
	SKB_DROP_REASON_TAP_TXFILTER,	/* dropped by tx filter implemented
					 * at tun/tap, e.g., check_filter()
					 */
	SKB_DROP_REASON_MAX,
};

/* To allow 64K frame to be packed as single skb without frag_list we
 * require 64K/PAGE_SIZE pages plus 1 additional page to allow for
 * buffers which do not start on a page boundary.
 *
 * Since GRO uses frags we allocate at least 16 regardless of page
 * size.
 */
#if (65536/PAGE_SIZE + 1) < 16
#define MAX_SKB_FRAGS 16UL
#else
#define MAX_SKB_FRAGS (65536/PAGE_SIZE + 1)
#endif
extern int sysctl_max_skb_frags;

/* Set skb_shinfo(skb)->gso_size to this in case you want skb_segment to
 * segment using its current segmentation instead.
 */
#define GSO_BY_FRAGS	0xFFFF

typedef struct bio_vec skb_frag_t;

#define HAVE_HW_TIME_STAMP

/**
 * struct skb_shared_hwtstamps - hardware time stamps
 * @hwtstamp:	hardware time stamp transformed into duration
 *		since arbitrary point in time
 *
 * Software time stamps generated by ktime_get_real() are stored in
 * skb->tstamp.
 *
 * hwtstamps can only be compared against other hwtstamps from
 * the same device.
 *
 * This structure is attached to packets as part of the
 * &skb_shared_info. Use skb_hwtstamps() to get a pointer.
 */
struct skb_shared_hwtstamps {
	ktime_t	hwtstamp;
};

/* Definitions for tx_flags in struct skb_shared_info */
enum {
	/* generate hardware time stamp */
	SKBTX_HW_TSTAMP = 1 << 0,

	/* generate software time stamp when queueing packet to NIC */
	SKBTX_SW_TSTAMP = 1 << 1,

	/* device driver is going to provide hardware time stamp */
	SKBTX_IN_PROGRESS = 1 << 2,

	/* generate wifi status information (where possible) */
	SKBTX_WIFI_STATUS = 1 << 4,

	/* generate software time stamp when entering packet scheduling */
	SKBTX_SCHED_TSTAMP = 1 << 6,
};

#define SKBTX_ANY_SW_TSTAMP	(SKBTX_SW_TSTAMP    | \
				 SKBTX_SCHED_TSTAMP)
#define SKBTX_ANY_TSTAMP	(SKBTX_HW_TSTAMP | SKBTX_ANY_SW_TSTAMP)

/* Definitions for flags in struct skb_shared_info */
enum {
	/* use zcopy routines */
	SKBFL_ZEROCOPY_ENABLE = BIT(0),

	/* This indicates at least one fragment might be overwritten
	 * (as in vmsplice(), sendfile() ...)
	 * If we need to compute a TX checksum, we'll need to copy
	 * all frags to avoid possible bad checksum
	 */
	SKBFL_SHARED_FRAG = BIT(1),

	/* segment contains only zerocopy data and should not be
	 * charged to the kernel memory.
	 */
	SKBFL_PURE_ZEROCOPY = BIT(2),
};

#define SKBFL_ZEROCOPY_FRAG	(SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG)
#define SKBFL_ALL_ZEROCOPY	(SKBFL_ZEROCOPY_FRAG | SKBFL_PURE_ZEROCOPY)

/*
 * The callback notifies userspace to release buffers when skb DMA is done in
 * lower device, the skb last reference should be 0 when calling this.
 * The zerocopy_success argument is true if zero copy transmit occurred,
 * false on data copy or out of memory error caused by data copy attempt.
 * The ctx field is used to track device context.
 * The desc field is used to track userspace buffer index.
 */
struct ubuf_info {
	void (*callback)(struct sk_buff *, struct ubuf_info *,
			 bool zerocopy_success);
	union {
		struct {
			unsigned long desc;
			void *ctx;
		};
		struct {
			u32 id;
			u16 len;
			u16 zerocopy:1;
			u32 bytelen;
		};
	};
	refcount_t refcnt;
	u8 flags;

	struct mmpin {
		struct user_struct *user;
		unsigned int num_pg;
	} mmp;
};

/* This data is invariant across clones and lives at
 * the end of the header data, ie. at skb->end.
 */
struct skb_shared_info {
	__u8		flags;
	__u8		meta_len;
	__u8		nr_frags;
	__u8		tx_flags;
	unsigned short	gso_size;
	/* Warning: this field is not always filled in (UFO)! */
	unsigned short	gso_segs;
	struct sk_buff	*frag_list;
	struct skb_shared_hwtstamps hwtstamps;
	unsigned int	gso_type;
	u32		tskey;

	/*
	 * Warning : all fields before dataref are cleared in __alloc_skb()
	 */
	atomic_t	dataref;
	unsigned int	xdp_frags_size;

	/* Intermediate layers must ensure that destructor_arg
	 * remains valid until skb destructor */
	void *		destructor_arg;

	/* must be last field, see pskb_expand_head() */
	skb_frag_t	frags[MAX_SKB_FRAGS];
};

/* We divide dataref into two halves.  The higher 16 bits hold references
 * to the payload part of skb->data.  The lower 16 bits hold references to
 * the entire skb->data.  A clone of a headerless skb holds the length of
 * the header in skb->hdr_len.
 *
 * All users must obey the rule that the skb->data reference count must be
 * greater than or equal to the payload reference count.
 *
 * Holding a reference to the payload part means that the user does not
 * care about modifications to the header part of skb->data.
 */
#define SKB_DATAREF_SHIFT 16
#define SKB_DATAREF_MASK ((1 << SKB_DATAREF_SHIFT) - 1)


enum {
	SKB_FCLONE_UNAVAILABLE,	/* skb has no fclone (from head_cache) */
	SKB_FCLONE_ORIG,	/* orig skb (from fclone_cache) */
	SKB_FCLONE_CLONE,	/* companion fclone skb (from fclone_cache) */
};

enum {
	SKB_GSO_TCPV4 = 1 << 0,

	/* This indicates the skb is from an untrusted source. */
	SKB_GSO_DODGY = 1 << 1,

	/* This indicates the tcp segment has CWR set. */
	SKB_GSO_TCP_ECN = 1 << 2,

	SKB_GSO_TCP_FIXEDID = 1 << 3,

	SKB_GSO_TCPV6 = 1 << 4,

	SKB_GSO_FCOE = 1 << 5,

	SKB_GSO_GRE = 1 << 6,

	SKB_GSO_GRE_CSUM = 1 << 7,

	SKB_GSO_IPXIP4 = 1 << 8,

	SKB_GSO_IPXIP6 = 1 << 9,

	SKB_GSO_UDP_TUNNEL = 1 << 10,

	SKB_GSO_UDP_TUNNEL_CSUM = 1 << 11,

	SKB_GSO_PARTIAL = 1 << 12,

	SKB_GSO_TUNNEL_REMCSUM = 1 << 13,

	SKB_GSO_SCTP = 1 << 14,

	SKB_GSO_ESP = 1 << 15,

	SKB_GSO_UDP = 1 << 16,

	SKB_GSO_UDP_L4 = 1 << 17,

	SKB_GSO_FRAGLIST = 1 << 18,
};

#if BITS_PER_LONG > 32
#define NET_SKBUFF_DATA_USES_OFFSET 1
#endif

#ifdef NET_SKBUFF_DATA_USES_OFFSET
typedef unsigned int sk_buff_data_t;
#else
typedef unsigned char *sk_buff_data_t;
#endif

/**
 *	struct sk_buff - socket buffer
 *	@next: Next buffer in list
 *	@prev: Previous buffer in list
 *	@tstamp: Time we arrived/left
 *	@skb_mstamp_ns: (aka @tstamp) earliest departure time; start point
 *		for retransmit timer
 *	@rbnode: RB tree node, alternative to next/prev for netem/tcp
 *	@list: queue head
 *	@ll_node: anchor in an llist (eg socket defer_list)
 *	@sk: Socket we are owned by
 *	@ip_defrag_offset: (aka @sk) alternate use of @sk, used in
 *		fragmentation management
 *	@dev: Device we arrived on/are leaving by
 *	@dev_scratch: (aka @dev) alternate use of @dev when @dev would be %NULL
 *	@cb: Control buffer. Free for use by every layer. Put private vars here
 *	@_skb_refdst: destination entry (with norefcount bit)
 *	@sp: the security path, used for xfrm
 *	@len: Length of actual data
 *	@data_len: Data length
 *	@mac_len: Length of link layer header
 *	@hdr_len: writable header length of cloned skb
 *	@csum: Checksum (must include start/offset pair)
 *	@csum_start: Offset from skb->head where checksumming should start
 *	@csum_offset: Offset from csum_start where checksum should be stored
 *	@priority: Packet queueing priority
 *	@ignore_df: allow local fragmentation
 *	@cloned: Head may be cloned (check refcnt to be sure)
 *	@ip_summed: Driver fed us an IP checksum
 *	@nohdr: Payload reference only, must not modify header
 *	@pkt_type: Packet class
 *	@fclone: skbuff clone status
 *	@ipvs_property: skbuff is owned by ipvs
 *	@inner_protocol_type: whether the inner protocol is
 *		ENCAP_TYPE_ETHER or ENCAP_TYPE_IPPROTO
 *	@remcsum_offload: remote checksum offload is enabled
 *	@offload_fwd_mark: Packet was L2-forwarded in hardware
 *	@offload_l3_fwd_mark: Packet was L3-forwarded in hardware
 *	@tc_skip_classify: do not classify packet. set by IFB device
 *	@tc_at_ingress: used within tc_classify to distinguish in/egress
 *	@redirected: packet was redirected by packet classifier
 *	@from_ingress: packet was redirected from the ingress path
 *	@nf_skip_egress: packet shall skip nf egress - see netfilter_netdev.h
 *	@peeked: this packet has been seen already, so stats have been
 *		done for it, don't do them again
 *	@nf_trace: netfilter packet trace flag
 *	@protocol: Packet protocol from driver
 *	@destructor: Destruct function
 *	@tcp_tsorted_anchor: list structure for TCP (tp->tsorted_sent_queue)
 *	@_sk_redir: socket redirection information for skmsg
 *	@_nfct: Associated connection, if any (with nfctinfo bits)
 *	@nf_bridge: Saved data about a bridged frame - see br_netfilter.c
 *	@skb_iif: ifindex of device we arrived on
 *	@tc_index: Traffic control index
 *	@hash: the packet hash
 *	@queue_mapping: Queue mapping for multiqueue devices
 *	@head_frag: skb was allocated from page fragments,
 *		not allocated by kmalloc() or vmalloc().
 *	@pfmemalloc: skbuff was allocated from PFMEMALLOC reserves
 *	@pp_recycle: mark the packet for recycling instead of freeing (implies
 *		page_pool support on driver)
 *	@active_extensions: active extensions (skb_ext_id types)
 *	@ndisc_nodetype: router type (from link layer)
 *	@ooo_okay: allow the mapping of a socket to a queue to be changed
 *	@l4_hash: indicate hash is a canonical 4-tuple hash over transport
 *		ports.
 *	@sw_hash: indicates hash was computed in software stack
 *	@wifi_acked_valid: wifi_acked was set
 *	@wifi_acked: whether frame was acked on wifi or not
 *	@no_fcs:  Request NIC to treat last 4 bytes as Ethernet FCS
 *	@encapsulation: indicates the inner headers in the skbuff are valid
 *	@encap_hdr_csum: software checksum is needed
 *	@csum_valid: checksum is already valid
 *	@csum_not_inet: use CRC32c to resolve CHECKSUM_PARTIAL
 *	@csum_complete_sw: checksum was completed by software
 *	@csum_level: indicates the number of consecutive checksums found in
 *		the packet minus one that have been verified as
 *		CHECKSUM_UNNECESSARY (max 3)
 *	@dst_pending_confirm: need to confirm neighbour
 *	@decrypted: Decrypted SKB
 *	@slow_gro: state present at GRO time, slower prepare step required
 *	@mono_delivery_time: When set, skb->tstamp has the
 *		delivery_time in mono clock base (i.e. EDT).  Otherwise, the
 *		skb->tstamp has the (rcv) timestamp at ingress and
 *		delivery_time at egress.
 *	@napi_id: id of the NAPI struct this skb came from
 *	@sender_cpu: (aka @napi_id) source CPU in XPS
 *	@secmark: security marking
 *	@mark: Generic packet mark
 *	@reserved_tailroom: (aka @mark) number of bytes of free space available
 *		at the tail of an sk_buff
 *	@vlan_present: VLAN tag is present
 *	@vlan_proto: vlan encapsulation protocol
 *	@vlan_tci: vlan tag control information
 *	@inner_protocol: Protocol (encapsulation)
 *	@inner_ipproto: (aka @inner_protocol) stores ipproto when
 *		skb->inner_protocol_type == ENCAP_TYPE_IPPROTO;
 *	@inner_transport_header: Inner transport layer header (encapsulation)
 *	@inner_network_header: Network layer header (encapsulation)
 *	@inner_mac_header: Link layer header (encapsulation)
 *	@transport_header: Transport layer header
 *	@network_header: Network layer header
 *	@mac_header: Link layer header
 *	@kcov_handle: KCOV remote handle for remote coverage collection
 *	@tail: Tail pointer
 *	@end: End pointer
 *	@head: Head of buffer
 *	@data: Data head pointer
 *	@truesize: Buffer size
 *	@users: User count - see {datagram,tcp}.c
 *	@extensions: allocated extensions, valid if active_extensions is nonzero
 */

struct sk_buff {
	union {
		struct {
			/* These two members must be first to match sk_buff_head. */
			struct sk_buff		*next;
			struct sk_buff		*prev;

			union {
				struct net_device	*dev;
				/* Some protocols might use this space to store information,
				 * while device pointer would be NULL.
				 * UDP receive path is one user.
				 */
				unsigned long		dev_scratch;
			};
		};
		struct rb_node		rbnode; /* used in netem, ip4 defrag, and tcp stack */
		struct list_head	list;
		struct llist_node	ll_node;
	};

	union {
		struct sock		*sk;
		int			ip_defrag_offset;
	};

	union {
		ktime_t		tstamp;
		u64		skb_mstamp_ns; /* earliest departure time */
	};
	/*
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a skb_clone()
	 * first. This is owned by whoever has the skb queued ATM.
	 */
	char			cb[48] __aligned(8);

	union {
		struct {
			unsigned long	_skb_refdst;
			void		(*destructor)(struct sk_buff *skb);
		};
		struct list_head	tcp_tsorted_anchor;
#ifdef CONFIG_NET_SOCK_MSG
		unsigned long		_sk_redir;
#endif
	};

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	unsigned long		 _nfct;
#endif
	unsigned int		len,
				data_len;
	__u16			mac_len,
				hdr_len;

	/* Following fields are _not_ copied in __copy_skb_header()
	 * Note that queue_mapping is here mostly to fill a hole.
	 */
	__u16			queue_mapping;

/* if you move cloned around you also must adapt those constants */
#ifdef __BIG_ENDIAN_BITFIELD
#define CLONED_MASK	(1 << 7)
#else
#define CLONED_MASK	1
#endif
#define CLONED_OFFSET		offsetof(struct sk_buff, __cloned_offset)

	/* private: */
	__u8			__cloned_offset[0];
	/* public: */
	__u8			cloned:1,
				nohdr:1,
				fclone:2,
				peeked:1,
				head_frag:1,
				pfmemalloc:1,
				pp_recycle:1; /* page_pool recycle indicator */
#ifdef CONFIG_SKB_EXTENSIONS
	__u8			active_extensions;
#endif

	/* Fields enclosed in headers group are copied
	 * using a single memcpy() in __copy_skb_header()
	 */
	struct_group(headers,

	/* private: */
	__u8			__pkt_type_offset[0];
	/* public: */
	__u8			pkt_type:3; /* see PKT_TYPE_MAX */
	__u8			ignore_df:1;
	__u8			nf_trace:1;
	__u8			ip_summed:2;
	__u8			ooo_okay:1;

	__u8			l4_hash:1;
	__u8			sw_hash:1;
	__u8			wifi_acked_valid:1;
	__u8			wifi_acked:1;
	__u8			no_fcs:1;
	/* Indicates the inner headers are valid in the skbuff. */
	__u8			encapsulation:1;
	__u8			encap_hdr_csum:1;
	__u8			csum_valid:1;

	/* private: */
	__u8			__pkt_vlan_present_offset[0];
	/* public: */
	__u8			vlan_present:1;	/* See PKT_VLAN_PRESENT_BIT */
	__u8			csum_complete_sw:1;
	__u8			csum_level:2;
	__u8			dst_pending_confirm:1;
	__u8			mono_delivery_time:1;	/* See SKB_MONO_DELIVERY_TIME_MASK */
#ifdef CONFIG_NET_CLS_ACT
	__u8			tc_skip_classify:1;
	__u8			tc_at_ingress:1;	/* See TC_AT_INGRESS_MASK */
#endif
#ifdef CONFIG_IPV6_NDISC_NODETYPE
	__u8			ndisc_nodetype:2;
#endif

	__u8			ipvs_property:1;
	__u8			inner_protocol_type:1;
	__u8			remcsum_offload:1;
#ifdef CONFIG_NET_SWITCHDEV
	__u8			offload_fwd_mark:1;
	__u8			offload_l3_fwd_mark:1;
#endif
	__u8			redirected:1;
#ifdef CONFIG_NET_REDIRECT
	__u8			from_ingress:1;
#endif
#ifdef CONFIG_NETFILTER_SKIP_EGRESS
	__u8			nf_skip_egress:1;
#endif
#ifdef CONFIG_TLS_DEVICE
	__u8			decrypted:1;
#endif
	__u8			slow_gro:1;
	__u8			csum_not_inet:1;

#ifdef CONFIG_NET_SCHED
	__u16			tc_index;	/* traffic control index */
#endif

	union {
		__wsum		csum;
		struct {
			__u16	csum_start;
			__u16	csum_offset;
		};
	};
	__u32			priority;
	int			skb_iif;
	__u32			hash;
	__be16			vlan_proto;
	__u16			vlan_tci;
#if defined(CONFIG_NET_RX_BUSY_POLL) || defined(CONFIG_XPS)
	union {
		unsigned int	napi_id;
		unsigned int	sender_cpu;
	};
#endif
#ifdef CONFIG_NETWORK_SECMARK
	__u32		secmark;
#endif

	union {
		__u32		mark;
		__u32		reserved_tailroom;
	};

	union {
		__be16		inner_protocol;
		__u8		inner_ipproto;
	};

	__u16			inner_transport_header;
	__u16			inner_network_header;
	__u16			inner_mac_header;

	__be16			protocol;
	__u16			transport_header;
	__u16			network_header;
	__u16			mac_header;

#ifdef CONFIG_KCOV
	u64			kcov_handle;
#endif

	); /* end headers group */

	/* These elements must be at the end, see alloc_skb() for details.  */
	sk_buff_data_t		tail;
	sk_buff_data_t		end;
	unsigned char		*head,
				*data;
	unsigned int		truesize;
	refcount_t		users;

#ifdef CONFIG_SKB_EXTENSIONS
	/* only useable after checking ->active_extensions != 0 */
	struct skb_ext		*extensions;
#endif
};

/* if you move pkt_type around you also must adapt those constants */
#ifdef __BIG_ENDIAN_BITFIELD
#define PKT_TYPE_MAX	(7 << 5)
#else
#define PKT_TYPE_MAX	7
#endif
#define PKT_TYPE_OFFSET		offsetof(struct sk_buff, __pkt_type_offset)

/* if you move pkt_vlan_present, tc_at_ingress, or mono_delivery_time
 * around, you also must adapt these constants.
 */
#ifdef __BIG_ENDIAN_BITFIELD
#define PKT_VLAN_PRESENT_BIT	7
#define TC_AT_INGRESS_MASK		(1 << 0)
#define SKB_MONO_DELIVERY_TIME_MASK	(1 << 2)
#else
#define PKT_VLAN_PRESENT_BIT	0
#define TC_AT_INGRESS_MASK		(1 << 7)
#define SKB_MONO_DELIVERY_TIME_MASK	(1 << 5)
#endif
#define PKT_VLAN_PRESENT_OFFSET	offsetof(struct sk_buff, __pkt_vlan_present_offset)

#ifdef __KERNEL__

/* Layout of fast clones : [skb1][skb2][fclone_ref] */
struct sk_buff_fclones {
	struct sk_buff	skb1;

	struct sk_buff	skb2;

	refcount_t	fclone_ref;
};

struct skb_seq_state {
	__u32		lower_offset;
	__u32		upper_offset;
	__u32		frag_idx;
	__u32		stepped_offset;
	struct sk_buff	*root_skb;
	struct sk_buff	*cur_skb;
	__u8		*frag_data;
	__u32		frag_off;
};

/*
 * Packet hash types specify the type of hash in skb_set_hash.
 *
 * Hash types refer to the protocol layer addresses which are used to
 * construct a packet's hash. The hashes are used to differentiate or identify
 * flows of the protocol layer for the hash type. Hash types are either
 * layer-2 (L2), layer-3 (L3), or layer-4 (L4).
 *
 * Properties of hashes:
 *
 * 1) Two packets in different flows have different hash values
 * 2) Two packets in the same flow should have the same hash value
 *
 * A hash at a higher layer is considered to be more specific. A driver should
 * set the most specific hash possible.
 *
 * A driver cannot indicate a more specific hash than the layer at which a hash
 * was computed. For instance an L3 hash cannot be set as an L4 hash.
 *
 * A driver may indicate a hash level which is less specific than the
 * actual layer the hash was computed on. For instance, a hash computed
 * at L4 may be considered an L3 hash. This should only be done if the
 * driver can't unambiguously determine that the HW computed the hash at
 * the higher layer. Note that the "should" in the second property above
 * permits this.
 */
enum pkt_hash_types {
	PKT_HASH_TYPE_NONE,	/* Undefined type */
	PKT_HASH_TYPE_L2,	/* Input: src_MAC, dest_MAC */
	PKT_HASH_TYPE_L3,	/* Input: src_IP, dst_IP */
	PKT_HASH_TYPE_L4,	/* Input: src_IP, dst_IP, src_port, dst_port */
};

#ifdef CONFIG_SKB_EXTENSIONS
enum skb_ext_id {
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	SKB_EXT_BRIDGE_NF,
#endif
#ifdef CONFIG_XFRM
	SKB_EXT_SEC_PATH,
#endif
#if IS_ENABLED(CONFIG_NET_TC_SKB_EXT)
	TC_SKB_EXT,
#endif
#if IS_ENABLED(CONFIG_MPTCP)
	SKB_EXT_MPTCP,
#endif
#if IS_ENABLED(CONFIG_MCTP_FLOWS)
	SKB_EXT_MCTP,
#endif
	SKB_EXT_NUM, /* must be last */
};

/**
 *	struct skb_ext - sk_buff extensions
 *	@refcnt: 1 on allocation, deallocated on 0
 *	@offset: offset to add to @data to obtain extension address
 *	@chunks: size currently allocated, stored in SKB_EXT_ALIGN_SHIFT units
 *	@data: start of extension data, variable sized
 *
 *	Note: offsets/lengths are stored in chunks of 8 bytes, this allows
 *	to use 'u8' types while allowing up to 2kb worth of extension data.
 */
struct skb_ext {
	refcount_t refcnt;
	u8 offset[SKB_EXT_NUM]; /* in chunks of 8 bytes */
	u8 chunks;		/* same */
	char data[] __aligned(8);
};
#endif /* CONFIG_SKB_EXTENSIONS */


#endif	/* __KERNEL__ */
#endif	/* _LINUX_SKBUFF_TYPES_H */
