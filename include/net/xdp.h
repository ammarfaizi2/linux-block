/* SPDX-License-Identifier: GPL-2.0-only */
/* include/net/xdp.h
 *
 * Copyright (c) 2017 Jesper Dangaard Brouer, Red Hat Inc.
 */
#ifndef __LINUX_NET_XDP_H__
#define __LINUX_NET_XDP_H__

#include <linux/types.h>
#include <linux/cache.h>

/**
 * DOC: XDP RX-queue information
 *
 * The XDP RX-queue info (xdp_rxq_info) is associated with the driver
 * level RX-ring queues.  It is information that is specific to how
 * the driver have configured a given RX-ring queue.
 *
 * Each xdp_buff frame received in the driver carries a (pointer)
 * reference to this xdp_rxq_info structure.  This provides the XDP
 * data-path read-access to RX-info for both kernel and bpf-side
 * (limited subset).
 *
 * For now, direct access is only safe while running in NAPI/softirq
 * context.  Contents are read-mostly and must not be updated during
 * driver NAPI/softirq poll.
 *
 * The driver usage API is a register and unregister API.
 *
 * The struct is not directly tied to the XDP prog.  A new XDP prog
 * can be attached as long as it doesn't change the underlying
 * RX-ring.  If the RX-ring does change significantly, the NIC driver
 * naturally need to stop the RX-ring before purging and reallocating
 * memory.  In that process the driver MUST call unregister (which
 * also applies for driver shutdown and unload).  The register API is
 * also mandatory during RX-ring setup.
 */

enum xdp_mem_type {
	MEM_TYPE_PAGE_SHARED = 0, /* Split-page refcnt based model */
	MEM_TYPE_PAGE_ORDER0,     /* Orig XDP full page model */
	MEM_TYPE_PAGE_POOL,
	MEM_TYPE_XSK_BUFF_POOL,
	MEM_TYPE_MAX,
};

/* XDP flags for ndo_xdp_xmit */
#define XDP_XMIT_FLUSH		(1U << 0)	/* doorbell signal consumer */
#define XDP_XMIT_FLAGS_MASK	XDP_XMIT_FLUSH

struct xdp_mem_info {
	u32 type; /* enum xdp_mem_type, but known size type */
	u32 id;
};

struct page_pool;

struct ____cacheline_aligned xdp_rxq_info { /* perf critical, avoid false-sharing */
	struct net_device *dev;
	u32 queue_index;
	u32 reg_state;
	struct xdp_mem_info mem;
	unsigned int napi_id;
	u32 frag_size;
};

struct xdp_txq_info {
	struct net_device *dev;
};

enum xdp_buff_flags {
	XDP_FLAGS_HAS_FRAGS		= BIT(0), /* non-linear xdp buff */
	XDP_FLAGS_FRAGS_PF_MEMALLOC	= BIT(1), /* xdp paged memory is under
						   * pressure
						   */
};

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz; /* frame size to deduce data_hard_end/reserved tailroom*/
	u32 flags; /* supported values defined in xdp_buff_flags */
};

struct xdp_frame {
	void *data;
	u16 len;
	u16 headroom;
	u32 metasize:8;
	u32 frame_sz:24;
	/* Lifetime of xdp_rxq_info is limited to NAPI/enqueue time,
	 * while mem info is valid on remote CPU.
	 */
	struct xdp_mem_info mem;
	struct net_device *dev_rx; /* used by cpumap */
	u32 flags; /* supported values defined in xdp_buff_flags */
};

static __always_inline bool xdp_frame_has_frags(struct xdp_frame *frame)
{
	return !!(frame->flags & XDP_FLAGS_HAS_FRAGS);
}

static __always_inline bool xdp_frame_is_frag_pfmemalloc(struct xdp_frame *frame)
{
	return !!(frame->flags & XDP_FLAGS_FRAGS_PF_MEMALLOC);
}

#define XDP_BULK_QUEUE_SIZE	16
struct xdp_frame_bulk {
	int count;
	void *xa;
	void *q[XDP_BULK_QUEUE_SIZE];
};

struct xdp_cpumap_stats {
	unsigned int redirect;
	unsigned int pass;
	unsigned int drop;
};

struct xdp_attachment_info {
	struct bpf_prog *prog;
	u32 flags;
};

#define DEV_MAP_BULK_SIZE XDP_BULK_QUEUE_SIZE

#include <net/xdp_api.h>

#endif /* __LINUX_NET_XDP_H__ */
