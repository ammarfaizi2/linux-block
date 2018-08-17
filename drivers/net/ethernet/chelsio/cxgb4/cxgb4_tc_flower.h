/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (c) 2017 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __CXGB4_TC_FLOWER_H
#define __CXGB4_TC_FLOWER_H

#include <net/pkt_cls.h>

struct ch_tc_flower_stats {
	u64 prev_packet_count;
	u64 packet_count;
	u64 byte_count;
	u64 last_used;
};

struct ch_tc_flower_entry {
	struct ch_filter_specification fs;
	struct ch_tc_flower_stats stats;
	unsigned long tc_flower_cookie;
	struct rhash_head node;
	struct rcu_head rcu;
	spinlock_t lock; /* lock for stats */
	u32 filter_id;
};

#define PEDIT_ETH_DMAC_MASK		htonl(0xffff0000)
#define PEDIT_TCP_UDP_SPORT_MASK	htonl(0xffff0000)
#define PEDIT_ETH_DMAC_31_0		0x0
#define PEDIT_ETH_DMAC_47_32_SMAC_15_0	0x4
#define PEDIT_ETH_SMAC_47_16		0x8
#define PEDIT_IP4_SRC			0xC
#define PEDIT_IP4_DST			0x10
#define PEDIT_IP6_SRC_31_0		0x8
#define PEDIT_IP6_SRC_63_32		0xC
#define PEDIT_IP6_SRC_95_64		0x10
#define PEDIT_IP6_SRC_127_96		0x14
#define PEDIT_IP6_DST_31_0		0x18
#define PEDIT_IP6_DST_63_32		0x1C
#define PEDIT_IP6_DST_95_64		0x20
#define PEDIT_IP6_DST_127_96		0x24
#define PEDIT_TCP_SPORT_DPORT		0x0
#define PEDIT_UDP_SPORT_DPORT		0x0

int cxgb4_tc_flower_replace(struct net_device *dev,
			    struct tc_cls_flower_offload *cls);
int cxgb4_tc_flower_destroy(struct net_device *dev,
			    struct tc_cls_flower_offload *cls);
int cxgb4_tc_flower_stats(struct net_device *dev,
			  struct tc_cls_flower_offload *cls);

int cxgb4_init_tc_flower(struct adapter *adap);
void cxgb4_cleanup_tc_flower(struct adapter *adap);
#endif /* __CXGB4_TC_FLOWER_H */
