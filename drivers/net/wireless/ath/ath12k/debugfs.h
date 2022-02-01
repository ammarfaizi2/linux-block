/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _ATH12K_DEBUGFS_H_
#define _ATH12K_DEBUGFS_H_

#include "hal_tx.h"

#define ATH12K_TX_POWER_MAX_VAL	70
#define ATH12K_TX_POWER_MIN_VAL	0

/* htt_dbg_ext_stats_type */
enum ath12k_dbg_htt_ext_stats_type {
	ATH12K_DBG_HTT_EXT_STATS_RESET                      =  0,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_TX                    =  1,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_RX                    =  2,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_TX_HWQ                =  3,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_TX_SCHED              =  4,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_ERROR                 =  5,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_TQM                   =  6,
	ATH12K_DBG_HTT_EXT_STATS_TQM_CMDQ                   =  7,
	ATH12K_DBG_HTT_EXT_STATS_TX_DE_INFO                 =  8,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_TX_RATE               =  9,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_RX_RATE               =  10,
	ATH12K_DBG_HTT_EXT_STATS_PEER_INFO                  =  11,
	ATH12K_DBG_HTT_EXT_STATS_TX_SELFGEN_INFO            =  12,
	ATH12K_DBG_HTT_EXT_STATS_TX_MU_HWQ                  =  13,
	ATH12K_DBG_HTT_EXT_STATS_RING_IF_INFO               =  14,
	ATH12K_DBG_HTT_EXT_STATS_SRNG_INFO                  =  15,
	ATH12K_DBG_HTT_EXT_STATS_SFM_INFO                   =  16,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_TX_MU                 =  17,
	ATH12K_DBG_HTT_EXT_STATS_ACTIVE_PEERS_LIST          =  18,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_CCA_STATS             =  19,
	ATH12K_DBG_HTT_EXT_STATS_TWT_SESSIONS               =  20,
	ATH12K_DBG_HTT_EXT_STATS_REO_RESOURCE_STATS         =  21,
	ATH12K_DBG_HTT_EXT_STATS_TX_SOUNDING_INFO           =  22,
	ATH12K_DBG_HTT_EXT_STATS_PDEV_OBSS_PD_STATS	    =  23,
	ATH12K_DBG_HTT_EXT_STATS_RING_BACKPRESSURE_STATS    =  24,

	/* keep this last */
	ATH12K_DBG_HTT_NUM_EXT_STATS,
};

struct debug_htt_stats_req {
	bool done;
	u8 pdev_id;
	u8 type;
	u8 peer_addr[ETH_ALEN];
	struct completion cmpln;
	u32 buf_len;
	u8 buf[];
};

struct ath_pktlog_hdr {
	u16 flags;
	u16 missed_cnt;
	u16 log_type;
	u16 size;
	u32 timestamp;
	u32 type_specific_data;
	struct mlo_timestamp m_timestamp;
	u8 payload[];
};

#define ATH12K_HTT_PEER_STATS_RESET BIT(16)

#define ATH12K_HTT_STATS_BUF_SIZE (1024 * 512)
#define ATH12K_FW_STATS_BUF_SIZE (1024 * 1024)

enum ath12k_pktlog_filter {
	ATH12K_PKTLOG_RX		= 0x000000001,
	ATH12K_PKTLOG_TX		= 0x000000002,
	ATH12K_PKTLOG_RCFIND		= 0x000000004,
	ATH12K_PKTLOG_RCUPDATE		= 0x000000008,
	ATH12K_PKTLOG_EVENT_SMART_ANT	= 0x000000020,
	ATH12K_PKTLOG_EVENT_SW		= 0x000000040,
	ATH12K_PKTLOG_HYBRID		= 0x000000200,
	ATH12K_PKTLOG_ANY		= 0x00000006f,
};

enum ath12k_pktlog_mode {
	ATH12K_PKTLOG_MODE_LITE = 1,
	ATH12K_PKTLOG_MODE_FULL = 2,
};

enum ath12k_pktlog_enum {
	ATH12K_PKTLOG_TYPE_TX_CTRL      = 1,
	ATH12K_PKTLOG_TYPE_TX_STAT      = 2,
	ATH12K_PKTLOG_TYPE_TX_MSDU_ID   = 3,
	ATH12K_PKTLOG_TYPE_RX_STAT      = 5,
	ATH12K_PKTLOG_TYPE_RC_FIND      = 6,
	ATH12K_PKTLOG_TYPE_RC_UPDATE    = 7,
	ATH12K_PKTLOG_TYPE_TX_VIRT_ADDR = 8,
	ATH12K_PKTLOG_TYPE_RX_CBF       = 10,
	ATH12K_PKTLOG_TYPE_RX_STATBUF   = 22,
	ATH12K_PKTLOG_TYPE_PPDU_STATS   = 23,
	ATH12K_PKTLOG_TYPE_LITE_RX      = 24,
};

enum ath12k_dbg_aggr_mode {
	ATH12K_DBG_AGGR_MODE_AUTO,
	ATH12K_DBG_AGGR_MODE_MANUAL,
	ATH12K_DBG_AGGR_MODE_MAX,
};

#ifdef CONFIG_ATH12K_DEBUGFS
int ath12k_debugfs_soc_create(struct ath12k_base *ab);
void ath12k_debugfs_soc_destroy(struct ath12k_base *ab);
int ath12k_debugfs_pdev_create(struct ath12k_base *ab);
void ath12k_debugfs_pdev_destroy(struct ath12k_base *ab);
int ath12k_debugfs_register(struct ath12k *ar);
void ath12k_debugfs_unregister(struct ath12k *ar);
int ath12k_debugfs_create(void);
void ath12k_debugfs_destroy(void);
void ath12k_debugfs_fw_stats_process(struct ath12k_base *ab, struct sk_buff *skb);

void ath12k_debugfs_fw_stats_init(struct ath12k *ar);

static inline bool ath12k_debugfs_is_pktlog_lite_mode_enabled(struct ath12k *ar)
{
	return (ar->debug.pktlog_mode == ATH12K_PKTLOG_MODE_LITE);
}

static inline bool ath12k_debugfs_is_pktlog_rx_stats_enabled(struct ath12k *ar)
{
	return (!ar->debug.pktlog_peer_valid && ar->debug.pktlog_mode);
}

static inline bool ath12k_debugfs_is_pktlog_peer_valid(struct ath12k *ar, u8 *addr)
{
	return (ar->debug.pktlog_peer_valid && ar->debug.pktlog_mode &&
		ether_addr_equal(addr, ar->debug.pktlog_peer_addr));
}

static inline int ath12k_debugfs_is_extd_tx_stats_enabled(struct ath12k *ar)
{
	return ar->debug.extd_tx_stats;
}

static inline int ath12k_debugfs_is_extd_rx_stats_enabled(struct ath12k *ar)
{
	return ar->debug.extd_rx_stats;
}

static inline int ath12k_debugfs_rx_filter(struct ath12k *ar)
{
	return ar->debug.rx_filter;
}

#else
static inline int ath12k_debugfs_create(void)
{
	return 0;
}

static inline void ath12k_debugfs_destroy(void)
{
}

static inline int ath12k_debugfs_soc_create(struct ath12k_base *ab)
{
	return 0;
}

static inline void ath12k_debugfs_soc_destroy(struct ath12k_base *ab)
{
}

static inline int ath12k_debugfs_pdev_create(struct ath12k_base *ab)
{
	return 0;
}

static inline void ath12k_debugfs_pdev_destroy(struct ath12k_base *ab)
{
}

static inline int ath12k_debugfs_register(struct ath12k *ar)
{
	return 0;
}

static inline void ath12k_debugfs_unregister(struct ath12k *ar)
{
}

static inline void ath12k_debugfs_fw_stats_process(struct ath12k_base *ab,
						   struct sk_buff *skb)
{
}

static inline void ath12k_debugfs_fw_stats_init(struct ath12k *ar)
{
}

static inline int ath12k_debugfs_is_extd_tx_stats_enabled(struct ath12k *ar)
{
	return 0;
}

static inline int ath12k_debugfs_is_extd_rx_stats_enabled(struct ath12k *ar)
{
	return 0;
}

static inline bool ath12k_debugfs_is_pktlog_lite_mode_enabled(struct ath12k *ar)
{
	return false;
}

static inline bool ath12k_debugfs_is_pktlog_rx_stats_enabled(struct ath12k *ar)
{
	return false;
}

static inline bool ath12k_debugfs_is_pktlog_peer_valid(struct ath12k *ar, u8 *addr)
{
	return false;
}

static inline int ath12k_debugfs_rx_filter(struct ath12k *ar)
{
	return 0;
}

#endif /* CONFIG_MAC80211_DEBUGFS*/

#endif /* _ATH12K_DEBUGFS_H_ */
