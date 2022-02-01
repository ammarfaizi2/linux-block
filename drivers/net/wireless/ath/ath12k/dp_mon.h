/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2019-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef ATH12K_DP_MON_H
#define ATH12K_DP_MON_H

#include "core.h"

#define ATH12K_DP_TX_MONITOR_MODE 0
#define ATH12K_DP_RX_MONITOR_MODE 1
#define ATH11K_DEFAULT_NOISE_FLOOR -95

#define HAL_RX_UL_OFDMA_USER_INFO_V0_W0_VALID		BIT(30)
#define HAL_RX_UL_OFDMA_USER_INFO_V0_W0_VER		BIT(31)
#define HAL_RX_UL_OFDMA_USER_INFO_V0_W1_NSS		GENMASK(2, 0)
#define HAL_RX_UL_OFDMA_USER_INFO_V0_W1_MCS		GENMASK(6, 3)
#define HAL_RX_UL_OFDMA_USER_INFO_V0_W1_LDPC		BIT(7)
#define HAL_RX_UL_OFDMA_USER_INFO_V0_W1_DCM		BIT(8)
#define HAL_RX_UL_OFDMA_USER_INFO_V0_W1_RU_START	GENMASK(15, 9)
#define HAL_RX_UL_OFDMA_USER_INFO_V0_W1_RU_SIZE		GENMASK(18, 16)

enum dp_mon_tx_ppdu_info_type {
	DP_MON_TX_PROT_PPDU_INFO,
	DP_MON_TX_DATA_PPDU_INFO
};

enum hal_tx_tlv_status {
	HAL_MON_TX_FES_SETUP,
	HAL_MON_TX_FES_STATUS_END,
	HAL_MON_RX_RESPONSE_REQUIRED_INFO,
	HAL_MON_RESPONSE_END_STATUS_INFO,
	HAL_MON_TX_MPDU_START,
	HAL_MON_TX_MSDU_START,
	HAL_MON_TX_BUFFER_ADDR,
	HAL_MON_TX_DATA,
	HAL_TX_MON_STATUS_PPDU_NOT_DONE,
};

enum medium_protection_type {
	HAL_MON_TX_MEDIUM_NO_PROTECTION,
	HAL_MON_TX_MEDIUM_RTS_LEGACY,
	HAL_MON_TX_MEDIUM_RTS_11AC_STATIC_BW,
	HAL_MON_TX_MEDIUM_RTS_11AC_DYNAMIC_BW,
	HAL_MON_TX_MEDIUM_CTS2SELF,
	HAL_MON_TX_MEDIUM_QOS_NULL_NO_ACK_3ADDR,
	HAL_MON_TX_MEDIUM_QOS_NULL_NO_ACK_4ADDR
};

struct ieee80211_qosframe_addr4 {
	__le16 frame_control;
	__le16 duration;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctrl;
	u8 addr4[ETH_ALEN];
	__le16 qos_ctrl;
} __packed;

struct ieee80211_frame_min_one {
	__le16 frame_control;
	__le16 duration;
	u8 addr1[ETH_ALEN];
} __packed;

#define HAL_TX_PHY_DESC_INFO0_BF_TYPE		GENMASK(17, 16)
#define HAL_TX_PHY_DESC_INFO0_PREAMBLE_11B	BIT(20)
#define HAL_TX_PHY_DESC_INFO0_PKT_TYPE		GENMASK(24, 21)
#define HAL_TX_PHY_DESC_INFO0_BANDWIDTH		GENMASK(30, 28)
#define HAL_TX_PHY_DESC_INFO1_MCS		GENMASK(3, 0)
#define HAL_TX_PHY_DESC_INFO1_STBC		BIT(6)
#define HAL_TX_PHY_DESC_INFO2_NSS		GENMASK(23, 21)
#define HAL_TX_PHY_DESC_INFO3_AP_PKT_BW		GENMASK(6, 4)
#define HAL_TX_PHY_DESC_INFO3_LTF_SIZE		GENMASK(20, 19)
#define HAL_TX_PHY_DESC_INFO3_ACTIVE_CHANNEL	GENMASK(17, 15)

struct hal_tx_phy_desc {
	__le32 info0;
	__le32 info1;
	__le32 info2;
	__le32 info3;
} __packed;

#define HAL_RX_FBM_ACK_INFO0_ADDR1_31_0		GENMASK(31, 0)
#define HAL_RX_FBM_ACK_INFO1_ADDR1_47_32	GENMASK(15, 0)
#define HAL_RX_FBM_ACK_INFO1_ADDR2_15_0		GENMASK(31, 16)
#define HAL_RX_FBM_ACK_INFO2_ADDR2_47_16	GENMASK(31, 0)

struct hal_rx_frame_bitmap_ack {
	__le32 reserved;
	__le32 info0;
	__le32 info1;
	__le32 info2;
	__le32 reserved1[10];
} __packed;

#define HAL_TX_FES_STAT_PROT_INFO0_STRT_FRM_TS_15_0	GENMASK(15, 0)
#define HAL_TX_FES_STAT_PROT_INFO0_STRT_FRM_TS_31_16	GENMASK(31, 16)
#define HAL_TX_FES_STAT_PROT_INFO1_END_FRM_TS_15_0	GENMASK(15, 0)
#define HAL_TX_FES_STAT_PROT_INFO1_END_FRM_TS_31_16	GENMASK(31, 16)

struct hal_tx_fes_status_prot {
	__le64 reserved;
	__le32 info0;
	__le32 info1;
	__le32 reserved1[11];
} __packed;

#define HAL_TX_FES_STAT_USR_PPDU_INFO0_DURATION		GENMASK(15, 0)

struct hal_tx_fes_status_user_ppdu {
	__le64 reserved;
	__le32 info0;
	__le32 reserved1[3];
} __packed;

#define HAL_TX_FES_STAT_STRT_INFO0_PROT_TS_LOWER_32	GENMASK(31, 0)
#define HAL_TX_FES_STAT_STRT_INFO1_PROT_TS_UPPER_32	GENMASK(31, 0)

struct hal_tx_fes_status_start_prot {
	__le32 info0;
	__le32 info1;
	__le64 reserved;
} __packed;

#define HAL_TX_FES_STATUS_START_INFO0_MEDIUM_PROT_TYPE	GENMASK(29, 27)

struct hal_tx_fes_status_start {
	__le32 reserved;
	__le32 info0;
	__le64 reserved1;
} __packed;

#define HAL_TX_Q_EXT_INFO0_FRAME_CTRL		GENMASK(15, 0)
#define HAL_TX_Q_EXT_INFO0_QOS_CTRL		GENMASK(31, 16)
#define HAL_TX_Q_EXT_INFO1_AMPDU_FLAG		BIT(0)

struct hal_tx_queue_exten {
	__le32 info0;
	__le32 info1;
} __packed;

#define HAL_TX_FES_SETUP_INFO0_NUM_OF_USERS	GENMASK(28, 23)

struct hal_tx_fes_setup {
	__le32 schedule_id;
	__le32 info0;
	__le64 reserved;
} __packed;

#define HAL_TX_PPDU_SETUP_INFO0_MEDIUM_PROT_TYPE	GENMASK(2, 0)
#define HAL_TX_PPDU_SETUP_INFO1_PROT_FRAME_ADDR1_31_0	GENMASK(31, 0)
#define HAL_TX_PPDU_SETUP_INFO2_PROT_FRAME_ADDR1_47_32	GENMASK(15, 0)
#define HAL_TX_PPDU_SETUP_INFO2_PROT_FRAME_ADDR2_15_0	GENMASK(31, 16)
#define HAL_TX_PPDU_SETUP_INFO3_PROT_FRAME_ADDR2_47_16	GENMASK(31, 0)
#define HAL_TX_PPDU_SETUP_INFO4_PROT_FRAME_ADDR3_31_0	GENMASK(31, 0)
#define HAL_TX_PPDU_SETUP_INFO5_PROT_FRAME_ADDR3_47_32	GENMASK(15, 0)
#define HAL_TX_PPDU_SETUP_INFO5_PROT_FRAME_ADDR4_15_0	GENMASK(31, 16)
#define HAL_TX_PPDU_SETUP_INFO6_PROT_FRAME_ADDR4_47_16	GENMASK(31, 0)

struct hal_tx_pcu_ppdu_setup_init {
	__le32 info0;
	__le32 info1;
	__le32 info2;
	__le32 info3;
	__le32 reserved;
	__le32 info4;
	__le32 info5;
	__le32 info6;
} __packed;

#define HAL_TX_FES_STATUS_END_INFO0_START_TIMESTAMP_15_0	GENMASK(15, 0)
#define HAL_TX_FES_STATUS_END_INFO0_START_TIMESTAMP_31_16	GENMASK(31, 16)

struct hal_tx_fes_status_end {
	__le32 reserved[2];
	__le32 info0;
	__le32 reserved1[19];
} __packed;

#define HAL_RX_RESP_REQ_INFO0_PPDU_ID		GENMASK(15, 0)
#define HAL_RX_RESP_REQ_INFO0_RECEPTION_TYPE	BIT(16)
#define HAL_RX_RESP_REQ_INFO1_DURATION		GENMASK(15, 0)
#define HAL_RX_RESP_REQ_INFO1_RATE_MCS		GENMASK(24, 21)
#define HAL_RX_RESP_REQ_INFO1_SGI		GENMASK(26, 25)
#define HAL_RX_RESP_REQ_INFO1_STBC		BIT(27)
#define HAL_RX_RESP_REQ_INFO1_LDPC		BIT(28)
#define HAL_RX_RESP_REQ_INFO1_IS_AMPDU		BIT(29)
#define HAL_RX_RESP_REQ_INFO2_NUM_USER		GENMASK(6, 0)
#define HAL_RX_RESP_REQ_INFO3_ADDR1_31_0	GENMASK(31, 0)
#define HAL_RX_RESP_REQ_INFO4_ADDR1_47_32	GENMASK(15, 0)
#define HAL_RX_RESP_REQ_INFO4_ADDR1_15_0	GENMASK(31, 16)
#define HAL_RX_RESP_REQ_INFO5_ADDR1_47_16	GENMASK(31, 0)

struct hal_rx_resp_req_info {
	__le32 info0;
	__le32 reserved[1];
	__le32 info1;
	__le32 info2;
	__le32 reserved1[2];
	__le32 info3;
	__le32 info4;
	__le32 info5;
	__le32 reserved2[5];
} __packed;

struct hal_mon_packet_info {
	u64 cookie;
	u16 dma_length;
	bool msdu_continuation;
	bool truncated;
};

struct dp_mon_tx_ppdu_info {
	u32 ppdu_id;
	u8  num_users;
	bool is_used;
	struct hal_rx_mon_ppdu_info rx_status;
	struct list_head dp_tx_mon_mpdu_list;
	struct dp_mon_mpdu *tx_mon_mpdu;
};

enum hal_rx_mon_status
ath12k_dp_mon_rx_parse_mon_status(struct ath12k *ar,
				  struct ath12k_mon_data *pmon,
				  int mac_id, struct sk_buff *skb,
				  struct napi_struct *napi);
int ath12k_dp_mon_buf_replenish(struct ath12k_base *ab,
				struct dp_rxdma_ring *buf_ring,
				int req_entries);
int ath12k_dp_mon_srng_process(struct ath12k *ar, int mac_id,
			       int *budget, bool flag,
			       struct napi_struct *napi);
int ath12k_dp_mon_process_ring(struct ath12k_base *ab, int mac_id,
			       struct napi_struct *napi, int budget, bool flag);
struct sk_buff *ath12k_dp_mon_tx_alloc_skb(void);
enum hal_tx_tlv_status
ath12k_dp_mon_tx_status_get_num_user(u16 tlv_tag,
				     struct hal_tlv_hdr *tx_tlv,
				     u8 *num_users);
enum hal_rx_mon_status
ath12k_dp_mon_tx_parse_mon_status(struct ath12k *ar,
				  struct ath12k_mon_data *pmon,
				  int mac_id,
				  struct sk_buff *skb,
				  struct napi_struct *napi,
				  u32 ppdu_id);
void ath12k_dp_mon_rx_process_ulofdma(struct hal_rx_mon_ppdu_info *ppdu_info);
int ath12k_dp_mon_rx_process_stats(struct ath12k *ar, int mac_id,
				   struct napi_struct *napi, int *budget);
#endif
