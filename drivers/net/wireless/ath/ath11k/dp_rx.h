/* SPDX-License-Identifier: ISC */
/*
 * Copyright (c) 2018-2019 The Linux Foundation. All rights reserved.
 */
#ifndef ATH11K_DP_RX_H
#define ATH11K_DP_RX_H

#include "core.h"
#include "rx_desc.h"
#include "debug.h"

#define DP_RX_MPDU_ERR_FCS			BIT(0)
#define DP_RX_MPDU_ERR_DECRYPT			BIT(1)
#define DP_RX_MPDU_ERR_TKIP_MIC			BIT(2)
#define DP_RX_MPDU_ERR_AMSDU_ERR		BIT(3)
#define DP_RX_MPDU_ERR_OVERFLOW			BIT(4)
#define DP_RX_MPDU_ERR_MSDU_LEN			BIT(5)
#define DP_RX_MPDU_ERR_MPDU_LEN			BIT(6)
#define DP_RX_MPDU_ERR_UNENCRYPTED_FRAME	BIT(7)

enum dp_rx_decap_type {
	DP_RX_DECAP_TYPE_RAW,
	DP_RX_DECAP_TYPE_NATIVE_WIFI,
	DP_RX_DECAP_TYPE_ETHERNET2_DIX,
	DP_RX_DECAP_TYPE_8023,
};

struct ath11k_dp_amsdu_subframe_hdr {
	u8 dst[ETH_ALEN];
	u8 src[ETH_ALEN];
	__be16 len;
} __packed;

struct ath11k_dp_rfc1042_hdr {
	u8 llc_dsap;
	u8 llc_ssap;
	u8 llc_ctrl;
	u8 snap_oui[3];
	__be16 snap_type;
} __packed;

static inline u8 *
ath11k_dp_rx_h_80211_hdr(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return rxd->hdr_status;
}

static inline bool
ath11k_dp_rx_h_mpdu_start_valid_encrypt(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return !!FIELD_GET(RX_MPDU_START_INFO1_ENCRYPT_INFO_VALID,
			   __le32_to_cpu(rxd->mpdu_start.info1));
}

static inline void
ath11k_dp_rx_h_mpdu_start_dump_pn(struct ath11k_base *ab, u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	ath11k_info(ab, "Dump PN number: %x %x %x %x\n",
		    __le32_to_cpu(rxd->mpdu_start.pn[0]),
		    __le32_to_cpu(rxd->mpdu_start.pn[1]),
		    __le32_to_cpu(rxd->mpdu_start.pn[2]),
		    __le32_to_cpu(rxd->mpdu_start.pn[3]));
}

static inline enum hal_encrypt_type
ath11k_dp_rx_h_mpdu_start_enctype(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	if (!(__le32_to_cpu(rxd->mpdu_start.info1) &
	    RX_MPDU_START_INFO1_ENCRYPT_INFO_VALID))
		return HAL_ENCRYPT_TYPE_OPEN;

	return FIELD_GET(RX_MPDU_START_INFO2_ENC_TYPE,
			 __le32_to_cpu(rxd->mpdu_start.info2));
}

static inline u8
ath11k_dp_rx_h_mpdu_start_decap_type(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MPDU_START_INFO5_DECAP_TYPE,
			 __le32_to_cpu(rxd->mpdu_start.info5));
}

static inline bool
ath11k_dp_rx_h_attn_msdu_done(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return !!FIELD_GET(RX_ATTENTION_INFO2_MSDU_DONE,
			   __le32_to_cpu(rxd->attention.info2));
}

static inline bool
ath11k_dp_rx_h_attn_first_mpdu(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return !!FIELD_GET(RX_ATTENTION_INFO1_FIRST_MPDU,
			   __le32_to_cpu(rxd->attention.info1));
}

static inline bool
ath11k_dp_rx_h_attn_l4_cksum_fail(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return !!FIELD_GET(RX_ATTENTION_INFO1_TCP_UDP_CKSUM_FAIL,
			   __le32_to_cpu(rxd->attention.info1));
}

static inline bool
ath11k_dp_rx_h_attn_ip_cksum_fail(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return !!FIELD_GET(RX_ATTENTION_INFO1_IP_CKSUM_FAIL,
			   __le32_to_cpu(rxd->attention.info1));
}

static inline bool
ath11k_dp_rx_h_attn_is_decrypted(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return (FIELD_GET(RX_ATTENTION_INFO2_DCRYPT_STATUS_CODE,
			  __le32_to_cpu(rxd->attention.info2)) ==
		RX_DESC_DECRYPT_STATUS_CODE_OK);
}

static inline u32
ath11k_dp_rx_h_attn_mpdu_err(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;
	u32 info = __le32_to_cpu(rxd->attention.info1);
	u32 errmap = 0;

	if (info & RX_ATTENTION_INFO1_FCS_ERR)
		errmap |= DP_RX_MPDU_ERR_FCS;

	if (info & RX_ATTENTION_INFO1_DECRYPT_ERR)
		errmap |= DP_RX_MPDU_ERR_DECRYPT;

	if (info & RX_ATTENTION_INFO1_TKIP_MIC_ERR)
		errmap |= DP_RX_MPDU_ERR_TKIP_MIC;

	if (info & RX_ATTENTION_INFO1_A_MSDU_ERROR)
		errmap |= DP_RX_MPDU_ERR_AMSDU_ERR;

	if (info & RX_ATTENTION_INFO1_OVERFLOW_ERR)
		errmap |= DP_RX_MPDU_ERR_OVERFLOW;

	if (info & RX_ATTENTION_INFO1_MSDU_LEN_ERR)
		errmap |= DP_RX_MPDU_ERR_MSDU_LEN;

	if (info & RX_ATTENTION_INFO1_MPDU_LEN_ERR)
		errmap |= DP_RX_MPDU_ERR_MPDU_LEN;

	return errmap;
}

static inline u16
ath11k_dp_rx_h_msdu_start_msdu_len(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MSDU_START_INFO1_MSDU_LENGTH,
			 __le32_to_cpu(rxd->msdu_start.info1));
}

static inline u8
ath11k_dp_rx_h_msdu_start_sgi(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MSDU_START_INFO3_SGI,
			 __le32_to_cpu(rxd->msdu_start.info3));
}

static inline u8
ath11k_dp_rx_h_msdu_start_rate_mcs(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MSDU_START_INFO3_RATE_MCS,
			 __le32_to_cpu(rxd->msdu_start.info3));
}

static inline u8
ath11k_dp_rx_h_msdu_start_rx_bw(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MSDU_START_INFO3_RECV_BW,
			 __le32_to_cpu(rxd->msdu_start.info3));
}

static inline u8
ath11k_dp_rx_h_msdu_start_recption_type(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MSDU_START_INFO3_RECEPTION_TYPE,
			 __le32_to_cpu(rxd->msdu_start.info3));
}

static inline u32
ath11k_dp_rx_h_msdu_start_flow_id(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return __le32_to_cpu(rxd->msdu_start.flow_id_toeplitz);
}

static inline u8
ath11k_dp_rx_h_msdu_start_rssi(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MSDU_START_INFO3_USER_RSSI,
			 __le32_to_cpu(rxd->msdu_start.info3));
}

static inline u32
ath11k_dp_rx_h_msdu_start_freq(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return __le32_to_cpu(rxd->msdu_start.phy_meta_data);
}

static inline u8
ath11k_dp_rx_h_msdu_start_pkt_type(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MSDU_START_INFO3_PKT_TYPE,
			 __le32_to_cpu(rxd->msdu_start.info3));
}

static inline u8
ath11k_dp_rx_h_msdu_start_nss(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;
	u8 mimo_ss_bitmap = FIELD_GET(RX_MSDU_START_INFO3_MIMO_SS_BITMAP,
				      __le32_to_cpu(rxd->msdu_start.info3));

	return hweight8(mimo_ss_bitmap);
}

static inline u8
ath11k_dp_rx_h_msdu_end_l3pad(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return FIELD_GET(RX_MSDU_END_INFO2_L3_HDR_PADDING,
			 __le32_to_cpu(rxd->msdu_end.info2));
}

static inline bool
ath11k_dp_rx_h_msdu_end_first_msdu(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return !!FIELD_GET(RX_MSDU_END_INFO2_FIRST_MSDU,
			   __le32_to_cpu(rxd->msdu_end.info2));
}

static inline bool
ath11k_dp_rx_h_msdu_end_last_msdu(u8 *desc)
{
	struct hal_rx_desc *rxd = (struct hal_rx_desc *)desc;

	return !!FIELD_GET(RX_MSDU_END_INFO2_LAST_MSDU,
			   __le32_to_cpu(rxd->msdu_end.info2));
}

static inline void ath11k_dp_rx_desc_end_tlv_copy(u8 *first, u8 *last)
{
	struct hal_rx_desc *fdesc = (struct hal_rx_desc *)first;
	struct hal_rx_desc *ldesc = (struct hal_rx_desc *)last;

	memcpy((u8 *)&fdesc->msdu_end, (u8 *)&ldesc->msdu_end,
	       sizeof(struct rx_msdu_end));
	memcpy((u8 *)&fdesc->attention, (u8 *)&ldesc->attention,
	       sizeof(struct rx_attention));
	memcpy((u8 *)&fdesc->mpdu_end, (u8 *)&ldesc->mpdu_end,
	       sizeof(struct rx_mpdu_end));
}

int ath11k_dp_rx_ampdu_start(struct ath11k *ar,
			     struct ieee80211_ampdu_params *params);
int ath11k_dp_rx_ampdu_stop(struct ath11k *ar,
			    struct ieee80211_ampdu_params *params);
void ath11k_peer_rx_tid_cleanup(struct ath11k *ar, struct ath11k_peer *peer);
int ath11k_peer_rx_tid_setup(struct ath11k *ar, const u8 *peer_mac, int vdev_id,
			     u8 tid, u32 ba_win_sz, u16 ssn);
void ath11k_dp_htt_htc_t2h_msg_handler(struct ath11k_base *ab,
				       struct sk_buff *skb);
int ath11k_dp_rx_pdev_alloc(struct ath11k_base *ab, int pdev_idx);
void ath11k_dp_rx_pdev_free(struct ath11k_base *ab, int pdev_idx);
void ath11k_dp_reo_cmd_list_cleanup(struct ath11k_base *ab);
void ath11k_dp_process_reo_status(struct ath11k_base *ab);
int ath11k_dp_process_rxdma_err(struct ath11k_base *ab, int mac_id, int budget);
int ath11k_dp_rx_process_wbm_err(struct ath11k_base *ab,
				 struct napi_struct *napi, int budget);
int ath11k_dp_process_rx_err(struct ath11k_base *ab, struct napi_struct *napi,
			     int budget);
int ath11k_dp_process_rx(struct ath11k_base *ab, int mac_id,
			 struct napi_struct *napi, int budget);
int ath11k_dp_rxbufs_replenish(struct ath11k_base *ab, int mac_id,
			       struct dp_rxdma_ring *rx_ring,
			       int req_entries,
			       enum hal_rx_buf_return_buf_manager mgr,
			       gfp_t gfp);
int ath11k_dp_htt_tlv_iter(struct ath11k_base *ab, const void *ptr, size_t len,
			   int (*iter)(struct ath11k_base *ar, u16 tag, u16 len,
				       const void *ptr, void *data),
			   void *data);
int ath11k_dp_htt_rx_filter_setup(struct ath11k_base *ab, u32 ring_id,
				  int mac_id, enum hal_ring_type ring_type,
				  int rx_buf_size,
				  struct htt_rx_ring_tlv_filter *tlv_filter);
int ath11k_dp_rx_process_mon_status(struct ath11k_base *ab, int mac_id,
				    struct napi_struct *napi, int budget);
int ath11k_dp_rx_mon_status_bufs_replenish(struct ath11k_base *ab, int mac_id,
					   struct dp_rxdma_ring *rx_ring,
					   int req_entries,
					   enum hal_rx_buf_return_buf_manager mgr,
					   gfp_t gfp);
#endif /* ATH11K_DP_RX_H */
