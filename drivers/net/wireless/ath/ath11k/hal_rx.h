/* SPDX-License-Identifier: ISC */
/*
 * Copyright (c) 2018-2019 The Linux Foundation. All rights reserved.
 */

#ifndef ATH11K_HAL_RX_H
#define ATH11K_HAL_RX_H

struct hal_rx_mpdu_meta {
	u32 peer_meta;
	u16 msdu_cnt;
	u16 seq_num;
	bool frag;
	bool retry;
	bool ampdu;
	bool raw;
};

struct hal_rx_msdu_meta {
	u32 cookie;
	u32 msdu_len;
	bool first;
	bool last;
	bool continuation;
};

struct hal_rx_meta_info {
	enum hal_reo_dest_ring_push_reason push_reason;
	struct hal_rx_mpdu_meta mpdu_meta;
	struct hal_rx_msdu_meta msdu_meta;
};

struct hal_rx_wbm_rel_info {
	u32 cookie;
	enum hal_wbm_rel_src_module err_rel_src;
	enum hal_reo_dest_ring_push_reason push_reason;
	u32 err_code;
	bool first_msdu;
	bool last_msdu;
};

void ath11k_hal_reo_status_queue_stats(struct ath11k_base *ab, u32 *reo_desc,
				       struct hal_reo_status *status);
void ath11k_hal_reo_flush_queue_status(struct ath11k_base *ab, u32 *reo_desc,
				       struct hal_reo_status *status);
void ath11k_hal_reo_flush_cache_status(struct ath11k_base *ab, u32 *reo_desc,
				       struct hal_reo_status *status);
void ath11k_hal_reo_flush_cache_status(struct ath11k_base *ab, u32 *reo_desc,
				       struct hal_reo_status *status);
void ath11k_hal_reo_unblk_cache_status(struct ath11k_base *ab, u32 *reo_desc,
				       struct hal_reo_status *status);
void ath11k_hal_reo_flush_timeout_list_status(struct ath11k_base *ab,
					      u32 *reo_desc,
					      struct hal_reo_status *status);
void ath11k_hal_reo_desc_thresh_reached_status(struct ath11k_base *ab,
					       u32 *reo_desc,
					       struct hal_reo_status *status);
void ath11k_hal_reo_update_rx_reo_queue_status(struct ath11k_base *ab,
					       u32 *reo_desc,
					       struct hal_reo_status *status);
int ath11k_hal_reo_process_status(u8 *reo_desc, u8 *status);
void ath11k_hal_rx_msdu_link_info_get(void *link_desc, u32 *num_msdus,
				      struct hal_rx_msdu_meta *meta,
				      enum hal_rx_buf_return_buf_manager *rbm);
void ath11k_hal_rx_msdu_link_desc_set(struct ath11k_base *ab, void *desc,
				      void *link_desc,
				      enum hal_wbm_rel_bm_act action);
void ath11k_hal_rx_buf_addr_info_set(void *desc, dma_addr_t paddr,
				     u32 cookie, u8 manager);
void ath11k_hal_rx_buf_addr_info_get(void *desc, dma_addr_t *paddr,
				     u32 *cookie, u8 *rbm);
int ath11k_hal_desc_reo_parse_err(struct ath11k_base *ab, u32 *rx_desc,
				  dma_addr_t *paddr, u32 *desc_bank);
void ath11k_hal_rx_parse_dst_ring_desc(struct ath11k_base *ab, u32 *rx_desc,
				       struct hal_rx_meta_info *meta_info);
int ath11k_hal_wbm_desc_parse_err(struct ath11k_base *ab, void *desc,
				  struct hal_rx_wbm_rel_info *rel_info);
void ath11k_hal_rx_reo_ent_paddr_get(struct ath11k_base *ab, void *desc,
				     dma_addr_t *paddr, u32 *desc_bank);
#endif
