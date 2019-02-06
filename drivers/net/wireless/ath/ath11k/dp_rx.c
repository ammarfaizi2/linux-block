// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2018-2019 The Linux Foundation. All rights reserved.
 */

#include "core.h"
#include "debug.h"
#include "hal_desc.h"
#include "hw.h"
#include "dp_rx.h"
#include "hal_rx.h"
#include "dp_tx.h"

/* Returns number of Rx buffers replenished */
int ath11k_dp_rxbufs_replenish(struct ath11k_base *ab, int mac_id,
			       struct dp_rxdma_ring *rx_ring,
			       int req_entries,
			       enum hal_rx_buf_return_buf_manager mgr,
			       gfp_t gfp)
{
	struct hal_srng *srng;
	u32 *desc;
	struct sk_buff *skb;
	int num_free;
	int num_remain;
	int buf_id;
	u32 cookie;
	dma_addr_t paddr;

	req_entries = min(req_entries, rx_ring->bufs_max);

	srng = &ab->hal.srng_list[rx_ring->refill_buf_ring.ring_id];

	spin_lock_bh(&srng->lock);

	ath11k_hal_srng_access_begin(ab, srng);

	num_free = ath11k_hal_srng_src_num_free(ab, srng, true);
	if (!req_entries && (num_free > (rx_ring->bufs_max * 3) / 4))
		req_entries = num_free;

	req_entries = min(num_free, req_entries);
	num_remain = req_entries;

	while (num_remain > 0) {
		skb = dev_alloc_skb(DP_RX_BUFFER_SIZE +
				    DP_RX_BUFFER_ALIGN_SIZE);
		if (!skb)
			break;

		if (!IS_ALIGNED((unsigned long)skb->data,
				DP_RX_BUFFER_ALIGN_SIZE)) {
			skb_pull(skb,
				 PTR_ALIGN(skb->data, DP_RX_BUFFER_ALIGN_SIZE) -
				 skb->data);
		}

		paddr = dma_map_single(ab->dev, skb->data,
				       skb->len + skb_tailroom(skb),
				       DMA_FROM_DEVICE);
		if (dma_mapping_error(ab->dev, paddr))
			goto fail_free_skb;

		spin_lock_bh(&rx_ring->idr_lock);
		buf_id = idr_alloc(&rx_ring->bufs_idr, skb, 0,
				   rx_ring->bufs_max * 3, gfp);
		spin_unlock_bh(&rx_ring->idr_lock);
		if (buf_id < 0)
			goto fail_dma_unmap;

		desc = ath11k_hal_srng_src_get_next_entry(ab, srng);
		if (!desc)
			goto fail_idr_remove;

		ATH11K_SKB_RXCB(skb)->paddr = paddr;

		cookie = FIELD_PREP(DP_RXDMA_BUF_COOKIE_PDEV_ID, mac_id) |
			 FIELD_PREP(DP_RXDMA_BUF_COOKIE_BUF_ID, buf_id);

		num_remain--;

		ath11k_hal_rx_buf_addr_info_set(desc, paddr, cookie, mgr);
	}

	ath11k_hal_srng_access_end(ab, srng);

	spin_unlock_bh(&srng->lock);

	return req_entries - num_remain;

fail_idr_remove:
	spin_lock_bh(&rx_ring->idr_lock);
	idr_remove(&rx_ring->bufs_idr, buf_id);
	spin_unlock_bh(&rx_ring->idr_lock);
fail_dma_unmap:
	dma_unmap_single(ab->dev, paddr, skb->len + skb_tailroom(skb),
			 DMA_FROM_DEVICE);
fail_free_skb:
	dev_kfree_skb_any(skb);

	ath11k_hal_srng_access_end(ab, srng);

	spin_unlock_bh(&srng->lock);

	return req_entries - num_remain;
}

static int ath11k_dp_rxdma_pdev_buf_free(struct ath11k *ar)
{
	struct ath11k_pdev_dp *dp = &ar->dp;
	struct dp_rxdma_ring *rx_ring = &dp->rx_refill_buf_ring;
	struct sk_buff *skb;
	int buf_id;

	spin_lock_bh(&rx_ring->idr_lock);
	idr_for_each_entry(&rx_ring->bufs_idr, skb, buf_id) {
		idr_remove(&rx_ring->bufs_idr, buf_id);
		/* TODO: Understand where internal driver does this dma_unmap of
		 * of rxdma_buffer.
		 */
		dma_unmap_single(ar->ab->dev, ATH11K_SKB_RXCB(skb)->paddr,
				 skb->len + skb_tailroom(skb), DMA_FROM_DEVICE);
		dev_kfree_skb_any(skb);
	}

	idr_destroy(&rx_ring->bufs_idr);
	spin_unlock_bh(&rx_ring->idr_lock);

	return 0;
}

static int ath11k_dp_rxdma_pdev_buf_setup(struct ath11k *ar)
{
	struct ath11k_pdev_dp *dp = &ar->dp;
	struct dp_rxdma_ring *rx_ring = &dp->rx_refill_buf_ring;
	int num_entries;

	num_entries = rx_ring->refill_buf_ring.size /
		      ath11k_hal_srng_get_entrysize(HAL_RXDMA_BUF);

	rx_ring->bufs_max = num_entries;
	ath11k_dp_rxbufs_replenish(ar->ab, dp->mac_id, rx_ring, num_entries,
				   HAL_RX_BUF_RBM_SW3_BM, GFP_KERNEL);
	return 0;
}

static void ath11k_dp_rx_pdev_srng_free(struct ath11k *ar)
{
	struct ath11k_pdev_dp *dp = &ar->dp;

	ath11k_dp_srng_cleanup(ar->ab, &dp->rx_refill_buf_ring.refill_buf_ring);
	ath11k_dp_srng_cleanup(ar->ab, &dp->reo_dst_ring);
	ath11k_dp_srng_cleanup(ar->ab, &dp->rxdma_err_dst_ring);
}

static int ath11k_dp_rx_pdev_srng_alloc(struct ath11k *ar)
{
	struct ath11k_pdev_dp *dp = &ar->dp;
	int ret;

	ret = ath11k_dp_srng_setup(ar->ab,
				   &dp->rx_refill_buf_ring.refill_buf_ring,
				   HAL_RXDMA_BUF, 0,
				   dp->mac_id, DP_RXDMA_BUF_RING_SIZE);
	if (ret) {
		ath11k_warn(ar->ab, "failed to setup rx_refill_buf_ring\n");
		return ret;
	}

	ret = ath11k_dp_srng_setup(ar->ab, &dp->reo_dst_ring, HAL_REO_DST,
				   dp->mac_id, dp->mac_id,
				   DP_REO_DST_RING_SIZE);
	if (ret) {
		ath11k_warn(ar->ab, "failed to setup reo_dst_ring\n");
		return ret;
	}

	ret = ath11k_dp_srng_setup(ar->ab, &dp->rxdma_err_dst_ring,
				   HAL_RXDMA_DST, 0, dp->mac_id,
				   DP_RXDMA_ERR_DST_RING_SIZE);
	if (ret) {
		ath11k_warn(ar->ab, "failed to setup reo_dst_ring\n");
		return ret;
	}

	return 0;
}

void ath11k_dp_reo_cmd_list_cleanup(struct ath11k_base *ab)
{
	struct ath11k_dp *dp = &ab->dp;
	struct dp_reo_cmd *cmd, *tmp;
	struct dp_reo_cache_flush_elem *cmd_cache, *tmp_cache;

	spin_lock_bh(&dp->reo_cmd_lock);
	list_for_each_entry_safe(cmd, tmp, &dp->reo_cmd_list, list) {
		list_del(&cmd->list);
		dma_unmap_single(ab->dev, cmd->data.paddr,
				 cmd->data.size, DMA_BIDIRECTIONAL);
		kfree(cmd->data.vaddr);
		kfree(cmd);
	}

	list_for_each_entry_safe(cmd_cache, tmp_cache,
				 &dp->reo_cmd_cache_flush_list, list) {
		list_del(&cmd_cache->list);
		dma_unmap_single(ab->dev, cmd_cache->data.paddr,
				 cmd_cache->data.size, DMA_BIDIRECTIONAL);
		kfree(cmd_cache->data.vaddr);
		kfree(cmd_cache);
	}
	spin_unlock_bh(&dp->reo_cmd_lock);
}

static void ath11k_dp_reo_cmd_free(struct ath11k_dp *dp, void *ctx,
				   enum hal_reo_cmd_status status)
{
	struct dp_rx_tid *rx_tid = ctx;

	if (status != HAL_REO_CMD_SUCCESS)
		ath11k_warn(dp->sc, "failed to flush rx tid hw desc, tid %d status %d\n",
			    rx_tid->tid, status);

	dma_unmap_single(dp->sc->dev, rx_tid->paddr, rx_tid->size,
			 DMA_BIDIRECTIONAL);
	kfree(rx_tid->vaddr);
}

static void ath11k_dp_reo_cache_flush(struct ath11k_base *ab,
				      struct dp_rx_tid *rx_tid)
{
	struct ath11k_hal_reo_cmd cmd = {0};
	unsigned long tot_desc_sz, desc_sz;
	int ret;

	tot_desc_sz = rx_tid->size;
	desc_sz = ath11k_hal_reo_qdesc_size(0, HAL_DESC_REO_NON_QOS_TID);

	while (tot_desc_sz > desc_sz) {
		tot_desc_sz -= desc_sz;
		cmd.addr_lo = lower_32_bits(rx_tid->paddr + tot_desc_sz);
		cmd.addr_hi = upper_32_bits(rx_tid->paddr);
		ret = ath11k_dp_send_reo_cmd(ab, rx_tid,
					     HAL_REO_CMD_FLUSH_CACHE, &cmd,
					     NULL);
		if (ret)
			ath11k_warn(ab,
				    "failed to send HAL_REO_CMD_FLUSH_CACHE, tid %d (%d)\n",
				    rx_tid->tid, ret);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.addr_lo = lower_32_bits(rx_tid->paddr);
	cmd.addr_hi = upper_32_bits(rx_tid->paddr);
	cmd.flag |= HAL_REO_CMD_FLG_NEED_STATUS;
	ret = ath11k_dp_send_reo_cmd(ab, rx_tid,
				     HAL_REO_CMD_FLUSH_CACHE,
				     &cmd, ath11k_dp_reo_cmd_free);
	if (ret) {
		ath11k_err(ab, "failed to send HAL_REO_CMD_FLUSH_CACHE cmd, tid %d (%d)\n",
			   rx_tid->tid, ret);
		dma_unmap_single(ab->dev, rx_tid->paddr, rx_tid->size,
				 DMA_BIDIRECTIONAL);
		kfree(rx_tid->vaddr);
	}
}

static void ath11k_dp_rx_tid_del_func(struct ath11k_dp *dp, void *ctx,
				      enum hal_reo_cmd_status status)
{
	struct ath11k_base *ab = dp->sc;
	struct dp_rx_tid *rx_tid = ctx;
	struct dp_reo_cache_flush_elem *elem, *tmp;

	if (status == HAL_REO_CMD_DRAIN)
		goto free_desc;

	elem = kzalloc(sizeof(elem), GFP_ATOMIC);
	if (!elem) {
		ath11k_warn(ab, "failed to allocate memory for cache flush element\n");
		goto free_desc;
	}

	elem->ts = jiffies;
	memcpy(&elem->data, rx_tid, sizeof(*rx_tid));

	spin_lock_bh(&dp->reo_cmd_lock);
	list_add_tail(&elem->list, &dp->reo_cmd_cache_flush_list);
	spin_unlock_bh(&dp->reo_cmd_lock);

	/* Flush and invalidate aged REO desc from HW cache */
	spin_lock_bh(&dp->reo_cmd_lock);
	list_for_each_entry_safe(elem, tmp, &dp->reo_cmd_cache_flush_list,
				 list) {
		if (time_after(elem->ts, jiffies +
			       msecs_to_jiffies(DP_REO_DESC_FREE_TIMEOUT_MS))) {
			list_del(&elem->list);
			spin_unlock_bh(&dp->reo_cmd_lock);

			ath11k_dp_reo_cache_flush(ab, &elem->data);
			kfree(elem);
			spin_lock_bh(&dp->reo_cmd_lock);
		}
	}
	spin_unlock_bh(&dp->reo_cmd_lock);

	return;
free_desc:
	dma_unmap_single(ab->dev, rx_tid->paddr, rx_tid->size,
			 DMA_BIDIRECTIONAL);
	kfree(rx_tid->vaddr);
}

static void ath11k_peer_rx_tid_delete(struct ath11k *ar,
				      struct ath11k_peer *peer, u8 tid)
{
	struct ath11k_hal_reo_cmd cmd = {0};
	struct dp_rx_tid *rx_tid = &peer->rx_tid[tid];
	int ret;

	if (!rx_tid->active)
		return;

	cmd.addr_lo = lower_32_bits(rx_tid->paddr);
	cmd.addr_hi = upper_32_bits(rx_tid->paddr);
	cmd.upd0 |= HAL_REO_CMD_UPD0_VLD;
	ret = ath11k_dp_send_reo_cmd(ar->ab, rx_tid,
				     HAL_REO_CMD_UPDATE_RX_QUEUE, &cmd,
				     ath11k_dp_rx_tid_del_func);
	if (ret) {
		ath11k_err(ar->ab, "failed to send HAL_REO_CMD_UPDATE_RX_QUEUE cmd, tid %d (%d)\n",
			   tid, ret);
		dma_unmap_single(ar->ab->dev, rx_tid->paddr, rx_tid->size,
				 DMA_BIDIRECTIONAL);
		kfree(rx_tid->vaddr);
	}

	rx_tid->active = false;
}

void ath11k_peer_rx_tid_cleanup(struct ath11k *ar, struct ath11k_peer *peer)
{
	int i;

	for (i = 0; i <= IEEE80211_NUM_TIDS; i++)
		ath11k_peer_rx_tid_delete(ar, peer, i);
}

static int ath11k_peer_rx_tid_reo_update(struct ath11k *ar,
					 struct ath11k_peer *peer,
					 struct dp_rx_tid *rx_tid,
					 u32 ba_win_sz, u16 ssn)
{
	struct ath11k_hal_reo_cmd cmd = {0};
	int ret;

	cmd.addr_lo = lower_32_bits(rx_tid->paddr);
	cmd.addr_hi = upper_32_bits(rx_tid->paddr);
	cmd.flag = HAL_REO_CMD_FLG_NEED_STATUS;
	cmd.upd0 = HAL_REO_CMD_UPD0_BA_WINDOW_SIZE |
		   HAL_REO_CMD_UPD0_SSN;
	cmd.ba_window_size = ba_win_sz;
	cmd.upd2 = FIELD_PREP(HAL_REO_CMD_UPD2_SSN, ssn);

	ret = ath11k_dp_send_reo_cmd(ar->ab, rx_tid,
				     HAL_REO_CMD_UPDATE_RX_QUEUE, &cmd, NULL);
	if (ret) {
		ath11k_warn(ar->ab, "failed to update rx tid queue, tid %d (%d)\n",
			    rx_tid->tid, ret);
		return ret;
	}

	rx_tid->ba_win_sz = ba_win_sz;

	return 0;
}

static void ath11k_dp_rx_tid_mem_free(struct ath11k_base *ab,
				      const u8 *peer_mac, int vdev_id, u8 tid)
{
	struct ath11k_peer *peer;
	struct dp_rx_tid *rx_tid;

	spin_lock_bh(&ab->data_lock);

	peer = ath11k_peer_find(ab, vdev_id, peer_mac);
	if (!peer) {
		ath11k_warn(ab, "failed to find the peer to free up rx tid mem\n");
		goto unlock_exit;
	}

	rx_tid = &peer->rx_tid[tid];
	if (!rx_tid->active)
		goto unlock_exit;

	dma_unmap_single(ab->dev, rx_tid->paddr, rx_tid->size,
			 DMA_BIDIRECTIONAL);
	kfree(rx_tid->vaddr);

	rx_tid->active = false;

unlock_exit:
	spin_unlock_bh(&ab->data_lock);
}

int ath11k_peer_rx_tid_setup(struct ath11k *ar, const u8 *peer_mac, int vdev_id,
			     u8 tid, u32 ba_win_sz, u16 ssn,
			     enum hal_pn_type pn_type)
{
	struct ath11k_base *ab = ar->ab;
	struct ath11k_peer *peer;
	struct dp_rx_tid *rx_tid;
	u32 hw_desc_sz;
	u32 *addr_aligned;
	void *vaddr;
	dma_addr_t paddr;
	int ret;

	spin_lock_bh(&ab->data_lock);

	peer = ath11k_peer_find(ab, vdev_id, peer_mac);
	if (!peer) {
		ath11k_warn(ab, "failed to find the peer to set up rx tid\n");
		spin_unlock_bh(&ab->data_lock);
		return -ENOENT;
	}

	rx_tid = &peer->rx_tid[tid];
	/* Update the tid queue if it is already setup */
	if (rx_tid->active) {
		paddr = rx_tid->paddr;
		ret = ath11k_peer_rx_tid_reo_update(ar, peer, rx_tid,
						    ba_win_sz, ssn);
		spin_unlock_bh(&ab->data_lock);
		if (ret) {
			ath11k_warn(ab, "failed to udpate reo for rx tid %d\n", tid);
			return ret;
		}

		ret = ath11k_wmi_peer_rx_reorder_queue_setup(ar, vdev_id,
							     peer_mac, paddr,
							     tid, 1, ba_win_sz);
		if (ret)
			ath11k_warn(ab, "failed to send wmi command to update rx reorder queue, tid :%d (%d)\n",
				    tid, ret);
		return ret;
	}

	rx_tid->tid = tid;

	rx_tid->ba_win_sz = ba_win_sz;
	hw_desc_sz = ath11k_hal_reo_qdesc_size(ba_win_sz, tid);
	vaddr = kzalloc(hw_desc_sz + HAL_LINK_DESC_ALIGN - 1, GFP_KERNEL);
	if (!vaddr) {
		spin_unlock_bh(&ab->data_lock);
		return -ENOMEM;
	}

	addr_aligned = PTR_ALIGN(vaddr, HAL_LINK_DESC_ALIGN);

	ath11k_hal_reo_qdesc_setup(addr_aligned, tid, ba_win_sz,
				   ssn, pn_type);

	paddr = dma_map_single(ab->dev, addr_aligned, hw_desc_sz,
			       DMA_BIDIRECTIONAL);

	ret = dma_mapping_error(ab->dev, paddr);
	if (ret) {
		spin_unlock_bh(&ab->data_lock);
		goto err_mem_free;
	}

	rx_tid->vaddr = vaddr;
	rx_tid->paddr = paddr;
	rx_tid->size = hw_desc_sz;
	rx_tid->active = true;

	spin_unlock_bh(&ab->data_lock);

	ret = ath11k_wmi_peer_rx_reorder_queue_setup(ar, vdev_id, peer_mac,
						     paddr, tid, 1, ba_win_sz);
	if (ret) {
		ath11k_warn(ar->ab, "failed to setup rx reorder queue, tid :%d (%d)\n",
			    tid, ret);
		ath11k_dp_rx_tid_mem_free(ab, peer_mac, vdev_id, tid);
	}

	return ret;

err_mem_free:
	kfree(vaddr);

	return ret;
}

int ath11k_dp_rx_ampdu_start(struct ath11k *ar,
			     struct ieee80211_ampdu_params *params)
{
	struct ath11k_base *ab = ar->ab;
	struct ath11k_sta *arsta = (void *)params->sta->drv_priv;
	int vdev_id = arsta->arvif->vdev_id;
	int ret;

	ret = ath11k_peer_rx_tid_setup(ar, params->sta->addr, vdev_id,
				       params->tid, params->buf_size,
				       params->ssn, arsta->pn_type);
	if (ret)
		ath11k_warn(ab, "failed to setup rx tid %d\n", ret);

	return ret;
}

int ath11k_dp_rx_ampdu_stop(struct ath11k *ar,
			    struct ieee80211_ampdu_params *params)
{
	struct ath11k_base *ab = ar->ab;
	struct ath11k_peer *peer;
	struct ath11k_sta *arsta = (void *)params->sta->drv_priv;
	int vdev_id = arsta->arvif->vdev_id;
	dma_addr_t paddr;
	bool active;
	int ret;

	spin_lock_bh(&ab->data_lock);

	peer = ath11k_peer_find(ab, vdev_id, params->sta->addr);
	if (!peer) {
		ath11k_warn(ab, "failed to find the peer to stop rx aggregation\n");
		spin_unlock_bh(&ab->data_lock);
		return -ENOENT;
	}

	paddr = peer->rx_tid[params->tid].paddr;
	active = peer->rx_tid[params->tid].active;

	ath11k_peer_rx_tid_delete(ar, peer, params->tid);

	spin_unlock_bh(&ab->data_lock);

	if (!active)
		return 0;

	ret = ath11k_wmi_peer_rx_reorder_queue_setup(ar, vdev_id,
						     params->sta->addr, paddr,
						     params->tid, 1, 1);
	if (ret)
		ath11k_warn(ab, "failed to send wmi to delete rx tid %d\n",
			    ret);

	return ret;
}

int ath11k_dp_peer_rx_pn_replay_config(struct ath11k_vif *arvif,
				       const u8 *peer_addr,
				       enum set_key_cmd key_cmd,
				       struct ieee80211_key_conf *key)
{
	struct ath11k *ar = arvif->ar;
	struct ath11k_base *ab = ar->ab;
	struct ath11k_hal_reo_cmd cmd = {0};
	struct ath11k_peer *peer;
	struct dp_rx_tid *rx_tid;
	u8 tid;
	int ret = 0;

	/* NOTE: Enable PN/TSC replay check offload only for unicast frames.
	 * We use mac80211 PN/TSC replay check functionality for bcast/mcast
	 * for now.
	 */
	if (!(key->flags & IEEE80211_KEY_FLAG_PAIRWISE))
		return 0;

	cmd.flag |= HAL_REO_CMD_FLG_NEED_STATUS;
	cmd.upd0 |= HAL_REO_CMD_UPD0_PN |
		    HAL_REO_CMD_UPD0_PN_SIZE |
		    HAL_REO_CMD_UPD0_SVLD;

	switch (key->cipher) {
	case WLAN_CIPHER_SUITE_TKIP:
	case WLAN_CIPHER_SUITE_CCMP:
	case WLAN_CIPHER_SUITE_CCMP_256:
	case WLAN_CIPHER_SUITE_GCMP:
	case WLAN_CIPHER_SUITE_GCMP_256:
		if (key_cmd == SET_KEY) {
			cmd.upd0 |= HAL_REO_CMD_UPD0_PN_CHECK;
			cmd.pn_size = 48;
		}
		break;
	default:
		break;
	}

	spin_lock_bh(&ab->data_lock);

	peer = ath11k_peer_find(ab, arvif->vdev_id, peer_addr);
	if (!peer) {
		ath11k_warn(ab, "failed to find the peer to configure pn replay detection\n");
		spin_unlock_bh(&ab->data_lock);
		return -ENOENT;
	}

	for (tid = 0; tid <= IEEE80211_NUM_TIDS; tid++) {
		rx_tid = &peer->rx_tid[tid];
		if (!rx_tid->active)
			continue;
		cmd.addr_lo = lower_32_bits(rx_tid->paddr);
		cmd.addr_hi = upper_32_bits(rx_tid->paddr);
		ret = ath11k_dp_send_reo_cmd(ab, rx_tid,
					     HAL_REO_CMD_UPDATE_RX_QUEUE,
					     &cmd, NULL);
		if (ret) {
			ath11k_warn(ab, "failed to configure rx tid %d queue for pn replay detection %d\n",
				    tid, ret);
			break;
		}
	}

	spin_unlock_bh(&ar->ab->data_lock);

	return ret;
}

static inline int ath11k_get_ppdu_user_index(struct htt_ppdu_stats *ppdu_stats,
					      u16 peer_id)
{
	int i;

	for (i = 0; i < HTT_PPDU_STATS_MAX_USERS - 1; i++) {
		if (ppdu_stats->user_stats[i].is_valid_peer_id) {
			if (peer_id == ppdu_stats->user_stats[i].peer_id)
				return i;
		} else {
			return i;
		}
	}

	return -EINVAL;
}

static int ath11k_htt_tlv_ppdu_stats_parse(struct ath11k_base *ab,
					   u16 tag, u16 len, const void *ptr,
					   void *data)
{
	struct htt_ppdu_stats_info *ppdu_info;
	struct htt_ppdu_user_stats *user_stats;
	int cur_user;
	u16 peer_id;

	ppdu_info = (struct htt_ppdu_stats_info *)data;

	switch (tag) {
	case HTT_PPDU_STATS_TAG_COMMON:
		if (len < sizeof(struct htt_ppdu_stats_common)) {
			ath11k_warn(ab, "Invalid len %d for the tag 0x%x\n",
				    len, tag);
			return -EINVAL;
		}
		memcpy((void *)&ppdu_info->ppdu_stats.common, ptr,
		       sizeof(struct htt_ppdu_stats_common));
		break;
	case HTT_PPDU_STATS_TAG_USR_RATE:
		if (len < sizeof(struct htt_ppdu_stats_user_rate)) {
			ath11k_warn(ab, "Invalid len %d for the tag 0x%x\n",
				    len, tag);
			return -EINVAL;
		}

		peer_id = ((struct htt_ppdu_stats_user_rate *)ptr)->sw_peer_id;
		cur_user = ath11k_get_ppdu_user_index(&ppdu_info->ppdu_stats,
						      peer_id);
		if (cur_user < 0)
			return -EINVAL;
		user_stats = &ppdu_info->ppdu_stats.user_stats[cur_user];
		user_stats->peer_id = peer_id;
		user_stats->is_valid_peer_id = true;
		memcpy((void *)&user_stats->rate, ptr,
		       sizeof(struct htt_ppdu_stats_user_rate));
		user_stats->tlv_flags |= BIT(tag);
		break;
	case HTT_PPDU_STATS_TAG_USR_COMPLTN_COMMON:
		if (len < sizeof(struct htt_ppdu_stats_usr_cmpltn_cmn)) {
			ath11k_warn(ab, "Invalid len %d for the tag 0x%x\n",
				    len, tag);
			return -EINVAL;
		}

		peer_id = ((struct htt_ppdu_stats_usr_cmpltn_cmn *)ptr)->sw_peer_id;
		cur_user = ath11k_get_ppdu_user_index(&ppdu_info->ppdu_stats,
						      peer_id);
		if (cur_user < 0)
			return -EINVAL;
		user_stats = &ppdu_info->ppdu_stats.user_stats[cur_user];
		user_stats->peer_id = peer_id;
		user_stats->is_valid_peer_id = true;
		memcpy((void *)&user_stats->cmpltn_cmn, ptr,
		       sizeof(struct htt_ppdu_stats_usr_cmpltn_cmn));
		user_stats->tlv_flags |= BIT(tag);
		break;
	case HTT_PPDU_STATS_TAG_USR_COMPLTN_ACK_BA_STATUS:
		if (len <
		    sizeof(struct htt_ppdu_stats_usr_cmpltn_ack_ba_status)) {
			ath11k_warn(ab, "Invalid len %d for the tag 0x%x\n",
				    len, tag);
			return -EINVAL;
		}

		peer_id =
		((struct htt_ppdu_stats_usr_cmpltn_ack_ba_status *)ptr)->sw_peer_id;
		cur_user = ath11k_get_ppdu_user_index(&ppdu_info->ppdu_stats,
						      peer_id);
		if (cur_user < 0)
			return -EINVAL;
		user_stats = &ppdu_info->ppdu_stats.user_stats[cur_user];
		user_stats->peer_id = peer_id;
		user_stats->is_valid_peer_id = true;
		memcpy((void *)&user_stats->ack_ba, ptr,
		       sizeof(struct htt_ppdu_stats_usr_cmpltn_ack_ba_status));
		user_stats->tlv_flags |= BIT(tag);
		break;
	}
	return 0;
}

int ath11k_dp_htt_tlv_iter(struct ath11k_base *ab, const void *ptr, size_t len,
			   int (*iter)(struct ath11k_base *ar, u16 tag, u16 len,
				       const void *ptr, void *data),
			   void *data)
{
	const struct htt_tlv *tlv;
	const void *begin = ptr;
	u16 tlv_tag, tlv_len;
	int ret = -EINVAL;

	while(len > 0) {
		if (len < sizeof(*tlv)) {
			ath11k_err(ab, "htt tlv parse failure at byte %zd (%zu bytes left, %zu expected)\n",
				   ptr - begin, len, sizeof(*tlv));
			return -EINVAL;
		}
		tlv = (struct htt_tlv *)ptr;
		tlv_tag = FIELD_GET(HTT_TLV_TAG, tlv->header);
		tlv_len = FIELD_GET(HTT_TLV_LEN, tlv->header);
		ptr += sizeof(*tlv);
		len -= sizeof(*tlv);

		if (tlv_len > len) {
			ath11k_err(ab, "htt tlv parse failure of tag %hhu at byte %zd (%zu bytes left, %hhu expected)\n",
				   tlv_tag, ptr - begin, len, tlv_len);
			return -EINVAL;
		}
		ret = iter(ab, tlv_tag, tlv_len, ptr, data);
		if (ret == -ENOMEM)
			return ret;

		ptr += tlv_len;
		len -= tlv_len;
	}
	return 0;
}

static inline u8 ath11k_bw_to_mac80211_bw(u8 bw)
{
	u8 ret = 0;

	switch (bw) {
	case ATH11K_BW_20:
		ret = RATE_INFO_BW_20;
		break;
	case ATH11K_BW_40:
		ret = RATE_INFO_BW_40;
		break;
	case ATH11K_BW_80:
		ret = RATE_INFO_BW_80;
		break;
	case ATH11K_BW_160:
		ret = RATE_INFO_BW_160;
		break;
	}

	return ret;
}

static inline u32 ath11k_bw_to_mac80211_bwflags(u8 bw)
{
	u32 bwflags = 0;

	switch (bw) {
	case ATH11K_BW_40:
		bwflags = IEEE80211_TX_RC_40_MHZ_WIDTH;
		break;
	case ATH11K_BW_80:
		bwflags = IEEE80211_TX_RC_80_MHZ_WIDTH;
		break;
	case ATH11K_BW_160:
		bwflags = IEEE80211_TX_RC_160_MHZ_WIDTH;
		break;
	}

	return bwflags;
}

static void
ath11k_update_per_peer_tx_stats(struct ath11k *ar,
				struct htt_ppdu_user_stats *usr_stats)
{
	struct ath11k_base *ab = ar->ab;
	struct ath11k_peer *peer;
	struct ieee80211_sta *sta;
	struct ath11k_sta *arsta;
	struct htt_ppdu_stats_user_rate *user_rate;
	struct ieee80211_chanctx_conf *conf = NULL;
	struct ath11k_per_peer_tx_stats *peer_stats = &ar->peer_tx_stats;
	enum  htt_ppdu_stats_usr_compln_status status;
	int ret;
	u8 flags, mcs, nss, bw, sgi, rate_idx = 0;
	u32 succ_bytes = 0;
	u16 succ_mpdus = 0, rate = 0, succ_pkts = 0;
	bool is_ampdu = false;

	if (!usr_stats)
		return;

	if (!(usr_stats->tlv_flags & BIT(HTT_PPDU_STATS_TAG_USR_RATE)))
		return;

	if (usr_stats->tlv_flags & BIT(HTT_PPDU_STATS_TAG_USR_COMPLTN_COMMON))
		succ_mpdus = usr_stats->cmpltn_cmn.mpdu_success;

	status = HTT_PPDU_STATS_USER_STATUS_INVALID;
	if (usr_stats->tlv_flags & BIT(HTT_PPDU_STATS_TAG_USR_COMPLTN_COMMON)) {
		is_ampdu =
			HTT_USR_CMPLTN_IS_AMPDU(usr_stats->cmpltn_cmn.flags);
		status = usr_stats->cmpltn_cmn.status;
	}

	if (usr_stats->tlv_flags &
	    BIT(HTT_PPDU_STATS_TAG_USR_COMPLTN_ACK_BA_STATUS)) {
		succ_bytes = usr_stats->ack_ba.success_bytes;
		succ_pkts = FIELD_GET(HTT_PPDU_STATS_ACK_BA_INFO_NUM_MSDU_M,
				      usr_stats->ack_ba.info);
	}

	user_rate = &usr_stats->rate;
	flags = HTT_USR_RATE_PREAMBLE(user_rate->rate_flags);
	bw = HTT_USR_RATE_BW(user_rate->rate_flags) - 2;
	nss = HTT_USR_RATE_NSS(user_rate->rate_flags) + 1;
	mcs = HTT_USR_RATE_MCS(user_rate->rate_flags);
	sgi = HTT_USR_RATE_GI(user_rate->rate_flags);

        /* Note: If host configured fixed rates and in some other special
	 * cases, the broadcast/management frames are sent in different rates.
	 * Firmare rate's control to be skipped for this?
         */

	if (flags == WMI_RATE_PREAMBLE_VHT && mcs > 9) {
		ath11k_warn(ab, "Invalid VHT mcs %hhd peer stats",  mcs);
		return;
	}

	if (flags == WMI_RATE_PREAMBLE_HT && (mcs > 7 || nss < 1)) {
		ath11k_warn(ab, "Invalid HT mcs %hhd nss %hhd peer stats",
			    mcs, nss);
		return;
	}

	if (flags == WMI_RATE_PREAMBLE_CCK || flags == WMI_RATE_PREAMBLE_OFDM) {
		ret = ath11k_mac_hw_ratecode_to_legacy_rate(mcs,
							    flags,
							    &rate_idx,
							    &rate);
		if (ret < 0)
			return;
	}

	rcu_read_lock();
	spin_lock_bh(&ab->data_lock);
	peer = ath11k_peer_find_by_id(ab, usr_stats->peer_id);

	if (!peer || !peer->sta) {
		spin_unlock_bh(&ab->data_lock);
		rcu_read_unlock();
		return;
	}

	sta = peer->sta;
	arsta = (struct ath11k_sta *)sta->drv_priv;

	memset(&arsta->txrate, 0, sizeof(arsta->txrate));

	switch (flags) {
	case WMI_RATE_PREAMBLE_OFDM:
		arsta->txrate.legacy = rate;
		if (arsta->arvif && arsta->arvif->vif)
			conf = rcu_dereference(arsta->arvif->vif->chanctx_conf);
		if (conf && conf->def.chan->band == NL80211_BAND_5GHZ)
			arsta->tx_info.status.rates[0].idx = rate_idx - 4;
		break;
	case WMI_RATE_PREAMBLE_CCK:
		arsta->txrate.legacy = rate;
		arsta->tx_info.status.rates[0].idx = rate_idx;
		if (mcs > ATH11K_HW_RATE_CCK_LP_1M &&
		    mcs <= ATH11K_HW_RATE_CCK_SP_2M)
			arsta->tx_info.status.rates[0].flags |=
					IEEE80211_TX_RC_USE_SHORT_PREAMBLE;
		break;
	case WMI_RATE_PREAMBLE_HT:
		arsta->txrate.mcs = mcs + 8 * (nss - 1);
		arsta->tx_info.status.rates[0].idx = arsta->txrate.mcs;
		arsta->txrate.flags = RATE_INFO_FLAGS_MCS;
		arsta->tx_info.status.rates[0].flags |= IEEE80211_TX_RC_MCS;
		if (sgi) {
			arsta->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
			arsta->tx_info.status.rates[0].flags |=
					IEEE80211_TX_RC_SHORT_GI;
		}
		break;
	case WMI_RATE_PREAMBLE_VHT:
		arsta->txrate.mcs = mcs;
		ieee80211_rate_set_vht(&arsta->tx_info.status.rates[0], mcs, nss);
		if (sgi) {
			arsta->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
			arsta->tx_info.status.rates[0].flags |=
						IEEE80211_TX_RC_SHORT_GI;
		}
		arsta->txrate.flags = RATE_INFO_FLAGS_VHT_MCS;
		arsta->tx_info.status.rates[0].flags |= IEEE80211_TX_RC_VHT_MCS;
		break;
	}

	arsta->txrate.nss = nss;
	arsta->txrate.bw = bw;
	arsta->tx_info.status.rates[0].flags |= ath11k_bw_to_mac80211_bwflags(bw);

	memcpy(&arsta->last_txrate, &arsta->txrate, sizeof(struct rate_info));

	if (succ_mpdus) {
		arsta->tx_info.flags = IEEE80211_TX_STAT_ACK;
		arsta->tx_info.status.rates[0].count = 1;
		ieee80211_tx_rate_update(ar->hw, sta, &arsta->tx_info);
	}

	memset(peer_stats, 0, sizeof(*peer_stats));

	peer_stats->succ_pkts = succ_pkts;
	peer_stats->succ_bytes = succ_bytes;
	peer_stats->is_ampdu = is_ampdu;
	peer_stats->status = status;

	if (ath11k_debug_is_extd_tx_stats_enabled(ar))
		ath11k_accumulate_per_peer_tx_stats(arsta,
						    peer_stats, rate_idx);

	spin_unlock_bh(&ab->data_lock);
	rcu_read_unlock();
}

static void ath11k_htt_update_ppdu_stats(struct ath11k *ar,
					 struct htt_ppdu_stats *ppdu_stats)
{
	struct htt_ppdu_user_stats *usr_stats;
	u8 user;

	for (user = 0; user < HTT_PPDU_STATS_MAX_USERS - 1; user++) {
		usr_stats = &ppdu_stats->user_stats[user];
		ath11k_update_per_peer_tx_stats(ar, usr_stats);
	}
}

static
struct htt_ppdu_stats_info *ath11k_dp_htt_get_ppdu_desc(struct ath11k *ar,
							u32 ppdu_id)
{
	struct htt_ppdu_stats_info *ppdu_info = NULL;

	if (!list_empty(&ar->ppdu_stats_info)) {
		list_for_each_entry(ppdu_info, &ar->ppdu_stats_info, list) {
			if (ppdu_info && ppdu_info->ppdu_id == ppdu_id)
				return ppdu_info;
		}

		if (ar->ppdu_stat_list_depth > HTT_PPDU_DESC_MAX_DEPTH) {
			ppdu_info = list_first_entry(&ar->ppdu_stats_info,
						     typeof(*ppdu_info), list);
			list_del(&ppdu_info->list);
			ar->ppdu_stat_list_depth--;
			ath11k_htt_update_ppdu_stats(ar, &ppdu_info->ppdu_stats);
			kfree(ppdu_info);
		}
	}

	ppdu_info = kzalloc(sizeof(*ppdu_info), GFP_KERNEL);
	if (!ppdu_info)
		return NULL;

	list_add_tail(&ppdu_info->list, &ar->ppdu_stats_info);
	ar->ppdu_stat_list_depth++;

	return ppdu_info;
}

static int ath11k_htt_pull_ppdu_stats(struct ath11k_base *ab,
					 struct sk_buff *skb) {
	u8 *data = (u8 *)skb->data;
	struct htt_ppdu_stats_info *ppdu_info;
	struct ath11k *ar;
	int ret;
	u8 pdev_id;
	u32 ppdu_id, len;

	len = FIELD_GET(HTT_T2H_PPDU_STATS_PAYLOAD_SIZE_M, *(u32 *)data);
	pdev_id = FIELD_GET(HTT_T2H_PPDU_STATS_PDEV_ID_M, *(u32 *)data);
	pdev_id = DP_HW2SW_MACID(pdev_id);
	ppdu_id = *((u32 *)data + 1);

	ar = ab->pdevs[pdev_id].ar;

	/* TLV info starts after 16bytes of header */
	data = (u8 *)data + 16;

	ppdu_info = ath11k_dp_htt_get_ppdu_desc(ar, ppdu_id);
	if (!ppdu_info)
		return 0;

	ppdu_info->ppdu_id = ppdu_id;
	ret = ath11k_dp_htt_tlv_iter(ab, data, len,
				     ath11k_htt_tlv_ppdu_stats_parse,
				     (void *)ppdu_info);
	if (ret) {
		ath11k_warn(ab, "Failed to parse tlv %d\n", ret);
		return ret;
	}

	return 0;
}


void ath11k_dp_htt_htc_t2h_msg_handler(struct ath11k_base *ab,
				       struct sk_buff *skb)
{
	struct ath11k_dp *dp = &ab->dp;
	struct htt_resp_msg *resp = (struct htt_resp_msg *)skb->data;
	enum htt_t2h_msg_type type = FIELD_GET(HTT_T2H_MSG_TYPE, *(u32 *)resp);
	u16 peer_id;
	u8 vdev_id;
	u8 mac_addr[ETH_ALEN];
	u16 peer_mac_h16;
	u16 ast_hash;

	ath11k_dbg(ab, ATH11K_DBG_DP_HTT, "dp_htt rx msg type :0x%0x\n", type);

	switch (type) {
	case HTT_T2H_MSG_TYPE_VERSION_CONF:
		dp->htt_tgt_ver_major = FIELD_GET(HTT_T2H_VERSION_CONF_MAJOR,
						  resp->version_msg.version);
		dp->htt_tgt_ver_minor = FIELD_GET(HTT_T2H_VERSION_CONF_MINOR,
						  resp->version_msg.version);
		complete(&dp->htt_tgt_version_received);
		break;
	case HTT_T2H_MSG_TYPE_PEER_MAP:
		vdev_id = FIELD_GET(HTT_T2H_PEER_MAP_INFO_VDEV_ID,
				    resp->peer_map_ev.info);
		peer_id = FIELD_GET(HTT_T2H_PEER_MAP_INFO_PEER_ID,
				    resp->peer_map_ev.info);
		peer_mac_h16 = FIELD_GET(HTT_T2H_PEER_MAP_INFO1_MAC_ADDR_H16,
					 resp->peer_map_ev.info1);
		dp_peer_map_get_mac_addr(resp->peer_map_ev.mac_addr_l32,
					 peer_mac_h16, mac_addr);
		ast_hash = FIELD_GET(HTT_T2H_PEER_MAP_INFO2_AST_HASH_VAL,
				     resp->peer_map_ev.info1);
		ath11k_peer_map_event(ab, vdev_id, peer_id, mac_addr, ast_hash);
		break;
	case HTT_T2H_MSG_TYPE_PEER_UNMAP:
		peer_id = FIELD_GET(HTT_T2H_PEER_UNMAP_INFO_PEER_ID,
				    resp->peer_unmap_ev.info);
		ath11k_peer_unmap_event(ab, peer_id);
		break;
	case HTT_T2H_MSG_TYPE_PPDU_STATS_IND:
		ath11k_htt_pull_ppdu_stats(ab, skb);
		break;
	case HTT_T2H_MSG_TYPE_EXT_STATS_CONF:
		ath11k_dbg_htt_ext_stats_handler(ab, skb);
	default:
		ath11k_warn(ab, "htt event %d not handled\n", type);
		break;
	}

	dev_kfree_skb_any(skb);
}

static int ath11k_dp_rx_msdu_coalesce(struct ath11k *ar,
				      struct sk_buff_head *msdu_list,
				      struct sk_buff *first, int msdu_len)
{
	struct sk_buff *skb;
	struct ath11k_skb_rxcb *rxcb = ATH11K_SKB_RXCB(first);
	u8 l3pad_bytes = ath11k_dp_rx_h_msdu_end_l3pad(first->data);
	int space_extra;
	int rem_len;
	int buf_len;

	if (rxcb->is_first_msdu && rxcb->is_last_msdu) {
		skb_put(first, HAL_RX_DESC_SIZE + l3pad_bytes + msdu_len);
		skb_pull(first, HAL_RX_DESC_SIZE + l3pad_bytes);
		return 0;
	}

	if (WARN_ON_ONCE(msdu_len <= (DP_RX_BUFFER_SIZE -
			 (HAL_RX_DESC_SIZE + l3pad_bytes))))
		return 0;

	rxcb->is_first_msdu = ath11k_dp_rx_h_msdu_end_first_msdu(first->data);
	rxcb->is_last_msdu = ath11k_dp_rx_h_msdu_end_last_msdu(first->data);

	/* MSDU spans over multiple buffers because the length of the MSDU
	 * exceeds DP_RX_BUFFER_SIZE - HAL_RX_DESC_SIZE. So assume the data
	 * in the first buf is of length DP_RX_BUFFER_SIZE - HAL_RX_DESC_SIZE.
	 */
	skb_put(first, DP_RX_BUFFER_SIZE);
	skb_pull(first, HAL_RX_DESC_SIZE + l3pad_bytes);

	space_extra = msdu_len - (DP_RX_BUFFER_SIZE + skb_tailroom(first));
	if (space_extra > 0 &&
	    (pskb_expand_head(first, 0, space_extra, GFP_ATOMIC) < 0)) {
		/* Free up all buffers of the MSDU */
		while ((skb = __skb_dequeue(msdu_list)) != NULL) {
			rxcb = ATH11K_SKB_RXCB(skb);
			if (!rxcb->is_continuation) {
				dev_kfree_skb_any(skb);
				break;
			}
			dev_kfree_skb_any(skb);
		}
		return -ENOMEM;
	}

	rem_len = msdu_len -
		  (DP_RX_BUFFER_SIZE - HAL_RX_DESC_SIZE - l3pad_bytes);
	while ((skb = __skb_dequeue(msdu_list)) != NULL && rem_len > 0) {
		if (!ath11k_dp_rx_h_attn_msdu_done(skb->data)) {
			ath11k_warn(ar->ab, "msdu_done bit in attention is not set\n");
			dev_kfree_skb_any(skb);
			return -EIO;
		}

		rxcb = ATH11K_SKB_RXCB(skb);
		if (rxcb->is_continuation)
			buf_len = DP_RX_BUFFER_SIZE - HAL_RX_DESC_SIZE;
		else
			buf_len = rem_len;

		if (buf_len > (DP_RX_BUFFER_SIZE - HAL_RX_DESC_SIZE)) {
			WARN_ON_ONCE(1);
			dev_kfree_skb_any(skb);
			return -EINVAL;
		}

		skb_put(skb, buf_len + HAL_RX_DESC_SIZE);
		skb_pull(skb, HAL_RX_DESC_SIZE);
		skb_copy_from_linear_data(skb, skb_put(first, buf_len),
					  buf_len);
		dev_kfree_skb_any(skb);

		rem_len -= buf_len;
		if (!rxcb->is_continuation)
			break;
	}

	return 0;
}

static int ath11k_dp_rx_retrieve_amsdu(struct ath11k *ar,
				       struct sk_buff_head *msdu_list,
				       struct sk_buff_head *amsdu_list)
{
	struct sk_buff *msdu = skb_peek(msdu_list);
	struct ath11k_skb_rxcb *rxcb;
	struct ieee80211_hdr *hdr;
	u16 msdu_len;
	u8 l3_pad_bytes;
	u8 *hdr_status, *desc;
	int ret;

	if (!msdu)
		return -ENOENT;

	do {
		desc = msdu->data;
		if (!ath11k_dp_rx_h_attn_msdu_done(desc)) {
			ath11k_warn(ar->ab, "msdu_done bit in attention is not set\n");
			__skb_queue_purge(amsdu_list);
			return -EIO;
		}

		hdr_status = ath11k_dp_rx_h_80211_hdr(desc);
		hdr = (struct ieee80211_hdr *)hdr_status;

		/* Process only data frames */
		if (!ieee80211_is_data(hdr->frame_control)) {
			__skb_queue_purge(amsdu_list);
			return 0;
		}

		rxcb = ATH11K_SKB_RXCB(msdu);
		rxcb->rx_desc = msdu->data;
		msdu_len = ath11k_dp_rx_h_msdu_start_msdu_len(msdu->data);
		__skb_unlink(msdu, msdu_list);

		if (!rxcb->is_continuation) {
			l3_pad_bytes = ath11k_dp_rx_h_msdu_end_l3pad(msdu->data);
			skb_put(msdu, HAL_RX_DESC_SIZE + l3_pad_bytes + msdu_len);
			skb_pull(msdu, HAL_RX_DESC_SIZE + l3_pad_bytes);
		} else {
			ret = ath11k_dp_rx_msdu_coalesce(ar, msdu_list,
							 msdu, msdu_len);
			if (ret) {
				ath11k_warn(ar->ab, "failed to coalesce msdu rx buffer%d\n", ret);
				dev_kfree_skb_any(msdu);
				__skb_queue_purge(amsdu_list);
				return ret;
			}
		}
		__skb_queue_tail(amsdu_list, msdu);

		/* Should we also consider msdu_cnt from mpdu_meta while
		 * preparing amsdu list?
		 */
		if (rxcb->is_last_msdu)
			break;
	} while ((msdu = skb_peek(msdu_list)) != NULL);

	return 0;
}

static void ath11k_dp_rx_h_csum_offload(struct sk_buff *msdu)
{
	struct ath11k_skb_rxcb *rxcb = ATH11K_SKB_RXCB(msdu);
	bool ip_csum_fail, l4_csum_fail;

	ip_csum_fail = ath11k_dp_rx_h_attn_ip_cksum_fail(rxcb->rx_desc);
	l4_csum_fail = ath11k_dp_rx_h_attn_l4_cksum_fail(rxcb->rx_desc);

	msdu->ip_summed = (ip_csum_fail || l4_csum_fail) ?
			  CHECKSUM_NONE : CHECKSUM_UNNECESSARY;
}

static int ath11k_dp_rx_crypto_mic_len(struct ath11k *ar,
				       enum hal_encrypt_type enctype)
{
	switch (enctype) {
	case HAL_ENCRYPT_TYPE_OPEN:
	case HAL_ENCRYPT_TYPE_WEP_40:
	case HAL_ENCRYPT_TYPE_WEP_104:
	case HAL_ENCRYPT_TYPE_TKIP_NO_MIC:
	case HAL_ENCRYPT_TYPE_TKIP_MIC:
		return 0;
	case HAL_ENCRYPT_TYPE_CCMP_128:
		return IEEE80211_CCMP_MIC_LEN;
	case HAL_ENCRYPT_TYPE_CCMP_256:
		return IEEE80211_CCMP_256_MIC_LEN;
	case HAL_ENCRYPT_TYPE_GCMP_128:
	case HAL_ENCRYPT_TYPE_AES_GCMP_256:
		return IEEE80211_GCMP_MIC_LEN;
	case HAL_ENCRYPT_TYPE_WEP_128:
	case HAL_ENCRYPT_TYPE_WAPI_GCM_SM4:
	case HAL_ENCRYPT_TYPE_WAPI:
		break;
	}

	ath11k_warn(ar->ab, "unsupported encryption type %d for mic len\n", enctype);
	return 0;
}

static int ath11k_dp_rx_crypto_param_len(struct ath11k *ar,
					 enum hal_encrypt_type enctype)
{
	switch (enctype) {
	case HAL_ENCRYPT_TYPE_OPEN:
		return 0;
	case HAL_ENCRYPT_TYPE_WEP_40:
	case HAL_ENCRYPT_TYPE_WEP_104:
		return IEEE80211_WEP_IV_LEN;
	case HAL_ENCRYPT_TYPE_TKIP_NO_MIC:
	case HAL_ENCRYPT_TYPE_TKIP_MIC:
		return IEEE80211_TKIP_IV_LEN;
	case HAL_ENCRYPT_TYPE_CCMP_128:
		return IEEE80211_CCMP_HDR_LEN;
	case HAL_ENCRYPT_TYPE_CCMP_256:
		return IEEE80211_CCMP_256_HDR_LEN;
	case HAL_ENCRYPT_TYPE_GCMP_128:
	case HAL_ENCRYPT_TYPE_AES_GCMP_256:
		return IEEE80211_GCMP_HDR_LEN;
	case HAL_ENCRYPT_TYPE_WEP_128:
	case HAL_ENCRYPT_TYPE_WAPI_GCM_SM4:
	case HAL_ENCRYPT_TYPE_WAPI:
		break;
	}

	ath11k_warn(ar->ab, "unsupported encryption type %d\n", enctype);
	return 0;
}

static int ath11k_dp_rx_crypto_icv_len(struct ath11k *ar,
				       enum hal_encrypt_type enctype)
{
	switch (enctype) {
	case HAL_ENCRYPT_TYPE_OPEN:
	case HAL_ENCRYPT_TYPE_CCMP_128:
	case HAL_ENCRYPT_TYPE_CCMP_256:
	case HAL_ENCRYPT_TYPE_GCMP_128:
	case HAL_ENCRYPT_TYPE_AES_GCMP_256:
		return 0;
	case HAL_ENCRYPT_TYPE_WEP_40:
	case HAL_ENCRYPT_TYPE_WEP_104:
		return IEEE80211_WEP_ICV_LEN;
	case HAL_ENCRYPT_TYPE_TKIP_NO_MIC:
	case HAL_ENCRYPT_TYPE_TKIP_MIC:
		return IEEE80211_TKIP_ICV_LEN;
	case HAL_ENCRYPT_TYPE_WEP_128:
	case HAL_ENCRYPT_TYPE_WAPI_GCM_SM4:
	case HAL_ENCRYPT_TYPE_WAPI:
		break;
	}

	ath11k_warn(ar->ab, "unsupported encryption type %d\n", enctype);
	return 0;
}

static void ath11k_dp_rx_h_undecap_nwifi(struct ath11k *ar,
					 struct sk_buff *msdu,
					 u8 *first_hdr,
					 enum hal_encrypt_type enctype,
					 struct ieee80211_rx_status *status)
{
	struct ieee80211_hdr *hdr;
	size_t hdr_len;
	u8 da[ETH_ALEN];
	u8 sa[ETH_ALEN];

	/* pull decapped header and copy SA & DA */
	hdr = (struct ieee80211_hdr *)msdu->data;
	ether_addr_copy(da, ieee80211_get_DA(hdr));
	ether_addr_copy(sa, ieee80211_get_SA(hdr));
	skb_pull(msdu, ieee80211_hdrlen(hdr->frame_control));

	/* push original 802.11 header */
	hdr = (struct ieee80211_hdr *)first_hdr;

	if (!(status->flag & RX_FLAG_IV_STRIPPED)) {
		memcpy(skb_push(msdu,
				ath11k_dp_rx_crypto_param_len(ar, enctype)),
		       hdr, ath11k_dp_rx_crypto_param_len(ar, enctype));
	}

	hdr_len = ieee80211_hdrlen(hdr->frame_control);
	memcpy(skb_push(msdu, hdr_len), hdr, hdr_len);

	/* original 802.11 header has a different DA and in
	 * case of 4addr it may also have different SA
	 */
	hdr = (struct ieee80211_hdr *)msdu->data;
	ether_addr_copy(ieee80211_get_DA(hdr), da);
	ether_addr_copy(ieee80211_get_SA(hdr), sa);
}

#define MICHAEL_MIC_LEN 8

static void ath11k_dp_rx_h_undecap_raw(struct ath11k *ar, struct sk_buff *msdu,
				       enum hal_encrypt_type enctype,
				       struct ieee80211_rx_status *status,
				       bool decrypted)
{
	struct ath11k_skb_rxcb *rxcb = ATH11K_SKB_RXCB(msdu);
	struct ieee80211_hdr *hdr;
	size_t hdr_len;
	size_t crypto_len;

	if (!rxcb->is_first_msdu ||
	    !(rxcb->is_first_msdu && rxcb->is_last_msdu)) {
		WARN_ON_ONCE(1);
		return;
	}

	skb_trim(msdu, msdu->len - FCS_LEN);

	if (!decrypted)
		return;

	hdr = (void *)msdu->data;

	/* Tail */
	if (status->flag & RX_FLAG_IV_STRIPPED) {
		skb_trim(msdu, msdu->len -
			 ath11k_dp_rx_crypto_mic_len(ar, enctype));

		skb_trim(msdu, msdu->len -
			 ath11k_dp_rx_crypto_icv_len(ar, enctype));
	} else {
		/* MIC */
		if (status->flag & RX_FLAG_MIC_STRIPPED)
			skb_trim(msdu, msdu->len -
				 ath11k_dp_rx_crypto_mic_len(ar, enctype));

		/* ICV */
		if (status->flag & RX_FLAG_ICV_STRIPPED)
			skb_trim(msdu, msdu->len -
				 ath11k_dp_rx_crypto_icv_len(ar, enctype));
	}

	/* MMIC */
	if ((status->flag & RX_FLAG_MMIC_STRIPPED) &&
	    !ieee80211_has_morefrags(hdr->frame_control) &&
	    enctype == HAL_ENCRYPT_TYPE_TKIP_MIC)
		skb_trim(msdu, msdu->len - MICHAEL_MIC_LEN);

	/* Head */
	if (status->flag & RX_FLAG_IV_STRIPPED) {
		hdr_len = ieee80211_hdrlen(hdr->frame_control);
		crypto_len = ath11k_dp_rx_crypto_param_len(ar, enctype);

		memmove((void *)msdu->data + crypto_len,
			(void *)msdu->data, hdr_len);
		skb_pull(msdu, crypto_len);
	}
}

static void ath11k_dp_rx_h_undecap(struct ath11k *ar, struct sk_buff *msdu,
				   u8 *first_hdr, enum hal_encrypt_type enctype,
				   struct ieee80211_rx_status *status,
				   bool decrypted)
{
	struct ath11k_skb_rxcb *rxcb = ATH11K_SKB_RXCB(msdu);
	u8 decap;

	decap = ath11k_dp_rx_h_mpdu_start_decap_type(rxcb->rx_desc);

	switch (decap) {
	case DP_RX_DECAP_TYPE_NATIVE_WIFI:
		ath11k_dp_rx_h_undecap_nwifi(ar, msdu, first_hdr,
					     enctype, status);
		break;
	case DP_RX_DECAP_TYPE_RAW:
		ath11k_dp_rx_h_undecap_raw(ar, msdu, enctype, status,
					   decrypted);
		break;
	case DP_RX_DECAP_TYPE_ETHERNET2_DIX:
	case DP_RX_DECAP_TYPE_8023:
		/* TODO: Handle undecap for these formats */
		break;
	}
}

static void ath11k_dp_rx_h_mpdu(struct ath11k *ar,
				struct sk_buff_head *amsdu_list,
				u8 *rx_desc,
				struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_hdr *hdr;
	enum hal_encrypt_type enctype;
	struct sk_buff *last_msdu;
	struct sk_buff *msdu;
	struct ath11k_skb_rxcb *last_rxcb;
	bool is_decrypted, fill_crypto_hdr;
	u32 err_bitmap;
	u8 *qos, *hdr_status;

	if (skb_queue_empty(amsdu_list))
		return;

	hdr_status = ath11k_dp_rx_h_80211_hdr(rx_desc);
	hdr = (struct ieee80211_hdr *)hdr_status;

	/* Each A-MSDU subframe will use the original header as the base and be
	 * reported as a separate MSDU so strip the A-MSDU bit from QoS Ctl.
	 */
	if (ieee80211_is_data_qos(hdr->frame_control)) {
		qos = ieee80211_get_qos_ctl(hdr);
		qos[0] &= ~IEEE80211_QOS_CTL_A_MSDU_PRESENT;
	}

	is_decrypted = ath11k_dp_rx_h_attn_is_decrypted(rx_desc);
	enctype = ath11k_dp_rx_h_mpdu_start_enctype(rx_desc);

	/* Some attention flags are valid only in the last MSDU. */
	last_msdu = skb_peek_tail(amsdu_list);
	last_rxcb = ATH11K_SKB_RXCB(last_msdu);

	err_bitmap = ath11k_dp_rx_h_attn_mpdu_err(last_rxcb->rx_desc);
	fill_crypto_hdr = !ath11k_dp_rx_h_mpdu_end_pn_valid(last_rxcb->rx_desc);

	/* Clear per-MPDU flags while leaving per-PPDU flags intact. */
	rx_status->flag &= ~(RX_FLAG_FAILED_FCS_CRC |
			     RX_FLAG_MMIC_ERROR |
			     RX_FLAG_DECRYPTED |
			     RX_FLAG_IV_STRIPPED |
			     RX_FLAG_MMIC_STRIPPED);

	if (err_bitmap & DP_RX_MPDU_ERR_FCS)
		rx_status->flag |= RX_FLAG_FAILED_FCS_CRC;

	if (err_bitmap & DP_RX_MPDU_ERR_TKIP_MIC)
		rx_status->flag |= RX_FLAG_MMIC_ERROR;

	if (is_decrypted) {
		rx_status->flag |= RX_FLAG_DECRYPTED | RX_FLAG_MMIC_STRIPPED;

		if (fill_crypto_hdr)
			rx_status->flag |= RX_FLAG_MIC_STRIPPED |
					RX_FLAG_ICV_STRIPPED;
		else
			rx_status->flag |= RX_FLAG_IV_STRIPPED;
	}

	skb_queue_walk(amsdu_list, msdu) {
		ath11k_dp_rx_h_csum_offload(msdu);
		ath11k_dp_rx_h_undecap(ar, msdu, hdr_status,
				       enctype, rx_status, is_decrypted);

		if (!is_decrypted)
			continue;

		if (fill_crypto_hdr)
			continue;

		hdr = (void *)msdu->data;
		hdr->frame_control &= ~__cpu_to_le16(IEEE80211_FCTL_PROTECTED);
	}
}

static void ath11k_dp_rx_h_rate(struct ath11k *ar, void *rx_desc,
				struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_supported_band *sband;
	enum rx_msdu_start_pkt_type pkt_type;
	u8 bw;
	u8 rate_mcs, nss;
	u8 sgi;
	bool is_cck;

	pkt_type = ath11k_dp_rx_h_msdu_start_pkt_type(rx_desc);
	bw = ath11k_dp_rx_h_msdu_start_rx_bw(rx_desc);
	rate_mcs = ath11k_dp_rx_h_msdu_start_rate_mcs(rx_desc);
	nss = ath11k_dp_rx_h_msdu_start_nss(rx_desc);
	sgi = ath11k_dp_rx_h_msdu_start_sgi(rx_desc);

	switch (pkt_type) {
	case RX_MSDU_START_PKT_TYPE_11A:
	case RX_MSDU_START_PKT_TYPE_11B:
		is_cck = (pkt_type == RX_MSDU_START_PKT_TYPE_11B);
		sband = &ar->mac.sbands[rx_status->band];
		rx_status->rate_idx = ath11k_mac_hw_rate_to_idx(sband, rate_mcs,
								is_cck);
		break;
	case RX_MSDU_START_PKT_TYPE_11N:
		if (rate_mcs > 7) {
			ath11k_warn(ar->ab, "Received with invalid mcs in HT mode %d\n", rate_mcs);
			break;
		}
		rx_status->rate_idx = rate_mcs + (8 * (nss - 1));
		rx_status->encoding = RX_ENC_HT;
		if (sgi)
			rx_status->enc_flags |= RX_ENC_FLAG_SHORT_GI;
		rx_status->bw = ath11k_bw_to_mac80211_bw(bw);
		break;
	case RX_MSDU_START_PKT_TYPE_11AC:
		rx_status->rate_idx = rate_mcs;
		if (rate_mcs > 9) {
			ath11k_warn(ar->ab, "Received with invalid mcs in VHT mode %d\n", rate_mcs);
			break;
		}
		rx_status->encoding = RX_ENC_VHT;
		rx_status->nss = nss;
		if (sgi)
			rx_status->enc_flags |= RX_ENC_FLAG_SHORT_GI;
		rx_status->bw = ath11k_bw_to_mac80211_bw(bw);
		break;
	case RX_MSDU_START_PKT_TYPE_11AX:
		ath11k_warn(ar->ab, "pkt_type %d not yet supported\n", pkt_type);
		break;
	}
}

static void ath11k_dp_rx_h_ppdu(struct ath11k *ar, void *rx_desc,
				struct ieee80211_rx_status *rx_status)
{
	u8 channel_num;

	rx_status->freq = 0;
	rx_status->rate_idx = 0;
	rx_status->nss = 0;
	rx_status->encoding = RX_ENC_LEGACY;
	rx_status->bw = RATE_INFO_BW_20;

	rx_status->flag |= RX_FLAG_NO_SIGNAL_VAL;

	/* TODO: Use real NF instead of default one */
	rx_status->signal = ath11k_dp_rx_h_msdu_start_rssi(rx_desc) +
			    ATH11K_DEFAULT_NOISE_FLOOR;
	rx_status->flag &= ~RX_FLAG_NO_SIGNAL_VAL;

	channel_num = ath11k_dp_rx_h_msdu_start_freq(rx_desc);

	if (channel_num >= 1 && channel_num <= 14) {
		rx_status->band = NL80211_BAND_2GHZ;
	} else if (channel_num >= 36 && channel_num <= 173) {
		rx_status->band = NL80211_BAND_5GHZ;
	} else {
		ath11k_warn(ar->ab, "Unsupported Channel info received %d\n",
			    channel_num);
		return;
	}

	rx_status->freq = ieee80211_channel_to_frequency(channel_num,
							 rx_status->band);

	ath11k_dp_rx_h_rate(ar, rx_desc, rx_status);
}

static void ath11k_dp_rx_process_amsdu(struct ath11k *ar,
				       struct sk_buff_head *amsdu_list,
				       struct ieee80211_rx_status *rx_status)
{
	struct sk_buff *first;
	struct ath11k_skb_rxcb *rxcb;
	void *rx_desc;
	bool first_mpdu;

	if (skb_queue_empty(amsdu_list))
		return;

	first = skb_peek(amsdu_list);
	rxcb = ATH11K_SKB_RXCB(first);
	rx_desc = rxcb->rx_desc;

	first_mpdu = ath11k_dp_rx_h_attn_first_mpdu(rx_desc);
	if (first_mpdu)
		ath11k_dp_rx_h_ppdu(ar, rx_desc, rx_status);

	/* TODO: Check if we need to drop frames in certain cases something
	 * like while in the middle of CAC.
	 */

	ath11k_dp_rx_h_mpdu(ar, amsdu_list, rx_desc, rx_status);
}

static char *ath11k_print_get_tid(struct ieee80211_hdr *hdr, char *out,
				  size_t size)
{
	u8 *qc;
	int tid;

	if (!ieee80211_is_data_qos(hdr->frame_control))
		return "";

	qc = ieee80211_get_qos_ctl(hdr);
	tid = *qc & IEEE80211_QOS_CTL_TID_MASK;
	snprintf(out, size, "tid %d", tid);

	return out;
}

static void ath11k_dp_rx_deliver_msdu(struct ath11k *ar, struct napi_struct *napi,
				      struct sk_buff *msdu)
{
	struct ieee80211_rx_status *status;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)msdu->data;
	char tid[32];

	status = IEEE80211_SKB_RXCB(msdu);

	ath11k_dbg(ar->ab, ATH11K_DBG_DATA,
		   "rx skb %pK len %u peer %pM %s %s sn %u %s%s%s%s%s%s %srate_idx %u vht_nss %u freq %u band %u flag 0x%x fcs-err %i mic-err %i amsdu-more %i\n",
		   msdu,
		   msdu->len,
		   ieee80211_get_SA(hdr),
		   ath11k_print_get_tid(hdr, tid, sizeof(tid)),
		   is_multicast_ether_addr(ieee80211_get_DA(hdr)) ?
							"mcast" : "ucast",
		   (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4,
		   (status->encoding == RX_ENC_LEGACY) ? "legacy" : "",
		   (status->encoding == RX_ENC_HT) ? "ht" : "",
		   (status->encoding == RX_ENC_VHT) ? "vht" : "",
		   (status->bw == RATE_INFO_BW_40) ? "40" : "",
		   (status->bw == RATE_INFO_BW_80) ? "80" : "",
		   (status->bw == RATE_INFO_BW_160) ? "160" : "",
		   status->enc_flags & RX_ENC_FLAG_SHORT_GI ? "sgi " : "",
		   status->rate_idx,
		   status->nss,
		   status->freq,
		   status->band, status->flag,
		   !!(status->flag & RX_FLAG_FAILED_FCS_CRC),
		   !!(status->flag & RX_FLAG_MMIC_ERROR),
		   !!(status->flag & RX_FLAG_AMSDU_MORE));

	/* TODO: trace rx packet */

	ieee80211_rx_napi(ar->hw, NULL, msdu, napi);
}

static void ath11k_dp_rx_deliver_amsdu(struct ath11k *ar,
				       struct sk_buff_head *amsdu_list,
				       struct ieee80211_rx_status *rxs,
				       struct napi_struct *napi)
{
	struct sk_buff *msdu;
	struct sk_buff *first_subframe;
	struct ieee80211_rx_status *status;

	first_subframe = skb_peek(amsdu_list);

	while ((msdu = __skb_dequeue(amsdu_list))) {
		/* Setup per-MSDU flags */
		if (skb_queue_empty(amsdu_list))
			rxs->flag &= ~RX_FLAG_AMSDU_MORE;
		else
			rxs->flag |= RX_FLAG_AMSDU_MORE;

		if (msdu == first_subframe) {
			first_subframe = NULL;
			rxs->flag &= ~RX_FLAG_ALLOW_SAME_PN;
		} else {
			rxs->flag |= RX_FLAG_ALLOW_SAME_PN;
		}

		status = IEEE80211_SKB_RXCB(msdu);
		*status = *rxs;

		ath11k_dp_rx_deliver_msdu(ar, napi, msdu);
	}
}

int ath11k_dp_process_rx(struct ath11k_base *ab, int mac_id,
			 struct napi_struct *napi, int budget)
{
	struct ath11k *ar = ab->pdevs[mac_id].ar;
	struct ath11k_pdev_dp *dp = &ar->dp;
	struct ieee80211_rx_status *rx_status = &dp->rx_status;
	struct dp_rxdma_ring *rx_ring = &dp->rx_refill_buf_ring;
	struct hal_srng *srng;
	struct hal_rx_meta_info meta_info;
	struct sk_buff *msdu;
	struct sk_buff_head msdu_list;
	struct sk_buff_head amsdu_list;
	struct ath11k_skb_rxcb *rxcb;
	u32 *rx_desc;
	int buf_id;
	int num_buffs_reaped = 0;
	int ret;

	__skb_queue_head_init(&msdu_list);

	srng = &ab->hal.srng_list[dp->reo_dst_ring.ring_id];

	spin_lock_bh(&srng->lock);

	ath11k_hal_srng_access_begin(ab, srng);

	while (budget) {
		rx_desc = ath11k_hal_srng_dst_get_next_entry(ab, srng);

		/* Hw might have updated the head pointer after we cached it.
		 * In this case, even though there are entries in the ring we'll
		 * get rx_desc NULL. Give the read another try with updated cached
		 * head pointer so that we can reap complete MPDU in the current
		 * rx processing.
		 */
		if (!rx_desc) {
			ath11k_hal_srng_access_begin(ab, srng);
			rx_desc = ath11k_hal_srng_dst_get_next_entry(ab, srng);
			if (!rx_desc)
				break;
			ath11k_hal_srng_access_end(ab, srng);
		}

		memset(&meta_info, 0, sizeof(meta_info));
		ath11k_hal_rx_parse_dst_ring_desc(ab, rx_desc, &meta_info);

		buf_id = FIELD_GET(DP_RXDMA_BUF_COOKIE_BUF_ID,
				   meta_info.msdu_meta.cookie);
		spin_lock_bh(&rx_ring->idr_lock);
		msdu = idr_find(&rx_ring->bufs_idr, buf_id);
		if (!msdu) {
			ath11k_warn(ab, "frame rx with invalid buf_id %d\n",
				    buf_id);
			spin_unlock_bh(&rx_ring->idr_lock);
			break;
		}

		idr_remove(&rx_ring->bufs_idr, buf_id);
		spin_unlock_bh(&rx_ring->idr_lock);

		rxcb = ATH11K_SKB_RXCB(msdu);
		dma_unmap_single(ab->dev, rxcb->paddr,
				 msdu->len + skb_tailroom(msdu),
				 DMA_FROM_DEVICE);

		if (meta_info.push_reason !=
		    HAL_REO_DEST_RING_PUSH_REASON_ROUTING_INSTRUCTION) {
			/* TODO: Check if the msdu can be sent up for processing */
			dev_kfree_skb_any(msdu);
			continue;
		}

		rxcb->is_first_msdu = meta_info.msdu_meta.first;
		rxcb->is_last_msdu = meta_info.msdu_meta.last;
		rxcb->is_continuation = meta_info.msdu_meta.continuation;
		__skb_queue_tail(&msdu_list, msdu);
		num_buffs_reaped++;
		budget--;
	}

	ath11k_hal_srng_access_end(ab, srng);

	spin_unlock_bh(&srng->lock);

	if (!num_buffs_reaped)
		goto exit;

	/* Should we reschedule it later if we are not able to replenish all
	 * the buffers?
	 */
	ath11k_dp_rxbufs_replenish(ab, mac_id, rx_ring, num_buffs_reaped,
				   HAL_RX_BUF_RBM_SW3_BM, GFP_ATOMIC);

	rcu_read_lock();
	if (!rcu_dereference(ab->pdevs_active[mac_id])) {
		__skb_queue_purge(&msdu_list);
		goto rcu_unlock;
	}

	while (!skb_queue_empty(&msdu_list)) {
		__skb_queue_head_init(&amsdu_list);
		ret = ath11k_dp_rx_retrieve_amsdu(ar, &msdu_list, &amsdu_list);
		if (ret) {
			if (ret == -EIO) {
				ath11k_err(ab, "rx ring got corrupted %d\n", ret);
				__skb_queue_purge(&msdu_list);
				/* Should stop processing any more rx in future from this ring? */
				goto rcu_unlock;
			}

			/* A-MSDU retrieval got failed due to non-fatal condition,
			 * continue processing with the next msdu.
			 */
			continue;
		}

		ath11k_dp_rx_process_amsdu(ar, &amsdu_list, rx_status);

		ath11k_dp_rx_deliver_amsdu(ar, &amsdu_list, rx_status, napi);
	}

rcu_unlock:
	rcu_read_unlock();
exit:
	return num_buffs_reaped;
}

static int ath11k_dp_rx_link_desc_return(struct ath11k_base *ab,
					 u32 *link_desc,
					 enum hal_wbm_rel_bm_act action)
{
	struct ath11k_dp *dp = &ab->dp;
	struct hal_srng *srng;
	u32 *desc;
	int ret = 0;

	srng = &ab->hal.srng_list[dp->wbm_desc_rel_ring.ring_id];

	spin_lock_bh(&srng->lock);

	ath11k_hal_srng_access_begin(ab, srng);

	desc = ath11k_hal_srng_src_get_next_entry(ab, srng);
	if (!desc) {
		ret = -ENOBUFS;
		goto exit;
	}

	ath11k_hal_rx_msdu_link_desc_set(ab, (void *)desc, (void *)link_desc,
					 action);

exit:
	ath11k_hal_srng_access_end(ab, srng);

	spin_unlock_bh(&srng->lock);

	return ret;
}

static void ath11k_dp_rx_frag_h_mpdu(struct ath11k *ar,
				     struct sk_buff *msdu,
				     u8 *rx_desc,
				     struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_channel *rx_channel;
	enum hal_encrypt_type enctype;
	bool is_decrypted;
	u32 err_bitmap;

	is_decrypted = ath11k_dp_rx_h_attn_is_decrypted(rx_desc);
	enctype = ath11k_dp_rx_h_mpdu_start_enctype(rx_desc);
	err_bitmap = ath11k_dp_rx_h_attn_mpdu_err(rx_desc);

	if (err_bitmap & DP_RX_MPDU_ERR_FCS)
		rx_status->flag |= RX_FLAG_FAILED_FCS_CRC;

	if (err_bitmap & DP_RX_MPDU_ERR_TKIP_MIC)
		rx_status->flag |= RX_FLAG_MMIC_ERROR;

	rx_status->encoding = RX_ENC_LEGACY;
	rx_status->bw = RATE_INFO_BW_20;

	/* TODO: Use real NF instead of default one */
	rx_status->signal = ath11k_dp_rx_h_msdu_start_rssi(rx_desc) +
			    ATH11K_DEFAULT_NOISE_FLOOR;

	rx_status->freq = ath11k_dp_rx_h_msdu_start_freq(rx_desc);
	rx_channel = ieee80211_get_channel(ar->hw->wiphy, rx_status->freq);
	if (rx_channel)
		rx_status->band = rx_channel->band;

	ath11k_dp_rx_h_rate(ar, rx_desc, rx_status);

	/* Rx fragments are received in raw mode */
	skb_trim(msdu, msdu->len - FCS_LEN);

	if (is_decrypted) {
		rx_status->flag |= RX_FLAG_DECRYPTED | RX_FLAG_MIC_STRIPPED;
		skb_trim(msdu, msdu->len -
			 ath11k_dp_rx_crypto_mic_len(ar, enctype));
	}
}

static int ath11k_dp_rx_frag_buf(struct ath11k *ar, struct napi_struct *napi,
				 int buf_id)
{
	struct ath11k_pdev_dp *dp = &ar->dp;
	struct dp_rxdma_ring *rx_ring = &dp->rx_refill_buf_ring;
	struct ieee80211_rx_status rx_status = {0};
	struct sk_buff *msdu;
	struct ath11k_skb_rxcb *rxcb;
	struct ieee80211_rx_status *status;
	void *rx_desc;
	u16 msdu_len;

	spin_lock_bh(&rx_ring->idr_lock);
	msdu = idr_find(&rx_ring->bufs_idr, buf_id);
	if (!msdu) {
		ath11k_warn(ar->ab, "fragment rx with invalid buf_id %d\n", buf_id);
		spin_unlock_bh(&rx_ring->idr_lock);
		return -EINVAL;
	}

	idr_remove(&rx_ring->bufs_idr, buf_id);
	spin_unlock_bh(&rx_ring->idr_lock);

	rxcb = ATH11K_SKB_RXCB(msdu);
	dma_unmap_single(ar->ab->dev, rxcb->paddr,
			 msdu->len + skb_tailroom(msdu),
			 DMA_FROM_DEVICE);

	rcu_read_lock();
	if (!rcu_dereference(ar->ab->pdevs_active[ar->pdev_idx])) {
		dev_kfree_skb_any(msdu);
		goto exit;
	}

	rx_desc = msdu->data;
	msdu_len = ath11k_dp_rx_h_msdu_start_msdu_len(rx_desc);
	skb_put(msdu, HAL_RX_DESC_SIZE + msdu_len);
	skb_pull(msdu, HAL_RX_DESC_SIZE);

	ath11k_dp_rx_frag_h_mpdu(ar, msdu, rx_desc, &rx_status);

	status = IEEE80211_SKB_RXCB(msdu);

	*status = rx_status;

	ath11k_dp_rx_deliver_msdu(ar, napi, msdu);

exit:
	rcu_read_unlock();
	return 0;
}

static int ath11k_dp_rx_process_fragments(struct ath11k *ar,
					  struct napi_struct *napi,
					  struct hal_rx_msdu_meta *meta,
					  u32 num_msdus)
{
	int i;
	int buf_id;
	int num_sent = 0;

	for (i = 0; i < num_msdus; i++) {
		buf_id = FIELD_GET(DP_RXDMA_BUF_COOKIE_BUF_ID,
				   meta[i].cookie);
		if (!ath11k_dp_rx_frag_buf(ar, napi, buf_id))
			num_sent++;
	}

	return num_sent;
}

int ath11k_dp_process_rx_err(struct ath11k_base *ab, int mac_id,
			     struct napi_struct *napi, int budget)
{
	struct ath11k *ar = ab->pdevs[mac_id].ar;
	struct ath11k_dp *dp = &ab->dp;
	struct dp_srng *reo_except = &dp->reo_except_ring;
	struct dp_rxdma_ring *rx_ring = &ar->dp.rx_refill_buf_ring;
	struct hal_srng *srng;
	struct hal_rx_msdu_meta meta[HAL_NUM_RX_MSDUS_PER_LINK_DESC];
	struct dp_link_desc_bank *link_desc_banks = dp->link_desc_banks;
	int n_bufs_reaped = 0, num_to_replenish = 0;
	u32 *desc;
	int ret;
	dma_addr_t paddr;
	u32 desc_bank;
	void *link_desc_va;
	enum hal_rx_buf_return_buf_manager rbm;
	struct hal_rx_meta_info meta_info;
	u32 num_msdus;

	srng = &ab->hal.srng_list[reo_except->ring_id];

	spin_lock_bh(&srng->lock);

	ath11k_hal_srng_access_begin(ab, srng);

	while (budget &&
	       (desc = ath11k_hal_srng_dst_get_next_entry(ab, srng))) {
		ret = ath11k_hal_desc_reo_parse_err(ab, desc, &paddr,
						    &desc_bank);
		if (ret) {
			ath11k_warn(ar->ab, "failed to parse error reo desc %d\n", ret);
			goto exit;
		}

		link_desc_va = link_desc_banks[desc_bank].vaddr +
			       (paddr - link_desc_banks[desc_bank].paddr);
		ath11k_hal_rx_msdu_link_info_get(link_desc_va, &num_msdus, meta,
						 &rbm);
		if (rbm != HAL_RX_BUF_RBM_WBM_IDLE_DESC_LIST ||
		    rbm != HAL_RX_BUF_RBM_SW3_BM) {
			ath11k_warn(ab, "invalid return buffer manager %d\n", rbm);
			ath11k_dp_rx_link_desc_return(ab, desc,
						HAL_WBM_REL_BM_ACT_REL_MSDU);
			continue;
		}

		memset(&meta_info, 0, sizeof(meta_info));
		ath11k_hal_rx_parse_dst_ring_desc(ab, desc, &meta_info);

		if (meta_info.mpdu_meta.frag) {
			n_bufs_reaped += ath11k_dp_rx_process_fragments(
							ar, napi, meta,
							num_msdus);
			num_to_replenish = n_bufs_reaped;
			if (n_bufs_reaped > budget) {
				n_bufs_reaped = budget;
				goto exit;
			}

			budget -= n_bufs_reaped;
			continue;
		}
	}

exit:
	ath11k_hal_srng_access_end(ab, srng);

	spin_unlock_bh(&srng->lock);

	ath11k_dp_rxbufs_replenish(ab, mac_id, rx_ring, num_to_replenish,
				   HAL_RX_BUF_RBM_SW3_BM, GFP_ATOMIC);

	return n_bufs_reaped;
}

static void ath11k_dp_rx_null_q_desc_sg_drop(struct ath11k *ar,
					     int msdu_len,
					     struct sk_buff_head *msdu_list)
{
	struct sk_buff *skb;
	struct ath11k_skb_rxcb *rxcb;
	int n_buffs;

	n_buffs = DIV_ROUND_UP(msdu_len,
			       (DP_RX_BUFFER_SIZE - HAL_RX_DESC_SIZE));

	skb_queue_walk(msdu_list, skb) {
		rxcb = ATH11K_SKB_RXCB(skb);
		if (rxcb->err_rel_src == HAL_WBM_REL_SRC_MODULE_REO &&
		    rxcb->err_code == HAL_REO_DEST_RING_ERROR_CODE_DESC_ADDR_ZERO) {
			if (n_buffs--)
				break;
			__skb_unlink(skb, msdu_list);
			dev_kfree_skb_any(skb);
		}
	}
}

static int ath11k_dp_rx_h_null_q_desc(struct ath11k *ar, struct sk_buff *msdu,
				      struct ieee80211_rx_status *status,
				      struct sk_buff_head *msdu_list)
{
	struct sk_buff_head amsdu_list;
	u16 msdu_len;
	u8 *desc = msdu->data;
	u8 l3pad_bytes;

	if (!ath11k_dp_rx_h_attn_msdu_done(desc)) {
		ath11k_warn(ar->ab,
			    "msdu_done bit not set in null_q_des processing\n");
		__skb_queue_purge(msdu_list);
		return -EIO;
	}

	/* Handle NULL queue descriptor violations arising out a missing
	 * REO queue for a given peer or a given TID. This typically
	 * may happen if a packet is received on a QOS enabled TID before the
	 * ADDBA negotiation for that TID, when the TID queue is setup. Or
	 * it may also happen for MC/BC frames if they are not routed to the
	 * non-QOS TID queue, in the absence of any other default TID queue.
	 * This error can show up both in a REO destination or WBM release ring.
	 */

	__skb_queue_head_init(&amsdu_list);

	l3pad_bytes = ath11k_dp_rx_h_msdu_end_l3pad(desc);
	msdu_len = ath11k_dp_rx_h_msdu_start_msdu_len(desc);

	if ((msdu_len + l3pad_bytes + HAL_RX_DESC_SIZE) > DP_RX_BUFFER_SIZE) {
		/* First buffer will be freed by the caller, so deduct it's length */
		msdu_len = msdu_len -
			   (DP_RX_BUFFER_SIZE - l3pad_bytes - HAL_RX_DESC_SIZE);
		ath11k_dp_rx_null_q_desc_sg_drop(ar, msdu_len, msdu_list);
		return -EINVAL;
	} else {

		skb_put(msdu, HAL_RX_DESC_SIZE + l3pad_bytes + msdu_len);
		skb_pull(msdu, HAL_RX_DESC_SIZE + l3pad_bytes);
	}

	ath11k_dp_rx_h_ppdu(ar, desc, status);

	__skb_queue_tail(&amsdu_list, msdu);

	ath11k_dp_rx_h_mpdu(ar, &amsdu_list, desc, status);

	/* Please note that caller will having the access to msdu and completing
	 * rx with mac80211. Need not worry about cleaning up amsdu_list.
	 */

	return 0;
}

static bool ath11k_dp_rx_h_reo_err(struct ath11k *ar, struct sk_buff *msdu,
				   struct ieee80211_rx_status *status,
				   struct sk_buff_head *msdu_list)
{
	struct ath11k_skb_rxcb *rxcb = ATH11K_SKB_RXCB(msdu);
	bool drop = false;

	switch (rxcb->err_code) {
	case HAL_REO_DEST_RING_ERROR_CODE_DESC_ADDR_ZERO:
		if (ath11k_dp_rx_h_null_q_desc(ar, msdu, status, msdu_list))
			drop = true;
		break;
	default:
		/* TODO: Review other errors and process them to mac80211
		 * as appropriate.
		 */
		drop = true;
		break;
	}

	return drop;
}

static void ath11k_dp_rx_h_tkip_mic_err(struct ath11k *ar, struct sk_buff *msdu,
					struct ieee80211_rx_status *status)
{
	u16 msdu_len;
	u8 *desc = msdu->data;
	u8 l3pad_bytes, *hdr_status;

	l3pad_bytes = ath11k_dp_rx_h_msdu_end_l3pad(desc);
	msdu_len = ath11k_dp_rx_h_msdu_start_msdu_len(desc);
	skb_put(msdu, HAL_RX_DESC_SIZE + l3pad_bytes + msdu_len);
	skb_pull(msdu, HAL_RX_DESC_SIZE + l3pad_bytes);

	ath11k_dp_rx_h_ppdu(ar, desc, status);

	hdr_status = ath11k_dp_rx_h_80211_hdr(desc);
	status->flag |= RX_FLAG_MMIC_ERROR;

	ath11k_dp_rx_h_undecap(ar, msdu, hdr_status,
			       HAL_ENCRYPT_TYPE_TKIP_MIC, status, false);
}

static bool ath11k_dp_rx_h_rxdma_err(struct ath11k *ar,  struct sk_buff *msdu,
				     struct ieee80211_rx_status *status)
{
	struct ath11k_skb_rxcb *rxcb = ATH11K_SKB_RXCB(msdu);
	bool drop = false;

	switch (rxcb->err_code) {
	case HAL_REO_ENTR_RING_RXDMA_ECODE_TKIP_MIC_ERR:
		ath11k_dp_rx_h_tkip_mic_err(ar, msdu, status);
		break;
	default:
		/* TODO: Review other rxdma error code to check if anything is
		 * worth reporting to mac80211
		 */
		drop = true;
		break;
	}

	return drop;
}

static void ath11k_dp_rx_wbm_err(struct ath11k *ar,
				 struct napi_struct *napi,
				 struct sk_buff *msdu,
				 struct sk_buff_head *msdu_list)
{
	struct ath11k_skb_rxcb *rxcb = ATH11K_SKB_RXCB(msdu);
	struct ieee80211_rx_status rxs = {0};
	struct ieee80211_rx_status *status;
	bool drop = true;

	switch (rxcb->err_rel_src) {
	case HAL_WBM_REL_SRC_MODULE_REO:
		drop = ath11k_dp_rx_h_reo_err(ar, msdu, &rxs, msdu_list);
		break;
	case HAL_WBM_REL_SRC_MODULE_RXDMA:
		drop = ath11k_dp_rx_h_rxdma_err(ar, msdu, &rxs);
		break;
	default:
		/* msdu will get freed */
		break;
	}

	if (drop) {
		dev_kfree_skb_any(msdu);
		return;
	}

	status = IEEE80211_SKB_RXCB(msdu);
	*status = rxs;

	ath11k_dp_rx_deliver_msdu(ar, napi, msdu);
}

int ath11k_dp_rx_process_wbm_err(struct ath11k_base *ab,
				 struct napi_struct *napi, int budget)
{
	struct ath11k *ar;
	struct ath11k_dp *dp = &ab->dp;
	struct dp_rxdma_ring *rx_ring;
	struct hal_rx_wbm_rel_info err_info;
	struct hal_srng *srng;
	struct sk_buff *msdu;
	struct sk_buff_head msdu_list[MAX_RADIOS];
	struct ath11k_skb_rxcb *rxcb;
	u32 *rx_desc;
	int buf_id, mac_id;
	int num_buffs_reaped[MAX_RADIOS] = {0};
	int total_num_buffs_reaped = 0;
	int ret, i;

	for (i = 0; i < MAX_RADIOS; i++)
		__skb_queue_head_init(&msdu_list[i]);

	srng = &ab->hal.srng_list[dp->rx_rel_ring.ring_id];

	spin_lock_bh(&srng->lock);

	ath11k_hal_srng_access_begin(ab, srng);

	while (budget) {
		rx_desc = ath11k_hal_srng_dst_get_next_entry(ab, srng);
		if (!rx_desc)
			break;

		ret = ath11k_hal_wbm_desc_parse_err(ab, rx_desc, &err_info);
		if (ret) {
			ath11k_warn(ab, "failed to parse rx error in wbm_rel ring desc %d\n", ret);
			break;
		}

		buf_id = FIELD_GET(DP_RXDMA_BUF_COOKIE_BUF_ID, err_info.cookie);
		mac_id = FIELD_GET(DP_RXDMA_BUF_COOKIE_PDEV_ID, err_info.cookie);

		ar = ab->pdevs[mac_id].ar;
		rx_ring = &ar->dp.rx_refill_buf_ring;

		spin_lock_bh(&rx_ring->idr_lock);
		msdu = idr_find(&rx_ring->bufs_idr, buf_id);
		if (!msdu) {
			ath11k_warn(ab, "frame rx with invalid buf_id %d pdev %d\n",
				    buf_id, mac_id);
			spin_unlock_bh(&rx_ring->idr_lock);
			break;
		}

		idr_remove(&rx_ring->bufs_idr, buf_id);
		spin_unlock_bh(&rx_ring->idr_lock);

		rxcb = ATH11K_SKB_RXCB(msdu);
		dma_unmap_single(ab->dev, rxcb->paddr,
				 msdu->len + skb_tailroom(msdu),
				 DMA_FROM_DEVICE);

		if (err_info.push_reason !=
		    HAL_REO_DEST_RING_PUSH_REASON_ERR_DETECTED) {
			dev_kfree_skb_any(msdu);
			continue;
		}

		rxcb->err_rel_src = err_info.err_rel_src;
		rxcb->err_code = err_info.err_code;
		rxcb->is_first_msdu = err_info.first_msdu;
		rxcb->is_last_msdu = err_info.last_msdu;
		rxcb->rx_desc = msdu->data;
		__skb_queue_tail(&msdu_list[mac_id], msdu);
		num_buffs_reaped[mac_id]++;
		total_num_buffs_reaped++;
		budget--;
	}

	ath11k_hal_srng_access_end(ab, srng);

	spin_unlock_bh(&srng->lock);

	if (!total_num_buffs_reaped)
		goto done;


	for (i = 0; i <  ab->num_radios; i++) {
		if (!num_buffs_reaped[i])
			continue;

		ar = ab->pdevs[i].ar;
		rx_ring = &ar->dp.rx_refill_buf_ring;

		ath11k_dp_rxbufs_replenish(ab, i, rx_ring, num_buffs_reaped[i],
					   HAL_RX_BUF_RBM_SW3_BM, GFP_ATOMIC);
	}

	rcu_read_lock();
	for (i = 0; i <  ab->num_radios; i++) {
		if (!rcu_dereference(ab->pdevs_active[i])) {
			__skb_queue_purge(&msdu_list[i]);
			continue;
		}

		ar = ab->pdevs[i].ar;
		while ((msdu = __skb_dequeue(&msdu_list[i])) != NULL)
			ath11k_dp_rx_wbm_err(ar, napi, msdu, &msdu_list[i]);
	}
	rcu_read_unlock();
done:
	return total_num_buffs_reaped;
}

int ath11k_dp_process_rxdma_err(struct ath11k_base *ab, int mac_id, int budget)
{
	struct ath11k *ar = ab->pdevs[mac_id].ar;
	struct dp_srng *err_ring = &ar->dp.rxdma_err_dst_ring;
	struct dp_rxdma_ring *rx_ring = &ar->dp.rx_refill_buf_ring;
	struct dp_link_desc_bank *link_desc_banks = ab->dp.link_desc_banks;
	struct hal_srng *srng;
	struct hal_rx_msdu_meta meta[HAL_NUM_RX_MSDUS_PER_LINK_DESC];
	enum hal_rx_buf_return_buf_manager rbm;
	struct ath11k_skb_rxcb *rxcb;
	struct sk_buff *skb;
	void *desc;
	int num_buf_freed = 0;
	int quota = budget;
	dma_addr_t paddr;
	u32 desc_bank;
	void *link_desc_va;
	int num_msdus;
	int i;
	int buf_id;

	srng = &ab->hal.srng_list[err_ring->ring_id];

	spin_lock_bh(&srng->lock);

	ath11k_hal_srng_access_begin(ab, srng);

	while (quota-- &&
	       (desc = ath11k_hal_srng_dst_get_next_entry(ab, srng))) {
		ath11k_hal_rx_reo_ent_paddr_get(ab, desc, &paddr, &desc_bank);

		link_desc_va = link_desc_banks[desc_bank].vaddr +
			       (paddr - link_desc_banks[desc_bank].paddr);
		ath11k_hal_rx_msdu_link_info_get(link_desc_va, &num_msdus, meta,
						 &rbm);

		for (i = 0; i < num_msdus; i++) {
			buf_id = FIELD_GET(DP_RXDMA_BUF_COOKIE_BUF_ID,
					   meta[i].cookie);

			spin_lock_bh(&rx_ring->idr_lock);
			skb = idr_find(&rx_ring->bufs_idr, buf_id);
			if (!skb) {
				ath11k_warn(ab, "rxdma error with invalid buf_id %d\n", buf_id);
				spin_unlock_bh(&rx_ring->idr_lock);
				continue;
			}

			idr_remove(&rx_ring->bufs_idr, buf_id);
			spin_unlock_bh(&rx_ring->idr_lock);

			rxcb = ATH11K_SKB_RXCB(skb);
			dma_unmap_single(ab->dev, rxcb->paddr,
					 skb->len + skb_tailroom(skb),
					 DMA_FROM_DEVICE);
			dev_kfree_skb_any(skb);

			num_buf_freed++;
		}

		ath11k_dp_rx_link_desc_return(ab, desc,
					      HAL_WBM_REL_BM_ACT_PUT_IN_IDLE);
	}

	ath11k_hal_srng_access_end(ab, srng);

	spin_unlock_bh(&srng->lock);

	if (num_buf_freed)
		ath11k_dp_rxbufs_replenish(ab, mac_id, rx_ring, num_buf_freed,
					   HAL_RX_BUF_RBM_SW3_BM, GFP_ATOMIC);

	return budget - quota;
}

void ath11k_dp_process_reo_status(struct ath11k_base *ab)
{
	struct ath11k_dp *dp = &ab->dp;
	struct hal_srng *srng;
	struct dp_reo_cmd *cmd, *tmp;
	bool found = false;
	u32 *reo_desc;
	u16 tag;
	struct hal_reo_status reo_status;

	srng = &ab->hal.srng_list[dp->reo_status_ring.ring_id];

	memset(&reo_status, 0, sizeof(reo_status));

	spin_lock_bh(&srng->lock);

	ath11k_hal_srng_access_begin(ab, srng);

	while ((reo_desc = ath11k_hal_srng_dst_get_next_entry(ab, srng))) {
		tag = FIELD_GET(HAL_SRNG_TLV_HDR_TAG, *reo_desc);

		switch (tag) {
		case HAL_REO_GET_QUEUE_STATS_STATUS:
			ath11k_hal_reo_status_queue_stats(ab, reo_desc,
							  &reo_status);
			break;
		case HAL_REO_FLUSH_QUEUE_STATUS:
			ath11k_hal_reo_flush_queue_status(ab, reo_desc,
							  &reo_status);
			break;
		case HAL_REO_FLUSH_CACHE_STATUS:
			ath11k_hal_reo_flush_cache_status(ab, reo_desc,
							  &reo_status);
			break;
		case HAL_REO_UNBLOCK_CACHE_STATUS:
			ath11k_hal_reo_unblk_cache_status(ab, reo_desc,
							  &reo_status);
			break;
		case HAL_REO_FLUSH_TIMEOUT_LIST_STATUS:
			ath11k_hal_reo_flush_timeout_list_status(ab, reo_desc,
								 &reo_status);
			break;
		case HAL_REO_DESCRIPTOR_THRESHOLD_REACHED_STATUS:
			ath11k_hal_reo_desc_thresh_reached_status(ab, reo_desc,
								  &reo_status);
			break;
		case HAL_REO_UPDATE_RX_REO_QUEUE_STATUS:
			ath11k_hal_reo_update_rx_reo_queue_status(ab, reo_desc,
								  &reo_status);
			break;
		default:
			break;
		}

		spin_lock_bh(&dp->reo_cmd_lock);
		list_for_each_entry_safe(cmd, tmp, &dp->reo_cmd_list, list) {
			if (reo_status.uniform_hdr.cmd_num == cmd->cmd_num) {
				found = true;
				list_del(&cmd->list);
				break;
			}
		}
		spin_unlock_bh(&dp->reo_cmd_lock);

		if (found) {
			cmd->handler(dp, (void *)&cmd->data,
				     reo_status.uniform_hdr.cmd_status);
			kfree(cmd);
		}

		found = false;
	}

	ath11k_hal_srng_access_end(ab, srng);

	spin_unlock_bh(&srng->lock);
}

void ath11k_dp_rx_pdev_free(struct ath11k_base *ab, int mac_id)
{
	struct ath11k *ar = ab->pdevs[mac_id].ar;

	ath11k_dp_rx_pdev_srng_free(ar);
	ath11k_dp_rxdma_pdev_buf_free(ar);
}

int ath11k_dp_rx_pdev_alloc(struct ath11k_base *ab, int mac_id)
{
	struct ath11k *ar = ab->pdevs[mac_id].ar;
	struct ath11k_pdev_dp *dp = &ar->dp;
	int ret;

	ret = ath11k_dp_rx_pdev_srng_alloc(ar);
	if (ret) {
		ath11k_warn(ab, "failed to setup rx srngs\n");
		return ret;
	}

	ret = ath11k_dp_rxdma_pdev_buf_setup(ar);
	if (ret) {
		ath11k_warn(ab, "failed to setup rxdma ring\n");
		return ret;
	}

	ret = ath11k_dp_htt_srng_setup(ab,
				dp->rx_refill_buf_ring.refill_buf_ring.ring_id,
				mac_id, HAL_RXDMA_BUF);
	if (ret) {
		ath11k_warn(ab, "failed to configure rx_refill_buf_ring %d\n",
			    ret);
		return ret;
	}

	ret = ath11k_dp_htt_srng_setup(ab, dp->rxdma_err_dst_ring.ring_id,
				       mac_id, HAL_RXDMA_DST);
	if (ret) {
		ath11k_warn(ab, "failed to configure rxdma_err_dest_ring %d\n",
			    ret);
		return ret;
	}

	return 0;
}
