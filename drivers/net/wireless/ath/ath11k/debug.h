/* SPDX-License-Identifier: ISC */
/*
 * Copyright (c) 2018-2019 The Linux Foundation. All rights reserved.
 */

#ifndef _ATH11K_DEBUG_H_
#define _ATH11K_DEBUG_H_

#include "hal_tx.h"

enum ath11k_debug_mask {
	ATH11K_DBG_AHB		= 0x00000001,
	ATH11K_DBG_WMI		= 0x00000002,
	ATH11K_DBG_HTC		= 0x00000004,
	ATH11K_DBG_DP_HTT	= 0x00000008,
	ATH11K_DBG_MAC		= 0x00000010,
	ATH11K_DBG_BOOT		= 0x00000020,
	ATH11K_DBG_QMI		= 0x00000040,
	ATH11K_DBG_DATA		= 0x00000080,
	ATH11K_DBG_MGMT		= 0x00000100,
	ATH11K_DBG_REG		= 0x00000200,
	ATH11K_DBG_TESTMODE	= 0x00000400,
	ATH11K_DBG_ANY		= 0xffffffff,
};

#define ATH11K_FW_STATS_BUF_SIZE (1024 * 1024)

__printf(2, 3) void ath11k_info(struct ath11k_base *sc, const char *fmt, ...);
__printf(2, 3) void ath11k_err(struct ath11k_base *sc, const char *fmt, ...);
__printf(2, 3) void ath11k_warn(struct ath11k_base *sc, const char *fmt, ...);

extern unsigned int ath11k_debug_mask;

#ifdef CONFIG_ATH11K_DEBUG
__printf(3, 4) void ath11k_dbg(struct ath11k_base *ab,
			       enum ath11k_debug_mask mask,
			       const char *fmt, ...);
void ath11k_dbg_dump(struct ath11k_base *ab,
		     enum ath11k_debug_mask mask,
		     const char *msg, const char *prefix,
		     const void *buf, size_t len);
#else /* CONFIG_ATH11K_DEBUG */
static inline int ath11k_dbg(struct ath11k_base *ab,
			     enum ath11k_debug_mask dbg_mask,
			     const char *fmt, ...)
{
	return 0;
}
static inline void ath11k_dbg_dump(struct ath11k_base *ab,
		     enum ath11k_debug_mask mask,
		     const char *msg, const char *prefix,
		     const void *buf, size_t len)
{

}
#endif /* CONFIG_ATH11K_DEBUG */

#ifdef CONFIG_ATH11K_DEBUGFS
int ath11k_debug_soc_create(struct ath11k_base *sc);
void ath11k_debug_soc_destroy(struct ath11k_base *sc);
int ath11k_debug_register(struct ath11k *ar);
void ath11k_debug_unregister(struct ath11k *ar);
void ath11k_htt_stats_debugfs_init(struct ath11k *ar);
void ath11k_dbg_htt_ext_stats_handler(struct ath11k_base *ab,
				      struct sk_buff *skb);
void ath11k_debug_fw_stats_process(struct ath11k_base *ab, u8 *evt_buf,
				   u32 len);

void ath11k_debug_fw_stats_init(struct ath11k *ar);

static inline int ath11k_debug_is_extd_tx_stats_enabled(struct ath11k *ar)
{
	return ar->debug.extd_tx_stats;
}

static inline int ath11k_debug_is_extd_rx_stats_enabled(struct ath11k *ar)
{
	return ar->debug.extd_rx_stats;
}
#else
static inline int ath11k_debug_soc_create(struct ath11k_base *sc)
{
	return 0;
}

static inline void ath11k_debug_soc_destroy(struct ath11k_base *sc)
{
}

static inline int ath11k_debug_register(struct ath11k *ar)
{
	return 0;
}

static inline void ath11k_debug_unregister(struct ath11k *ar)
{
}

static inline void ath11k_htt_stats_debugfs_init(struct ath11k *ar)
{
}

static inline void ath11k_dbg_htt_ext_stats_handler(struct ath11k_base *ab,
						    struct sk_buff *skb)
{
}

static inline void ath11k_debug_fw_stats_process(struct ath11k_base *ab, u8 *evt_buf,
						 u32 len)
{
}

static inline void ath11k_debug_fw_stats_init(struct ath11k *ar)
{
}

static inline int ath11k_debug_is_extd_tx_stats_enabled(struct ath11k *ar)
{
	return 0;
}

static inline int ath11k_debug_is_extd_rx_stats_enabled(struct ath11k *ar)
{
	return 0;
}
#endif /* CONFIG_ATH11K_DEBUGFS */

#ifdef CONFIG_MAC80211_DEBUGFS
void ath11k_sta_add_debugfs(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			    struct ieee80211_sta *sta, struct dentry *dir);
void
ath11k_accumulate_per_peer_tx_stats(struct ath11k_sta *arsta,
				    struct ath11k_per_peer_tx_stats *peer_stats,
				    u8 legacy_rate_idx);
void ath11k_update_per_peer_stats_from_txcompl(struct ath11k *ar,
					       struct sk_buff *msdu,
					       struct hal_tx_status *ts);
void ath11k_sta_update_rx_duration(struct ath11k *ar,
				   struct ath11k_fw_stats *stats);
#else /* !CONFIG_MAC80211_DEBUGFS */
static inline void
ath11k_accumulate_per_peer_tx_stats(struct ath11k_sta *arsta,
				    struct ath11k_per_peer_tx_stats *peer_stats,
				    u8 legacy_rate_idx)
{
}

static inline void
ath11k_update_per_peer_stats_from_txcompl(struct ath11k *ar,
					  struct sk_buff *msdu,
					  struct hal_tx_status *ts)
{
}

static inline void ath11k_sta_update_rx_duration(struct ath11k *ar,
						 struct ath11k_fw_stats *stats)
{
}

#endif /* CONFIG_MAC80211_DEBUGFS*/

#endif /* _ATH11K_DEBUG_H_ */
