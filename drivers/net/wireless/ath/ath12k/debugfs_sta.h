/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _ATH12K_DEBUGFS_STA_H_
#define _ATH12K_DEBUGFS_STA_H_

#include <net/mac80211.h>

#include "core.h"
#include "hal_tx.h"
#include "dp_rx.h"

#ifdef CONFIG_ATH12K_DEBUGFS

void ath12k_debugfs_sta_op_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			       struct ieee80211_sta *sta, struct dentry *dir);
void ath12k_debugfs_sta_add_tx_stats(struct ath12k_sta *arsta,
				     struct ath12k_per_peer_tx_stats *peer_stats,
				     u8 legacy_rate_idx);
void ath12k_debugfs_sta_update_txcompl(struct ath12k *ar,
				       struct sk_buff *msdu,
				       struct hal_tx_status *ts);

#else /* CONFIG_ATH12K_DEBUGFS */

#define ath12k_debugfs_sta_op_add NULL

static inline void
ath12k_debugfs_sta_add_tx_stats(struct ath12k_sta *arsta,
				struct ath12k_per_peer_tx_stats *peer_stats,
				u8 legacy_rate_idx)
{
}

static inline void ath12k_debugfs_sta_update_txcompl(struct ath12k *ar,
						     struct sk_buff *msdu,
						     struct hal_tx_status *ts)
{
}

#endif /* CONFIG_ATH12K_DEBUGFS */

#endif /* _ATH12K_DEBUGFS_STA_H_ */
