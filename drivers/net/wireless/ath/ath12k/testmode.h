/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "core.h"

#ifdef CONFIG_NL80211_TESTMODE

bool ath12k_tm_event_wmi(struct ath12k *ar, u32 cmd_id, struct sk_buff *skb);
int ath12k_tm_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		  void *data, int len);

#else

static inline bool ath12k_tm_event_wmi(struct ath12k *ar, u32 cmd_id,
				       struct sk_buff *skb)
{
	return false;
}

static inline int ath12k_tm_cmd(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				void *data, int len)
{
	return 0;
}

#endif
