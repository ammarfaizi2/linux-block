/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2019-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef ATH12K_REG_H
#define ATH12K_REG_H

#include <linux/kernel.h>
#include <net/regulatory.h>

struct ath12k_base;
struct ath12k;

/* DFS regdomains supported by Firmware */
enum ath12k_dfs_region {
	ATH12K_DFS_REG_UNSET,
	ATH12K_DFS_REG_FCC,
	ATH12K_DFS_REG_ETSI,
	ATH12K_DFS_REG_MKK,
	ATH12K_DFS_REG_CN,
	ATH12K_DFS_REG_KR,
	ATH12K_DFS_REG_MKK_N,
	ATH12K_DFS_REG_UNDEF,
};

/* ATH12K Regulatory API's */
void ath12k_reg_init(struct ath12k *ar);
void ath12k_reg_free(struct ath12k_base *ab);
void ath12k_regd_update_work(struct work_struct *work);
struct ieee80211_regdomain *
ath12k_reg_build_regd(struct ath12k_base *ab,
		      struct cur_regulatory_info *reg_info, bool intersect);
int ath12k_regd_update(struct ath12k *ar, bool init);
int ath12k_reg_update_chan_list(struct ath12k *ar);
#endif
