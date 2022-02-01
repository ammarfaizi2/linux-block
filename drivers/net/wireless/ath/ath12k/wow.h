/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2020-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#define ATH12K_WOW_RETRY_NUM		3
#define ATH12K_WOW_RETRY_WAIT_MS	200

int ath12k_wow_enable(struct ath12k_base *ab);
int ath12k_wow_wakeup(struct ath12k_base *ab);
