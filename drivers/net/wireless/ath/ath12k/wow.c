// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2020-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/delay.h>

#include "mac.h"
#include "core.h"
#include "hif.h"
#include "debug.h"
#include "wmi.h"
#include "wow.h"

int ath12k_wow_enable(struct ath12k_base *ab)
{
	struct ath12k *ar = ath12k_ab_to_ar(ab, 0);
	int i, ret;

	clear_bit(ATH12K_FLAG_HTC_SUSPEND_COMPLETE, &ab->dev_flags);

	for (i = 0; i < ATH12K_WOW_RETRY_NUM; i++) {
		reinit_completion(&ab->htc_suspend);

		ret = ath12k_wmi_wow_enable(ar);
		if (ret) {
			ath12k_warn(ab, "failed to issue wow enable: %d\n", ret);
			return ret;
		}

		ret = wait_for_completion_timeout(&ab->htc_suspend, 3 * HZ);
		if (ret == 0) {
			ath12k_warn(ab,
				    "timed out while waiting for htc suspend completion\n");
			return -ETIMEDOUT;
		}

		if (test_bit(ATH12K_FLAG_HTC_SUSPEND_COMPLETE, &ab->dev_flags))
			/* success, suspend complete received */
			return 0;

		ath12k_warn(ab, "htc suspend not complete, retrying (try %d)\n",
			    i);
		msleep(ATH12K_WOW_RETRY_WAIT_MS);
	}

	ath12k_warn(ab, "htc suspend not complete, failing after %d tries\n", i);

	return -ETIMEDOUT;
}

int ath12k_wow_wakeup(struct ath12k_base *ab)
{
	struct ath12k *ar = ath12k_ab_to_ar(ab, 0);
	int ret;

	reinit_completion(&ab->wow.wakeup_completed);

	ret = ath12k_wmi_wow_host_wakeup_ind(ar);
	if (ret) {
		ath12k_warn(ab, "failed to send wow wakeup indication: %d\n",
			    ret);
		return ret;
	}

	ret = wait_for_completion_timeout(&ab->wow.wakeup_completed, 3 * HZ);
	if (ret == 0) {
		ath12k_warn(ab, "timed out while waiting for wow wakeup completion\n");
		return -ETIMEDOUT;
	}

	return 0;
}
