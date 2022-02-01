/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2020-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _ATH12K_THERMAL_
#define _ATH12K_THERMAL_

#define ATH12K_THERMAL_TEMP_LOW_MARK -100
#define ATH12K_THERMAL_TEMP_HIGH_MARK 150
#define ATH12K_THERMAL_THROTTLE_MAX     100
#define ATH12K_THERMAL_DEFAULT_DUTY_CYCLE 100
#define ATH12K_HWMON_NAME_LEN           15
#define ATH12K_THERMAL_SYNC_TIMEOUT_HZ (5 * HZ)

struct ath12k_thermal {
	struct thermal_cooling_device *cdev;
	struct completion wmi_sync;

	/* protected by conf_mutex */
	u32 throttle_state;
	/* temperature value in Celcius degree
	 * protected by data_lock
	 */
	int temperature;
};

#if IS_REACHABLE(CONFIG_THERMAL)
int ath12k_thermal_register(struct ath12k_base *sc);
void ath12k_thermal_unregister(struct ath12k_base *sc);
int ath12k_thermal_set_throttling(struct ath12k *ar, u32 throttle_state);
void ath12k_thermal_event_temperature(struct ath12k *ar, int temperature);
#else
static inline int ath12k_thermal_register(struct ath12k_base *sc)
{
	return 0;
}

static inline void ath12k_thermal_unregister(struct ath12k_base *sc)
{
}

static inline int ath12k_thermal_set_throttling(struct ath12k *ar, u32 throttle_state)
{
	return 0;
}

static inline void ath12k_thermal_event_temperature(struct ath12k *ar,
						    int temperature)
{
}

#endif
#endif /* _ATH12K_THERMAL_ */
