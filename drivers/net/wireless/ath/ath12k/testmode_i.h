/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

/* "API" level of the ath12k testmode interface. Bump it after every
 * incompatible interface change.
 */
#define ATH12K_TESTMODE_VERSION_MAJOR 1

/* Bump this after every _compatible_ interface change, for example
 * addition of a new command or an attribute.
 */
#define ATH12K_TESTMODE_VERSION_MINOR 0

#define ATH12K_TM_DATA_MAX_LEN		5000

enum ath12k_tm_attr {
	__ATH12K_TM_ATTR_INVALID		= 0,
	ATH12K_TM_ATTR_CMD			= 1,
	ATH12K_TM_ATTR_DATA			= 2,
	ATH12K_TM_ATTR_WMI_CMDID		= 3,
	ATH12K_TM_ATTR_VERSION_MAJOR		= 4,
	ATH12K_TM_ATTR_VERSION_MINOR		= 5,
	ATH12K_TM_ATTR_WMI_OP_VERSION		= 6,

	/* keep last */
	__ATH12K_TM_ATTR_AFTER_LAST,
	ATH12K_TM_ATTR_MAX		= __ATH12K_TM_ATTR_AFTER_LAST - 1,
};

/* All ath12k testmode interface commands specified in
 * ATH12K_TM_ATTR_CMD
 */
enum ath12k_tm_cmd {
	/* Returns the supported ath12k testmode interface version in
	 * ATH12K_TM_ATTR_VERSION. Always guaranteed to work. User space
	 * uses this to verify it's using the correct version of the
	 * testmode interface
	 */
	ATH12K_TM_CMD_GET_VERSION = 0,

	/* The command used to transmit a WMI command to the firmware and
	 * the event to receive WMI events from the firmware. Without
	 * struct wmi_cmd_hdr header, only the WMI payload. Command id is
	 * provided with ATH12K_TM_ATTR_WMI_CMDID and payload in
	 * ATH12K_TM_ATTR_DATA.
	 */
	ATH12K_TM_CMD_WMI = 1,
};
