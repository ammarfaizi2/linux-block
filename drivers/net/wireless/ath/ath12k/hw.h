/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef ATH12K_HW_H
#define ATH12K_HW_H

#include "wmi.h"

/* Target configuration defines */

/* Num VDEVS per radio */
#define TARGET_NUM_VDEVS	(16 + 1)

#define TARGET_NUM_PEERS_PDEV	(512 + TARGET_NUM_VDEVS)

/* Num of peers for Single Radio mode */
#define TARGET_NUM_PEERS_SINGLE		(TARGET_NUM_PEERS_PDEV)

/* Num of peers for DBS */
#define TARGET_NUM_PEERS_DBS		(2 * TARGET_NUM_PEERS_PDEV)

/* Num of peers for DBS_SBS */
#define TARGET_NUM_PEERS_DBS_SBS	(3 * TARGET_NUM_PEERS_PDEV)

/* Max num of stations (per radio) */
#define TARGET_NUM_STATIONS	512

#define TARGET_NUM_PEERS(x)	TARGET_NUM_PEERS_##x
#define TARGET_NUM_PEER_KEYS	2
#define TARGET_NUM_TIDS(x)	(2 * TARGET_NUM_PEERS(x) + \
				 4 * TARGET_NUM_VDEVS + 8)

#define TARGET_AST_SKID_LIMIT	16
#define TARGET_NUM_OFFLD_PEERS	4
#define TARGET_NUM_OFFLD_REORDER_BUFFS 4

#define TARGET_TX_CHAIN_MASK	(BIT(0) | BIT(1) | BIT(2) | BIT(4))
#define TARGET_RX_CHAIN_MASK	(BIT(0) | BIT(1) | BIT(2) | BIT(4))
#define TARGET_RX_TIMEOUT_LO_PRI	100
#define TARGET_RX_TIMEOUT_HI_PRI	40

#define TARGET_DECAP_MODE_RAW		0
#define TARGET_DECAP_MODE_NATIVE_WIFI	1
#define TARGET_DECAP_MODE_ETH		2

#define TARGET_SCAN_MAX_PENDING_REQS	4
#define TARGET_BMISS_OFFLOAD_MAX_VDEV	3
#define TARGET_ROAM_OFFLOAD_MAX_VDEV	3
#define TARGET_ROAM_OFFLOAD_MAX_AP_PROFILES	8
#define TARGET_GTK_OFFLOAD_MAX_VDEV	3
#define TARGET_NUM_MCAST_GROUPS		12
#define TARGET_NUM_MCAST_TABLE_ELEMS	64
#define TARGET_MCAST2UCAST_MODE		2
#define TARGET_TX_DBG_LOG_SIZE		1024
#define TARGET_RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK 1
#define TARGET_VOW_CONFIG		0
#define TARGET_NUM_MSDU_DESC		(2500)
#define TARGET_MAX_FRAG_ENTRIES		6
#define TARGET_MAX_BCN_OFFLD		16
#define TARGET_NUM_WDS_ENTRIES		32
#define TARGET_DMA_BURST_SIZE		1
#define TARGET_RX_BATCHMODE		1

#define ATH12K_HW_MAX_QUEUES		4
#define ATH12K_QUEUE_LEN		4096

#define ATH11k_HW_RATECODE_CCK_SHORT_PREAM_MASK  0x4

#define ATH12K_FW_DIR			"ath12k"

#define ATH12K_BOARD_MAGIC		"QCA-ATH12K-BOARD"
#define ATH12K_BOARD_API2_FILE		"board-2.bin"
#define ATH12K_DEFAULT_BOARD_FILE	"board.bin"
#define ATH12K_DEFAULT_CAL_FILE		"caldata.bin"
#define ATH12K_AMSS_FILE		"amss.bin"
#define ATH12K_M3_FILE			"m3.bin"
#define ATH12K_REGDB_FILE_NAME		"regdb.bin"

enum ath12k_hw_rate_cck {
	ATH12K_HW_RATE_CCK_LP_11M = 0,
	ATH12K_HW_RATE_CCK_LP_5_5M,
	ATH12K_HW_RATE_CCK_LP_2M,
	ATH12K_HW_RATE_CCK_LP_1M,
	ATH12K_HW_RATE_CCK_SP_11M,
	ATH12K_HW_RATE_CCK_SP_5_5M,
	ATH12K_HW_RATE_CCK_SP_2M,
};

enum ath12k_hw_rate_ofdm {
	ATH12K_HW_RATE_OFDM_48M = 0,
	ATH12K_HW_RATE_OFDM_24M,
	ATH12K_HW_RATE_OFDM_12M,
	ATH12K_HW_RATE_OFDM_6M,
	ATH12K_HW_RATE_OFDM_54M,
	ATH12K_HW_RATE_OFDM_36M,
	ATH12K_HW_RATE_OFDM_18M,
	ATH12K_HW_RATE_OFDM_9M,
};

enum ath12k_bus {
	ATH12K_BUS_PCI,
};

#define ATH12K_EXT_IRQ_GRP_NUM_MAX 11

struct hal_rx_desc;
struct hal_tcl_data_cmd;
struct htt_rx_ring_tlv_filter;
enum hal_encrypt_type;

struct ath12k_hw_ring_mask {
	u8 tx[ATH12K_EXT_IRQ_GRP_NUM_MAX];
	u8 rx_mon_dest[ATH12K_EXT_IRQ_GRP_NUM_MAX];
	u8 rx[ATH12K_EXT_IRQ_GRP_NUM_MAX];
	u8 rx_err[ATH12K_EXT_IRQ_GRP_NUM_MAX];
	u8 rx_wbm_rel[ATH12K_EXT_IRQ_GRP_NUM_MAX];
	u8 reo_status[ATH12K_EXT_IRQ_GRP_NUM_MAX];
	u8 host2rxdma[ATH12K_EXT_IRQ_GRP_NUM_MAX];
	u8 tx_mon_dest[ATH12K_EXT_IRQ_GRP_NUM_MAX];
};

struct ath12k_hw_params {
	const char *name;
	u16 hw_rev;
	u8 max_radios;
	u32 bdf_addr;

	struct {
		const char *dir;
		size_t board_size;
		size_t cal_offset;
	} fw;

	const struct ath12k_hw_ops *hw_ops;
	const struct ath12k_hw_ring_mask *ring_mask;

	bool internal_sleep_clock;

	const struct ath12k_hw_regs *regs;
	u32 qmi_service_ins_id;
	const struct ce_attr *host_ce_config;
	u32 ce_count;
	const struct ce_pipe_config *target_ce_config;
	u32 target_ce_count;
	const struct service_to_pipe *svc_to_ce_map;
	u32 svc_to_ce_map_len;

	bool single_pdev_only;

	bool rxdma1_enable;
	int num_rxmda_per_pdev;
	bool rx_mac_buf_ring;
	bool vdev_start_delay;
	u8 spectral_fft_sz;

	u16 interface_modes;
	bool supports_monitor;
	bool idle_ps;
	bool cold_boot_calib;
	bool supports_suspend;
	u32 hal_desc_sz;
	u32 num_tcl_banks;
};

struct ath12k_hw_ops {
	u8 (*get_hw_mac_from_pdev_id)(int pdev_id);
	int (*mac_id_to_pdev_id)(struct ath12k_hw_params *hw, int mac_id);
	int (*mac_id_to_srng_id)(struct ath12k_hw_params *hw, int mac_id);
};

extern const struct ath12k_hw_ops qcn92xx_ops;

extern const struct ath12k_hw_ring_mask ath12k_hw_ring_mask_qcn92xx;

static inline
int ath12k_hw_get_mac_from_pdev_id(struct ath12k_hw_params *hw,
				   int pdev_idx)
{
	if (hw->hw_ops->get_hw_mac_from_pdev_id)
		return hw->hw_ops->get_hw_mac_from_pdev_id(pdev_idx);

	return 0;
}

static inline int ath12k_hw_mac_id_to_pdev_id(struct ath12k_hw_params *hw,
					      int mac_id)
{
	if (hw->hw_ops->mac_id_to_pdev_id)
		return hw->hw_ops->mac_id_to_pdev_id(hw, mac_id);

	return 0;
}

static inline int ath12k_hw_mac_id_to_srng_id(struct ath12k_hw_params *hw,
					      int mac_id)
{
	if (hw->hw_ops->mac_id_to_srng_id)
		return hw->hw_ops->mac_id_to_srng_id(hw, mac_id);

	return 0;
}

struct ath12k_fw_ie {
	__le32 id;
	__le32 len;
	u8 data[];
};

enum ath12k_bd_ie_board_type {
	ATH12K_BD_IE_BOARD_NAME = 0,
	ATH12K_BD_IE_BOARD_DATA = 1,
};

enum ath12k_bd_ie_type {
	/* contains sub IEs of enum ath12k_bd_ie_board_type */
	ATH12K_BD_IE_BOARD = 0,
	ATH12K_BD_IE_BOARD_EXT = 1,
};

struct ath12k_hw_regs {
	u32 hal_tcl1_ring_id;
	u32 hal_tcl1_ring_misc;
	u32 hal_tcl1_ring_tp_addr_lsb;
	u32 hal_tcl1_ring_tp_addr_msb;
	u32 hal_tcl1_ring_consumer_int_setup_ix0;
	u32 hal_tcl1_ring_consumer_int_setup_ix1;
	u32 hal_tcl1_ring_msi1_base_lsb;
	u32 hal_tcl1_ring_msi1_base_msb;
	u32 hal_tcl1_ring_msi1_data;
	u32 hal_tcl_ring_base_lsb;

	u32 hal_tcl_status_ring_base_lsb;

	u32 pcie_qserdes_sysclk_en_sel;
	u32 pcie_pcs_osc_dtct_config_base;
};

extern const struct ath12k_hw_regs qcn92xx_regs;
#endif
