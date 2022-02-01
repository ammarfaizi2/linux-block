// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>

#include "hw.h"
#include "core.h"
#include "ce.h"

static u8 ath12k_hw_qcn92xx_mac_from_pdev_id(int pdev_idx)
{
	return pdev_idx;
}

static int ath12k_hw_mac_id_to_pdev_id_qcn92xx(struct ath12k_hw_params *hw,
					       int mac_id)
{
	return mac_id;
}

static int ath12k_hw_mac_id_to_srng_id_qcn92xx(struct ath12k_hw_params *hw,
					       int mac_id)
{
	return 0;
}

const struct ath12k_hw_ops qcn92xx_ops = {
	.get_hw_mac_from_pdev_id = ath12k_hw_qcn92xx_mac_from_pdev_id,
	.mac_id_to_pdev_id = ath12k_hw_mac_id_to_pdev_id_qcn92xx,
	.mac_id_to_srng_id = ath12k_hw_mac_id_to_srng_id_qcn92xx,
};

#define ATH12K_TX_RING_MASK_0 0x1
#define ATH12K_TX_RING_MASK_1 0x2
#define ATH12K_TX_RING_MASK_2 0x4
#define ATH12K_TX_RING_MASK_3 0x8

#define ATH12K_RX_RING_MASK_0 0x1
#define ATH12K_RX_RING_MASK_1 0x2
#define ATH12K_RX_RING_MASK_2 0x4
#define ATH12K_RX_RING_MASK_3 0x8

#define ATH12K_RX_ERR_RING_MASK_0 0x1

#define ATH12K_RX_WBM_REL_RING_MASK_0 0x1

#define ATH12K_REO_STATUS_RING_MASK_0 0x1

#define ATH12K_HOST2RXDMA_RING_MASK_0 0x1

#define ATH12K_RX_MON_RING_MASK_0 0x1
#define ATH12K_RX_MON_RING_MASK_1 0x2
#define ATH12K_RX_MON_RING_MASK_2 0x4

#define ATH12K_TX_MON_RING_MASK_0 0x1
#define ATH12K_TX_MON_RING_MASK_1 0x2

/* Target firmware's Copy Engine configuration. */
const struct ce_pipe_config ath12k_target_ce_config_wlan_qcn92xx[] = {
	/* CE0: host->target HTC control and raw streams */
	{
		.pipenum = __cpu_to_le32(0),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE1: target->host HTT + HTC control */
	{
		.pipenum = __cpu_to_le32(1),
		.pipedir = __cpu_to_le32(PIPEDIR_IN),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE2: target->host WMI */
	{
		.pipenum = __cpu_to_le32(2),
		.pipedir = __cpu_to_le32(PIPEDIR_IN),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE3: host->target WMI (mac0) */
	{
		.pipenum = __cpu_to_le32(3),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE4: host->target HTT */
	{
		.pipenum = __cpu_to_le32(4),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(256),
		.nbytes_max = __cpu_to_le32(256),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR),
		.reserved = __cpu_to_le32(0),
	},

	/* CE5: target->host Pktlog */
	{
		.pipenum = __cpu_to_le32(5),
		.pipedir = __cpu_to_le32(PIPEDIR_IN),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE6: Reserved for target autonomous hif_memcpy */
	{
		.pipenum = __cpu_to_le32(6),
		.pipedir = __cpu_to_le32(PIPEDIR_INOUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(16384),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE7: host->target WMI (mac1) */
	{
		.pipenum = __cpu_to_le32(7),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE8: Reserved for target autonomous hif_memcpy */
	{
		.pipenum = __cpu_to_le32(8),
		.pipedir = __cpu_to_le32(PIPEDIR_INOUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(16384),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE9, 10 and 11: Reserved for MHI */

	/* CE12: Target CV prefetch */
	{
		.pipenum = __cpu_to_le32(12),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(8192),
		.reserved = __cpu_to_le32(0),
	},

	/* CE13: Target CV prefetch */
	{
		.pipenum = __cpu_to_le32(13),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(8192),
		.reserved = __cpu_to_le32(0),
	},

	/* CE14: WMI logging/CFR/Spectral/Radar */
	{
		.pipenum = __cpu_to_le32(14),
		.pipedir = __cpu_to_le32(PIPEDIR_IN),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE15: Reserved */
};

/* Map from service/endpoint to Copy Engine.
 * This table is derived from the CE_PCI TABLE, above.
 * It is passed to the Target at startup for use by firmware.
 */
const struct service_to_pipe ath12k_target_service_to_ce_map_wlan_qcn92xx[] = {
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_DATA_VO),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_DATA_VO),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_DATA_BK),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_DATA_BK),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_DATA_BE),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_DATA_BE),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_DATA_VI),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_DATA_VI),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_CONTROL),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_CONTROL),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_RSVD_CTRL),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(0),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_RSVD_CTRL),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(1),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_TEST_RAW_STREAMS),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(0),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_TEST_RAW_STREAMS),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(1),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_HTT_DATA_MSG),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(4),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_HTT_DATA_MSG),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(1),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_PKT_LOG),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(5),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_CONTROL_MAC1),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(7),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_CONTROL_MAC1),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH12K_HTC_SVC_ID_WMI_CONTROL_DIAG),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(14),
	},

	/* (Additions here) */

	{ /* must be last */
		__cpu_to_le32(0),
		__cpu_to_le32(0),
		__cpu_to_le32(0),
	},
};

const struct ath12k_hw_ring_mask ath12k_hw_ring_mask_qcn92xx = {
	.tx  = {
		ATH12K_TX_RING_MASK_0,
		ATH12K_TX_RING_MASK_1,
		ATH12K_TX_RING_MASK_2,
		ATH12K_TX_RING_MASK_3,
	},
	.rx_mon_dest = {
		0, 0, 0,
		ATH12K_RX_MON_RING_MASK_0,
		ATH12K_RX_MON_RING_MASK_1,
		ATH12K_RX_MON_RING_MASK_2,
	},
	.rx = {
		0, 0, 0, 0,
		ATH12K_RX_RING_MASK_0,
		ATH12K_RX_RING_MASK_1,
		ATH12K_RX_RING_MASK_2,
		ATH12K_RX_RING_MASK_3,
	},
	.rx_err = {
		0, 0, 0,
		ATH12K_RX_ERR_RING_MASK_0,
	},
	.rx_wbm_rel = {
		0, 0, 0,
		ATH12K_RX_WBM_REL_RING_MASK_0,
	},
	.reo_status = {
		0, 0, 0,
		ATH12K_REO_STATUS_RING_MASK_0,
	},
	.host2rxdma = {
		0, 0, 0,
		ATH12K_HOST2RXDMA_RING_MASK_0,
	},
	.tx_mon_dest = {
		ATH12K_TX_MON_RING_MASK_0,
		ATH12K_TX_MON_RING_MASK_1,
		0, 0, 0, 0, 0, 0
	},
};

const struct ath12k_hw_regs qcn92xx_regs = {
	/* SW2TCL(x) R0 ring configuration address */
	.hal_tcl1_ring_id = 0x00000908,
	.hal_tcl1_ring_misc = 0x00000910,
	.hal_tcl1_ring_tp_addr_lsb = 0x0000091c,
	.hal_tcl1_ring_tp_addr_msb = 0x00000920,
	.hal_tcl1_ring_consumer_int_setup_ix0 = 0x00000930,
	.hal_tcl1_ring_consumer_int_setup_ix1 = 0x00000934,
	.hal_tcl1_ring_msi1_base_lsb = 0x00000948,
	.hal_tcl1_ring_msi1_base_msb = 0x0000094c,
	.hal_tcl1_ring_msi1_data = 0x00000950,
	.hal_tcl_ring_base_lsb = 0x00000b58,

	/* TCL STATUS ring address */
	.hal_tcl_status_ring_base_lsb = 0x00000d38,

	/* PCIe base address */
	.pcie_qserdes_sysclk_en_sel = 0x01e0c0a8,
	.pcie_pcs_osc_dtct_config_base = 0x01e0d45c,
};
