// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>

#include "debug.h"
#include "core.h"
#include "ce.h"
#include "hw.h"
#include "mhi.h"
#include "dp_rx.h"

static u8 ath12k_hw_qcn9274_mac_from_pdev_id(int pdev_idx)
{
	return pdev_idx;
}

static int ath12k_hw_mac_id_to_pdev_id_qcn9274(const struct ath12k_hw_params *hw,
					       int mac_id)
{
	return mac_id;
}

static int ath12k_hw_mac_id_to_srng_id_qcn9274(const struct ath12k_hw_params *hw,
					       int mac_id)
{
	return 0;
}

static u8 ath12k_hw_get_ring_selector_qcn9274(struct sk_buff *skb)
{
	return smp_processor_id();
}

static bool ath12k_dp_srng_is_comp_ring_qcn9274(int ring_num)
{
	if (ring_num < 3 || ring_num == 4)
		return true;

	return false;
}

static int ath12k_hw_mac_id_to_pdev_id_wcn7850(const struct ath12k_hw_params *hw,
					       int mac_id)
{
	return 0;
}

static int ath12k_hw_mac_id_to_srng_id_wcn7850(const struct ath12k_hw_params *hw,
					       int mac_id)
{
	return mac_id;
}

static u8 ath12k_hw_get_ring_selector_wcn7850(struct sk_buff *skb)
{
	return skb_get_queue_mapping(skb);
}

static bool ath12k_dp_srng_is_comp_ring_wcn7850(int ring_num)
{
	if (ring_num == 0 || ring_num == 2 || ring_num == 4)
		return true;

	return false;
}

static const struct ath12k_hw_ops qcn9274_ops = {
	.get_hw_mac_from_pdev_id = ath12k_hw_qcn9274_mac_from_pdev_id,
	.mac_id_to_pdev_id = ath12k_hw_mac_id_to_pdev_id_qcn9274,
	.mac_id_to_srng_id = ath12k_hw_mac_id_to_srng_id_qcn9274,
	.rxdma_ring_sel_config = ath12k_dp_rxdma_ring_sel_config_qcn9274,
	.get_ring_selector = ath12k_hw_get_ring_selector_qcn9274,
	.dp_srng_is_tx_comp_ring = ath12k_dp_srng_is_comp_ring_qcn9274,
};

static const struct ath12k_hw_ops wcn7850_ops = {
	.get_hw_mac_from_pdev_id = ath12k_hw_qcn9274_mac_from_pdev_id,
	.mac_id_to_pdev_id = ath12k_hw_mac_id_to_pdev_id_wcn7850,
	.mac_id_to_srng_id = ath12k_hw_mac_id_to_srng_id_wcn7850,
	.rxdma_ring_sel_config = ath12k_dp_rxdma_ring_sel_config_wcn7850,
	.get_ring_selector = ath12k_hw_get_ring_selector_wcn7850,
	.dp_srng_is_tx_comp_ring = ath12k_dp_srng_is_comp_ring_wcn7850,
};

#define ATH12K_TX_RING_MASK_0 0x1
#define ATH12K_TX_RING_MASK_1 0x2
#define ATH12K_TX_RING_MASK_2 0x4
#define ATH12K_TX_RING_MASK_3 0x8
#define ATH12K_TX_RING_MASK_4 0x10

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
static const struct ce_pipe_config ath12k_target_ce_config_wlan_qcn9274[] = {
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
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE13: Target CV prefetch */
	{
		.pipenum = __cpu_to_le32(13),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
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

/* Target firmware's Copy Engine configuration. */
static const struct ce_pipe_config ath12k_target_ce_config_wlan_wcn7850[] = {
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

	/* CE3: host->target WMI */
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

	/* CE7 used only by Host */
	{
		.pipenum = __cpu_to_le32(7),
		.pipedir = __cpu_to_le32(PIPEDIR_INOUT_H2H),
		.nentries = __cpu_to_le32(0),
		.nbytes_max = __cpu_to_le32(0),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR),
		.reserved = __cpu_to_le32(0),
	},

	/* CE8 target->host used only by IPA */
	{
		.pipenum = __cpu_to_le32(8),
		.pipedir = __cpu_to_le32(PIPEDIR_INOUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(16384),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},
	/* CE 9, 10, 11 are used by MHI driver */
};

/* Map from service/endpoint to Copy Engine.
 * This table is derived from the CE_PCI TABLE, above.
 * It is passed to the Target at startup for use by firmware.
 */
static const struct service_to_pipe ath12k_target_service_to_ce_map_wlan_qcn9274[] = {
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
		__cpu_to_le32(ATH12K_HTC_SVC_ID_PKT_LOG),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(5),
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

static const struct service_to_pipe ath12k_target_service_to_ce_map_wlan_wcn7850[] = {
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
		__cpu_to_le32(2),
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

	/* (Additions here) */

	{ /* must be last */
		__cpu_to_le32(0),
		__cpu_to_le32(0),
		__cpu_to_le32(0),
	},
};

static const struct ath12k_hw_ring_mask ath12k_hw_ring_mask_qcn9274 = {
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
	},
};

static const struct ath12k_hw_ring_mask ath12k_hw_ring_mask_wcn7850 = {
	.tx  = {
		ATH12K_TX_RING_MASK_0,
		ATH12K_TX_RING_MASK_2,
		ATH12K_TX_RING_MASK_4,
	},
	.rx_mon_dest = {
	},
	.rx = {
		0, 0, 0,
		ATH12K_RX_RING_MASK_0,
		ATH12K_RX_RING_MASK_1,
		ATH12K_RX_RING_MASK_2,
		ATH12K_RX_RING_MASK_3,
	},
	.rx_err = {
		ATH12K_RX_ERR_RING_MASK_0,
	},
	.rx_wbm_rel = {
		ATH12K_RX_WBM_REL_RING_MASK_0,
	},
	.reo_status = {
		ATH12K_REO_STATUS_RING_MASK_0,
	},
	.host2rxdma = {
	},
	.tx_mon_dest = {
	},
};

static const struct ath12k_hw_regs qcn9274_regs = {
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

	.hal_wbm_idle_ring_base_lsb = 0x00000d0c,
	.hal_wbm_idle_ring_misc_addr = 0x00000d1c,
	.hal_wbm_r0_idle_list_cntl_addr = 0x00000210,
	.hal_wbm_r0_idle_list_size_addr = 0x00000214,
	.hal_wbm_scattered_ring_base_lsb = 0x00000220,
	.hal_wbm_scattered_ring_base_msb = 0x00000224,
	.hal_wbm_scattered_desc_head_info_ix0 = 0x00000230,
	.hal_wbm_scattered_desc_head_info_ix1 = 0x00000234,
	.hal_wbm_scattered_desc_tail_info_ix0 = 0x00000240,
	.hal_wbm_scattered_desc_tail_info_ix1 = 0x00000244,
	.hal_wbm_scattered_desc_ptr_hp_addr = 0x0000024c,

	.hal_wbm_sw_release_ring_base_lsb = 0x0000034c,
	.hal_wbm_sw1_release_ring_base_lsb = 0x000003c4,
	.hal_wbm0_release_ring_base_lsb = 0x00000dd8,
	.hal_wbm1_release_ring_base_lsb = 0x00000e50,

	/* PCIe base address */
	.pcie_qserdes_sysclk_en_sel = 0x01e0c0a8,
	.pcie_pcs_osc_dtct_config_base = 0x01e0d45c,
};

static const struct ath12k_hw_regs wcn7850_regs = {
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

	.hal_wbm_idle_ring_base_lsb = 0x00000d3c,
	.hal_wbm_idle_ring_misc_addr = 0x00000d4c,
	.hal_wbm_r0_idle_list_cntl_addr = 0x00000240,
	.hal_wbm_r0_idle_list_size_addr = 0x00000244,
	.hal_wbm_scattered_ring_base_lsb = 0x00000250,
	.hal_wbm_scattered_ring_base_msb = 0x00000254,
	.hal_wbm_scattered_desc_head_info_ix0 = 0x00000260,
	.hal_wbm_scattered_desc_head_info_ix1 = 0x00000264,
	.hal_wbm_scattered_desc_tail_info_ix0 = 0x00000270,
	.hal_wbm_scattered_desc_tail_info_ix1 = 0x00000274,
	.hal_wbm_scattered_desc_ptr_hp_addr = 0x00000027c,

	.hal_wbm_sw_release_ring_base_lsb = 0x0000037c,
	.hal_wbm_sw1_release_ring_base_lsb = 0x00000284,
	.hal_wbm0_release_ring_base_lsb = 0x00000e08,
	.hal_wbm1_release_ring_base_lsb = 0x00000e80,

	/* PCIe base address */
	.pcie_qserdes_sysclk_en_sel = 0x01e0e0a8,
	.pcie_pcs_osc_dtct_config_base = 0x01e0f45c,
};

static const struct ath12k_hw_hal_params ath12k_hw_hal_params_qcn9274 = {
	.rx_buf_rbm = HAL_RX_BUF_RBM_SW3_BM,
	.wbm2sw_cc_enable = HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW0_EN |
			    HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW1_EN |
			    HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW2_EN |
			    HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW3_EN |
			    HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW4_EN,
};

static const struct ath12k_hw_hal_params ath12k_hw_hal_params_wcn7850 = {
	.rx_buf_rbm = HAL_RX_BUF_RBM_SW1_BM,
	.wbm2sw_cc_enable = HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW0_EN |
			    HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW2_EN |
			    HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW3_EN |
			    HAL_WBM_SW_COOKIE_CONV_CFG_WBM2SW4_EN,
};

/* TODO: WCN7850 firmware requires this config now but in future it should
 * be optional
 */
static const char ath12k_hw_qdss_config_wcn7850[] = {
	"seq_start;\n"
	"seq_type:mem_req;\n"
	"sink:etb_lp,0x1,0x1000;\n"
	"sw_pwr_mask:0x35;\n"
	"seq_end;\n"
	"seq_start;\n"
	"seq_type:mac_event_trace;\n"
	"subsys_cfg_start:umac;\n"
	"cxc_eb0:0x2,0x0,0x0,0x0,0x0;\n"
	"reo_eb0:0x4,0x0,0x0,0x0,0x0;\n"
	"tqm_eb0:0x5,0x0,0x87C00000,0x0,0x0;\n"
	"tcl_eb0:0x6,0x0,0x0,0x0,0x0;\n"
	"wbm_eb0:0x7,0x0,0x0,0x0,0x0;\n"
	"cxc_eb1:0x8,0x0,0x0,0x0,0x0;\n"
	"tcl_eb1:0x9,0x0,0x0,0x0,0x0;\n"
	"reo_eb1:0xA,0x0,0x0,0x0,0x0;\n"
	"tqm_eb1:0xB,0x0,0x0,0x0,0x0;\n"
	"wbm_eb1:0xC,0x0,0x0,0x0,0x0;\n"
	"pmm:0xD,0x0,0x0,0x0,0x0;\n"
	"mxi:0xE,0x3922234,0x0,0x0,0x0;\n"
	"lpm:0xF,0x30,0x0,0x0,0x0;\n"
	"memw:0x0;\n"
	"subsys_cfg_end:umac;\n"
	"subsys_cfg_start:dmac;\n"
	"swevt:0x0,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0x00000000;\n"
	"txdma_eb0:0x1,0x200,0x0,0x0,0x0;\n"
	"txdma_eb1:0x2,0x12220,0xAF0,0x0,0x0;\n"
	"txdma_eb2:0x3,0x12220,0xAF0,0x0,0x0;\n"
	"rxdma_eb0:0x4,0x93297E3F,0xC00000,0x0,0x0;\n"
	"rxdma_eb1:0x5,0x707F,0x0,0x0,0x0;\n"
	"txole_eb0:0x6,0xFFFFFFFF,0x0,0x0,0x0;\n"
	"txole_eb1:0x7,0x781F0734,0x6,0x0,0x0;\n"
	"txole_eb2:0x8,0x781F0734,0x6,0x0,0x0;\n"
	"rxole_eb0:0x9,0x3FF,0x0,0x0,0x0;\n"
	"rxole_eb1:0xa,0x28F,0x0,0x0,0x0;\n"
	"rxole_eb2:0xb,0x20F8019F,0x0,0x0,0x0;\n"
	"crypto:0xC,0xFF3FFF,0x0,0x0,0x0;\n"
	"mxi:0xD,0x3122234,0x0,0x0,0x0;\n"
	"sfm_eb0:0xE,0x40000006,0x7F9,0x0,0x0;\n"
	"txmon_eb0:0x12,0x0,0x0,0x0,0x0;\n"
	"txmon_eb1:0x13,0x0,0x0,0x0,0x0;\n"
	"memw:0x0;\n"
	"subsys_cfg_end:dmac;\n"
	"subsys_cfg_start:pmac0;\n"
	"swevt:0x0,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0x00000000;\n"
	"hwsch:0x1,0x3FFFF7,0x30000,0x0,0x0;\n"
	"pdg:0x2,0xE430F87,0x622856E,0x0,0x0;\n"
	"txpcu_eb0:0x8,0xFFFFFFF7,0x1EFF,0x0,0x0;\n"
	"rxpcu_eb0:0x9,0x10060217,0x1F24500,0x0,0x0;\n"
	"rri:0xa,0x0,0x0,0x0,0x0;\n"
	"ampi:0xb,0x69C07,0x0,0x0,0x0;\n"
	"mxi:0xd,0x3122234,0x0,0x0,0x0;\n"
	"txpcu_eb1:0x10,0x0,0x0,0x0,0x0;\n"
	"sfm_eb1:0x12,0x40000003,0x7F8,0x0,0x0;\n"
	"rxpcu_eb1:0x13,0x0,0x0,0x0,0x0;\n"
	"hwmlo:0x1c,0x1C100004,0x0,0x0,0x0;\n"
	"memw:0x0;\n"
	"subsys_cfg_end:pmac0;\n"
	"subsys_cfg_start:pmac1;\n"
	"swevt:0x0,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0x00000000;\n"
	"hwsch:0x1,0x3FFFF7,0x30000,0x0,0x0;\n"
	"pdg:0x2,0xE430F87,0x622856E,0x0,0x0;\n"
	"txpcu_eb0:0x8,0xFFFFFFF7,0x1EFF,0x0,0x0;\n"
	"rxpcu_eb0:0x9,0x10060217,0x1F24500,0x0,0x0;\n"
	"rri:0xa,0x0,0x0,0x0,0x0;\n"
	"ampi:0xb,0x69C07,0x0,0x0,0x0;\n"
	"mxi:0xd,0x3122234,0x0,0x0,0x0;\n"
	"txpcu_eb1:0x10,0x0,0x0,0x0,0x0;\n"
	"sfm_eb1:0x12,0x40000003,0x7F8,0x0,0x0;\n"
	"rxpcu_eb1:0x13,0x0,0x0,0x0,0x0;\n"
	"hwmlo:0x1c,0x1C100004,0x0,0x0,0x0;\n"
	"memw:0x0;\n"
	"subsys_cfg_end:pmac1;\n"
	"seq_end;\n"
	"seq_start;\n"
	"seq_type:phy_event_trace;\n"
	"subsys_cfg_start:phya0;\n"
	"data_tlv:1;\n"
	"tpc:0x3,0x00000000,0x00000000;\n"
	"cal:0x4,0x00000000,0x00000000;\n"
	"impcorr:0x5,0x00000000,0x00000000;\n"
	"mpi:0x6,0x00000006,0x00000000;\n"
	"fft:0x7,0x00000000,0x00000000;\n"
	"txtd:0x8,0x00000000,0x00000000;\n"
	"pmi:0x9,0x0000000A,0x00000000;\n"
	"rxtd:0xa,0x0000000A,0x00000110;\n"
	"demfront:0xb,0x00000000,0x00000000;\n"
	"pcss:0xc,0x0000007D,0x00000000;\n"
	"txfd:0xd,0x00000000,0x00000000;\n"
	"robe:0xe,0x00000000,0x00000000;\n"
	"dmac_0_1:0x10,0x00000000,0x00000000;\n"
	"dmac_2_3:0x11,0x00000000,0x00000000;\n"
	"dmac_4_5:0x12,0x00000000,0x00000000;\n"
	"dmac_6:0x13,0x00000000,0x00000000;\n"
	"eos:0x0,0x00000000,0x00000000;\n"
	"subsys_cfg_end:phya0;\n"
	"subsys_cfg_start:phya1;\n"
	"data_tlv:1;\n"
	"tpc:0x3,0x00000000,0x00000000;\n"
	"cal:0x4,0x00000000,0x00000000;\n"
	"impcorr:0x5,0x00000000,0x00000000;\n"
	"mpi:0x6,0x00000006,0x00000000;\n"
	"fft:0x7,0x00000000,0x00000000;\n"
	"txtd:0x8,0x00000000,0x00000000;\n"
	"pmi:0x9,0x0000000A,0x00000000;\n"
	"rxtd:0xa,0x0000000A,0x00000110;\n"
	"demfront:0xb,0x00000000,0x00000000;\n"
	"pcss:0xc,0x0000007D,0x00000000;\n"
	"txfd:0xd,0x00000000,0x00000000;\n"
	"robe:0xe,0x00000000,0x00000000;\n"
	"dmac_0_1:0x10,0x00000000,0x00000000;\n"
	"dmac_2_3:0x11,0x00000000,0x00000000;\n"
	"dmac_4_5:0x12,0x00000000,0x00000000;\n"
	"dmac_6:0x13,0x00000000,0x00000000;\n"
	"eos:0x0,0x00000000,0x00000000;\n"
	"subsys_cfg_end:phya1;\n"
	"seq_end;\n"
};

static const struct ath12k_hw_params ath12k_hw_params[] = {
	{
		.name = "qcn9274 hw1.0",
		.hw_rev = ATH12K_HW_QCN9274_HW10,
		.fw = {
			.dir = "QCN9274/hw1.0",
			.board_size = 256 * 1024,
			.cal_offset = 128 * 1024,
		},
		.max_radios = 1,
		.single_pdev_only = false,
		.qmi_service_ins_id = ATH12K_QMI_WLFW_SERVICE_INS_ID_V01_QCN9274,
		.internal_sleep_clock = false,

		.hw_ops = &qcn9274_ops,
		.ring_mask = &ath12k_hw_ring_mask_qcn9274,
		.regs = &qcn9274_regs,

		.host_ce_config = ath12k_host_ce_config_qcn9274,
		.ce_count = 16,
		.target_ce_config = ath12k_target_ce_config_wlan_qcn9274,
		.target_ce_count = 12,
		.svc_to_ce_map = ath12k_target_service_to_ce_map_wlan_qcn9274,
		.svc_to_ce_map_len = 18,

		.hal_params = &ath12k_hw_hal_params_qcn9274,

		.rxdma1_enable = false,
		.num_rxmda_per_pdev = 1,
		.num_rxdma_dst_ring = 0,
		.rx_mac_buf_ring = false,
		.vdev_start_delay = false,

		.interface_modes = BIT(NL80211_IFTYPE_STATION) |
					BIT(NL80211_IFTYPE_AP),
		.supports_monitor = false,

		.idle_ps = false,
		.download_calib = true,
		.supports_suspend = false,
		.tcl_ring_retry = true,
		.reoq_lut_support = false,
		.supports_shadow_regs = false,

		.hal_desc_sz = sizeof(struct hal_rx_desc_qcn9274),
		.num_tcl_banks = 48,
		.max_tx_ring = 4,
		.static_window_map = true,

		.mhi_config = &ath12k_mhi_config_qcn9274,

		.wmi_init = ath12k_wmi_init_qcn9274,

		.hal_ops = &hal_qcn9274_ops,

		.qdss_config = NULL,
		.qdss_config_len = 0,
	},
	{
		.name = "wcn7850 hw2.0",
		.hw_rev = ATH12K_HW_WCN7850_HW20,

		.fw = {
			.dir = "WCN7850/hw2.0",
			.board_size = 256 * 1024,
			.cal_offset = 256 * 1024,
		},

		.max_radios = 1,
		.single_pdev_only = true,
		.qmi_service_ins_id = ATH12K_QMI_WLFW_SERVICE_INS_ID_V01_WCN7850,
		.internal_sleep_clock = true,

		.hw_ops = &wcn7850_ops,
		.ring_mask = &ath12k_hw_ring_mask_wcn7850,
		.regs = &wcn7850_regs,

		.host_ce_config = ath12k_host_ce_config_wcn7850,
		.ce_count = 9,
		.target_ce_config = ath12k_target_ce_config_wlan_wcn7850,
		.target_ce_count = 9,
		.svc_to_ce_map = ath12k_target_service_to_ce_map_wlan_wcn7850,
		.svc_to_ce_map_len = 14,

		.hal_params = &ath12k_hw_hal_params_wcn7850,

		.rxdma1_enable = false,
		.num_rxmda_per_pdev = 2,
		.num_rxdma_dst_ring = 1,
		.rx_mac_buf_ring = true,
		.vdev_start_delay = true,

		.interface_modes = BIT(NL80211_IFTYPE_STATION),
		.supports_monitor = false,

		.idle_ps = false,
		.download_calib = false,
		.supports_suspend = false,
		.tcl_ring_retry = false,
		.reoq_lut_support = false,
		.supports_shadow_regs = true,

		.hal_desc_sz = sizeof(struct hal_rx_desc_wcn7850),
		.num_tcl_banks = 7,
		.max_tx_ring = 3,
		.static_window_map = false,

		.mhi_config = &ath12k_mhi_config_wcn7850,

		.wmi_init = ath12k_wmi_init_wcn7850,

		.hal_ops = &hal_wcn7850_ops,

		.qdss_config = ath12k_hw_qdss_config_wcn7850,
		.qdss_config_len = sizeof(ath12k_hw_qdss_config_wcn7850),
	},
};

int ath12k_hw_init(struct ath12k_base *ab)
{
	const struct ath12k_hw_params *hw_params = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(ath12k_hw_params); i++) {
		hw_params = &ath12k_hw_params[i];

		if (hw_params->hw_rev == ab->hw_rev)
			break;
	}

	if (i == ARRAY_SIZE(ath12k_hw_params)) {
		ath12k_err(ab, "Unsupported hardware version: 0x%x\n", ab->hw_rev);
		return -EINVAL;
	}

	ab->hw_params = hw_params;

	ath12k_info(ab, "Hardware name: %s\n", ab->hw_params->name);

	return 0;
}
