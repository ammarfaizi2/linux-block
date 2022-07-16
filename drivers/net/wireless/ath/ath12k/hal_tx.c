// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "hal_desc.h"
#include "hal.h"
#include "hal_tx.h"
#include "hif.h"

#define DSCP_TID_MAP_TBL_ENTRY_SIZE 64

/* dscp_tid_map - Default DSCP-TID mapping
 *
 * DSCP        TID
 * 000000      0
 * 001000      1
 * 010000      2
 * 011000      3
 * 100000      4
 * 101000      5
 * 110000      6
 * 111000      7
 */
static const u8 dscp_tid_map[DSCP_TID_MAP_TBL_ENTRY_SIZE] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4,
	5, 5, 5, 5, 5, 5, 5, 5,
	6, 6, 6, 6, 6, 6, 6, 6,
	7, 7, 7, 7, 7, 7, 7, 7,
};

void ath12k_hal_tx_cmd_desc_setup(struct ath12k_base *ab, void *cmd,
				  struct hal_tx_info *ti)
{
	struct hal_tcl_data_cmd *tcl_cmd = (struct hal_tcl_data_cmd *)cmd;

	tcl_cmd->buf_addr_info.info0 =
		u32_encode_bits(ti->paddr, BUFFER_ADDR_INFO0_ADDR);
	tcl_cmd->buf_addr_info.info1 =
		u32_encode_bits(((uint64_t)ti->paddr >> HAL_ADDR_MSB_REG_SHIFT),
				BUFFER_ADDR_INFO1_ADDR);
	tcl_cmd->buf_addr_info.info1 |=
		u32_encode_bits((ti->rbm_id), BUFFER_ADDR_INFO1_RET_BUF_MGR) |
		u32_encode_bits(ti->desc_id, BUFFER_ADDR_INFO1_SW_COOKIE);

	tcl_cmd->info0 =
		u32_encode_bits(ti->type, HAL_TCL_DATA_CMD_INFO0_DESC_TYPE) |
		u32_encode_bits(ti->bank_id, HAL_TCL_DATA_CMD_INFO0_BANK_ID);

	tcl_cmd->info1 =
		u32_encode_bits(ti->meta_data_flags,
				HAL_TCL_DATA_CMD_INFO1_CMD_NUM);

	tcl_cmd->info2 = ti->flags0 |
		u32_encode_bits(ti->data_len, HAL_TCL_DATA_CMD_INFO2_DATA_LEN) |
		u32_encode_bits(ti->pkt_offset, HAL_TCL_DATA_CMD_INFO2_PKT_OFFSET);

	tcl_cmd->info3 = (ti->flags1 |
		u32_encode_bits(ti->tid, HAL_TCL_DATA_CMD_INFO3_TID)) |
		u32_encode_bits(ti->lmac_id, HAL_TCL_DATA_CMD_INFO3_PMAC_ID) |
		u32_encode_bits(ti->vdev_id, HAL_TCL_DATA_CMD_INFO3_VDEV_ID);

	tcl_cmd->info4 = u32_encode_bits(ti->bss_ast_idx,
					 HAL_TCL_DATA_CMD_INFO4_SEARCH_INDEX) |
			 u32_encode_bits(ti->bss_ast_hash,
					 HAL_TCL_DATA_CMD_INFO4_CACHE_SET_NUM);
	tcl_cmd->info5 = 0;
}

void ath12k_hal_tx_set_dscp_tid_map(struct ath12k_base *ab, int id)
{
	u32 ctrl_reg_val;
	u32 addr;
	u8 hw_map_val[HAL_DSCP_TID_TBL_SIZE];
	int i;
	u32 value;
	int cnt = 0;

	ctrl_reg_val = ath12k_hif_read32(ab, HAL_SEQ_WCSS_UMAC_TCL_REG +
					 HAL_TCL1_RING_CMN_CTRL_REG);
	/* Enable read/write access */
	ctrl_reg_val |= HAL_TCL1_RING_CMN_CTRL_DSCP_TID_MAP_PROG_EN;
	ath12k_hif_write32(ab, HAL_SEQ_WCSS_UMAC_TCL_REG +
			   HAL_TCL1_RING_CMN_CTRL_REG, ctrl_reg_val);

	addr = HAL_SEQ_WCSS_UMAC_TCL_REG + HAL_TCL1_RING_DSCP_TID_MAP +
	       (4 * id * (HAL_DSCP_TID_TBL_SIZE / 4));

	/* Configure each DSCP-TID mapping in three bits there by configure
	 * three bytes in an iteration.
	 */
	for (i = 0; i < DSCP_TID_MAP_TBL_ENTRY_SIZE; i += 8) {
		value = u32_encode_bits(dscp_tid_map[i],
					HAL_TCL1_RING_FIELD_DSCP_TID_MAP0) |
			u32_encode_bits(dscp_tid_map[i + 1],
					HAL_TCL1_RING_FIELD_DSCP_TID_MAP1) |
			u32_encode_bits(dscp_tid_map[i + 2],
					HAL_TCL1_RING_FIELD_DSCP_TID_MAP2) |
			u32_encode_bits(dscp_tid_map[i + 3],
					HAL_TCL1_RING_FIELD_DSCP_TID_MAP3) |
			u32_encode_bits(dscp_tid_map[i + 4],
					HAL_TCL1_RING_FIELD_DSCP_TID_MAP4) |
			u32_encode_bits(dscp_tid_map[i + 5],
					HAL_TCL1_RING_FIELD_DSCP_TID_MAP5) |
			u32_encode_bits(dscp_tid_map[i + 6],
					HAL_TCL1_RING_FIELD_DSCP_TID_MAP6) |
			u32_encode_bits(dscp_tid_map[i + 7],
					HAL_TCL1_RING_FIELD_DSCP_TID_MAP7);

		memcpy(&hw_map_val[cnt], (u8 *)&value, 3);
		cnt += 3;
	}

	for (i = 0; i < HAL_DSCP_TID_TBL_SIZE; i += 4) {
		ath12k_hif_write32(ab, addr, *(u32 *)&hw_map_val[i]);
		addr += 4;
	}

	/* Disable read/write access */
	ctrl_reg_val = ath12k_hif_read32(ab, HAL_SEQ_WCSS_UMAC_TCL_REG +
					 HAL_TCL1_RING_CMN_CTRL_REG);
	ctrl_reg_val &= ~HAL_TCL1_RING_CMN_CTRL_DSCP_TID_MAP_PROG_EN;
	ath12k_hif_write32(ab, HAL_SEQ_WCSS_UMAC_TCL_REG +
			   HAL_TCL1_RING_CMN_CTRL_REG,
			   ctrl_reg_val);
}

void ath12k_hal_tx_configure_bank_register(struct ath12k_base *ab, u32 bank_config,
					   u8 bank_id)
{
	ath12k_hif_write32(ab, HAL_TCL_SW_CONFIG_BANK_ADDR + 4 * bank_id,
			   bank_config);
}
