// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2018-2019 The Linux Foundation. All rights reserved.
 */

#include "qmi.h"
#include "core.h"
#include "debug.h"
#include <linux/of.h>
#include <linux/firmware.h>

static struct elem_info qmi_wlanfw_host_cap_req_msg_v01_ei[] = {
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   num_clients_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   num_clients),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   wake_msi_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   wake_msi),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   gpios_valid),
	},
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   gpios_len),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = QMI_WLFW_MAX_NUM_GPIO_V01,
		.elem_size      = sizeof(u32),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   gpios),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   nm_modem_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   nm_modem),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   bdf_support_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   bdf_support),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x15,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   bdf_cache_support_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x15,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   bdf_cache_support),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x16,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   m3_support_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x16,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   m3_support),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x17,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   m3_cache_support_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x17,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   m3_cache_support),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x18,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   cal_filesys_support_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x18,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   cal_filesys_support),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x19,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   cal_cache_support_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x19,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   cal_cache_support),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1A,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   cal_done_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1A,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   cal_done),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1B,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   mem_bucket_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1B,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   mem_bucket),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1C,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   mem_cfg_mode_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1C,
		.offset         = offsetof(struct qmi_wlanfw_host_cap_req_msg_v01,
					   mem_cfg_mode),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_host_cap_resp_msg_v01_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
				     struct qmi_wlanfw_host_cap_resp_msg_v01,
				     resp),
		.ei_array	= get_qmi_response_type_v01_ei(),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_ind_register_req_msg_v01_ei[] = {
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     fw_ready_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     fw_ready_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     initiate_cal_download_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     initiate_cal_download_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     initiate_cal_update_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     initiate_cal_update_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     msa_ready_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     msa_ready_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     pin_connect_result_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     pin_connect_result_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x15,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     client_id_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x15,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     client_id),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x16,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     request_mem_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x16,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     request_mem_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x17,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     fw_mem_ready_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x17,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     fw_mem_ready_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x18,
		.offset         = offsetof(struct qmi_wlanfw_ind_register_req_msg_v01,
					   fw_init_done_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x18,
		.offset         = offsetof(struct qmi_wlanfw_ind_register_req_msg_v01,
					   fw_init_done_enable),
	},

	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x19,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     rejuvenate_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x19,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     rejuvenate_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1A,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     xo_cal_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1A,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     xo_cal_enable),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1B,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     cal_done_enable_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x1B,
		.offset         = offsetof(
				     struct qmi_wlanfw_ind_register_req_msg_v01,
				     cal_done_enable),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_ind_register_resp_msg_v01_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
				    struct qmi_wlanfw_ind_register_resp_msg_v01,
				    resp),
		.ei_array      = get_qmi_response_type_v01_ei(),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				    struct qmi_wlanfw_ind_register_resp_msg_v01,
				    fw_status_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_8_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u64),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				    struct
				    qmi_wlanfw_ind_register_resp_msg_v01,
				    fw_status),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_mem_cfg_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_8_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u64),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_cfg_s_v01,
					   offset),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_cfg_s_v01,
					   size),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_cfg_s_v01,
					   secure_flag),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};


static struct elem_info qmi_wlanfw_mem_seg_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_seg_s_v01,
					   size),
	},
	{
		.data_type      = QMI_SIGNED_4_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(enum qmi_wlanfw_mem_type_enum_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_seg_s_v01,
					   type),
	},
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_seg_s_v01,
					   mem_cfg_len),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = QMI_WLANFW_MAX_NUM_MEM_CFG_V01,
		.elem_size      = sizeof(struct qmi_wlanfw_mem_cfg_s_v01),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_seg_s_v01,
					   mem_cfg),
		.ei_array      = qmi_wlanfw_mem_cfg_s_v01_ei,
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};


static struct elem_info qmi_wlanfw_request_mem_ind_msg_v01_ei[] = {
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct qmi_wlanfw_request_mem_ind_msg_v01,
					   mem_seg_len),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = QMI_WLANFW_MAX_NUM_MEM_SEG_V01,
		.elem_size      = sizeof(struct qmi_wlanfw_mem_seg_s_v01),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct qmi_wlanfw_request_mem_ind_msg_v01,
					   mem_seg),
		.ei_array      = qmi_wlanfw_mem_seg_s_v01_ei,
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_mem_seg_resp_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_8_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u64),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_seg_resp_s_v01,
					   addr),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_seg_resp_s_v01,
					   size),
	},
	{
		.data_type      = QMI_SIGNED_4_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(enum qmi_wlanfw_mem_type_enum_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_seg_resp_s_v01,
					   type),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_mem_seg_resp_s_v01,
					   restore),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_respond_mem_req_msg_v01_ei[] = {
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(
				     struct qmi_wlanfw_respond_mem_req_msg_v01,
				     mem_seg_len),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = QMI_WLANFW_MAX_NUM_MEM_SEG_V01,
		.elem_size      = sizeof(struct qmi_wlanfw_mem_seg_resp_s_v01),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(
				     struct qmi_wlanfw_respond_mem_req_msg_v01,
				     mem_seg),
		.ei_array      = qmi_wlanfw_mem_seg_resp_s_v01_ei,
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_respond_mem_resp_msg_v01_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
				     struct qmi_wlanfw_respond_mem_resp_msg_v01,
				     resp),
		.ei_array      = get_qmi_response_type_v01_ei(),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_cap_req_msg_v01_ei[] = {
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_rf_chip_info_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_rf_chip_info_s_v01,
					   chip_id),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_rf_chip_info_s_v01,
				     chip_family),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_rf_board_info_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				    struct qmi_wlanfw_rf_board_info_s_v01,
				    board_id),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_soc_info_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct qmi_wlanfw_soc_info_s_v01,
					   soc_id),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_fw_version_info_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_fw_version_info_s_v01,
				     fw_version),
	},
	{
		.data_type      = QMI_STRING,
		.elem_len       = QMI_WLANFW_MAX_TIMESTAMP_LEN_V01 + 1,
		.elem_size      = sizeof(char),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_fw_version_info_s_v01,
				     fw_build_timestamp),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_cap_resp_msg_v01_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
				     struct qmi_wlanfw_cap_resp_msg_v01,
				     resp),
		.ei_array      = get_qmi_response_type_v01_ei(),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_cap_resp_msg_v01,
				     chip_info_valid),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_wlanfw_rf_chip_info_s_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_cap_resp_msg_v01,
				     chip_info),
		.ei_array      = qmi_wlanfw_rf_chip_info_s_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(struct qmi_wlanfw_cap_resp_msg_v01,
					   board_info_valid),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_wlanfw_rf_board_info_s_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(struct qmi_wlanfw_cap_resp_msg_v01,
					   board_info),
		.ei_array      = qmi_wlanfw_rf_board_info_s_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(struct qmi_wlanfw_cap_resp_msg_v01,
					   soc_info_valid),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_wlanfw_soc_info_s_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(
				     struct qmi_wlanfw_cap_resp_msg_v01,
				     soc_info),
		.ei_array      = qmi_wlanfw_soc_info_s_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_cap_resp_msg_v01,
				     fw_version_info_valid),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(
				     struct qmi_wlanfw_fw_version_info_s_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(struct qmi_wlanfw_cap_resp_msg_v01,
					   fw_version_info),
		.ei_array	= qmi_wlanfw_fw_version_info_s_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(struct qmi_wlanfw_cap_resp_msg_v01,
					   fw_build_id_valid),
	},
	{
		.data_type      = QMI_STRING,
		.elem_len       = QMI_WLANFW_MAX_BUILD_ID_LEN_V01 + 1,
		.elem_size      = sizeof(char),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(struct qmi_wlanfw_cap_resp_msg_v01,
					   fw_build_id),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x15,
		.offset         = offsetof(struct qmi_wlanfw_cap_resp_msg_v01,
					   num_macs_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x15,
		.offset         = offsetof(struct qmi_wlanfw_cap_resp_msg_v01,
					   num_macs),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_bdf_download_req_msg_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     valid),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     file_id_valid),
	},
	{
		.data_type      = QMI_SIGNED_4_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(enum qmi_wlanfw_cal_temp_id_enum_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     file_id),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     total_size_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     total_size),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     seg_id_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     seg_id),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     data_valid),
	},
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u16),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     data_len),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = QMI_WLANFW_MAX_DATA_SIZE_V01,
		.elem_size      = sizeof(u8),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     data),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     end_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(
				     struct qmi_wlanfw_bdf_download_req_msg_v01,
				     end),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x15,
		.offset         = offsetof(struct qmi_wlanfw_bdf_download_req_msg_v01,
					   bdf_type_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x15,
		.offset         = offsetof(struct qmi_wlanfw_bdf_download_req_msg_v01,
					   bdf_type),
	},

	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_bdf_download_resp_msg_v01_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
					struct
					qmi_wlanfw_bdf_download_resp_msg_v01,
					resp),
		.ei_array      = get_qmi_response_type_v01_ei(),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_m3_info_req_msg_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_8_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u64),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(
				     struct qmi_wlanfw_m3_info_req_msg_v01,
				     addr),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
				     struct qmi_wlanfw_m3_info_req_msg_v01,
				     size),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_m3_info_resp_msg_v01_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
				     struct qmi_wlanfw_m3_info_resp_msg_v01,
				     resp),
		.ei_array      = get_qmi_response_type_v01_ei(),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_ce_tgt_pipe_cfg_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_ce_tgt_pipe_cfg_s_v01,
				     pipe_num),
	},
	{
		.data_type      = QMI_SIGNED_4_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(enum qmi_wlanfw_pipedir_enum_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_ce_tgt_pipe_cfg_s_v01,
				     pipe_dir),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_ce_tgt_pipe_cfg_s_v01,
				     nentries),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_ce_tgt_pipe_cfg_s_v01,
				     nbytes_max),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_ce_tgt_pipe_cfg_s_v01,
				     flags),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_ce_svc_pipe_cfg_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_ce_svc_pipe_cfg_s_v01,
				     service_id),
	},
	{
		.data_type      = QMI_SIGNED_4_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(enum qmi_wlanfw_pipedir_enum_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_ce_svc_pipe_cfg_s_v01,
				     pipe_dir),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_ce_svc_pipe_cfg_s_v01,
				     pipe_num),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_shadow_reg_cfg_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_2_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u16),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_shadow_reg_cfg_s_v01,
				     id),
	},
	{
		.data_type      = QMI_UNSIGNED_2_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u16),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_shadow_reg_cfg_s_v01,
				     offset),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_shadow_reg_v2_cfg_s_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(
				     struct qmi_wlanfw_shadow_reg_v2_cfg_s_v01,
				     addr),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_wlan_mode_req_msg_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u32),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_mode_req_msg_v01,
				     mode),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_mode_req_msg_v01,
				     hw_debug_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_mode_req_msg_v01,
				     hw_debug),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_wlan_mode_resp_msg_v01_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_mode_resp_msg_v01,
				     resp),
		.ei_array      = get_qmi_response_type_v01_ei(),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_wlan_cfg_req_msg_v01_ei[] = {
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     host_version_valid),
	},
	{
		.data_type      = QMI_STRING,
		.elem_len       = QMI_WLANFW_MAX_STR_LEN_V01 + 1,
		.elem_size      = sizeof(char),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     host_version),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     tgt_cfg_valid),
	},
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     tgt_cfg_len),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = QMI_WLANFW_MAX_NUM_CE_V01,
		.elem_size      = sizeof(
				    struct qmi_wlanfw_ce_tgt_pipe_cfg_s_v01),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     tgt_cfg),
		.ei_array      = qmi_wlanfw_ce_tgt_pipe_cfg_s_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     svc_cfg_valid),
	},
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     svc_cfg_len),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = QMI_WLANFW_MAX_NUM_SVC_V01,
		.elem_size      = sizeof(
				    struct qmi_wlanfw_ce_svc_pipe_cfg_s_v01),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     svc_cfg),
		.ei_array      = qmi_wlanfw_ce_svc_pipe_cfg_s_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     shadow_reg_valid),
	},
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     shadow_reg_len),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = QMI_WLANFW_MAX_NUM_SHADOW_REG_V01,
		.elem_size      = sizeof(
				    struct qmi_wlanfw_shadow_reg_cfg_s_v01),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0x13,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     shadow_reg),
		.ei_array      = qmi_wlanfw_shadow_reg_cfg_s_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     shadow_reg_v2_valid),
	},
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(u8),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     shadow_reg_v2_len),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = QMI_WLANFW_MAX_NUM_SHADOW_REG_V2_V01,
		.elem_size      = sizeof(
				    struct qmi_wlanfw_shadow_reg_v2_cfg_s_v01),
		.is_array       = VAR_LEN_ARRAY,
		.tlv_type       = 0x14,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_req_msg_v01,
				     shadow_reg_v2),
		.ei_array      = qmi_wlanfw_shadow_reg_v2_cfg_s_v01_ei,
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static struct elem_info qmi_wlanfw_wlan_cfg_resp_msg_v01_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(
				     struct qmi_wlanfw_wlan_cfg_resp_msg_v01,
				     resp),
		.ei_array      = get_qmi_response_type_v01_ei(),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type	= QMI_COMMON_TLV_TYPE,
	},
};

static int ath11k_qmi_host_cap_send(struct ath11k_base *sc)
{
	struct qmi_wlanfw_host_cap_req_msg_v01 req;
	struct qmi_wlanfw_host_cap_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	int ret = 0;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.num_clients_valid = 1;
	req.num_clients = 1;
	req.mem_cfg_mode = sc->qmi.target_mem_mode;
	req.mem_cfg_mode_valid = 1;
	req.bdf_support_valid = 1;
	req.bdf_support = 1;

	req.m3_support_valid = 0;
	req.m3_support = 0;

	req.m3_cache_support_valid = 0;
	req.m3_cache_support = 0;

	req.cal_done_valid = 1;
	req.cal_done = sc->qmi.cal_done;

	req_desc.max_msg_len = QMI_WLANFW_HOST_CAP_REQ_MSG_V01_MAX_LEN;
	req_desc.msg_id = QMI_WLANFW_HOST_CAP_REQ_V01;
	req_desc.ei_array = qmi_wlanfw_host_cap_req_msg_v01_ei;

	resp_desc.max_msg_len = QMI_WLANFW_HOST_CAP_RESP_MSG_V01_MAX_LEN;
	resp_desc.msg_id = QMI_WLFW_HOST_CAP_RESP_V01;
	resp_desc.ei_array = qmi_wlanfw_host_cap_resp_msg_v01_ei;

	ret = qmi_send_req_wait(sc->qmi.handle, &req_desc, &req,
				sizeof(req), &resp_desc, &resp, sizeof(resp),
				QMI_WLANFW_TIMEOUT_MS);
	if (ret < 0) {
		ath11k_warn(sc, "Failed to send host capability request,err = %d\n", ret);
		goto out;
	}

	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		ath11k_warn(sc, "Host capability request failed, result: %d, err: %d\n",
			    resp.resp.result, resp.resp.error);
		ret = resp.resp.result;
		goto out;
	}

	return 0;
out:
	return ret;
}

static int ath11k_qmi_fw_ind_register_send(struct ath11k_base *sc)
{
	struct qmi_wlanfw_ind_register_req_msg_v01 req;
	struct qmi_wlanfw_ind_register_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	int ret = 0;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.client_id_valid = 1;
	req.client_id = QMI_WLANFW_CLIENT_ID;
	req.fw_ready_enable_valid = 1;
	req.fw_ready_enable = 1;
	req.request_mem_enable_valid = 1;
	req.request_mem_enable = 1;
	req.fw_mem_ready_enable_valid = 1;
	req.fw_mem_ready_enable = 1;
	req.cal_done_enable_valid = 1;
	req.cal_done_enable = 1;
	req.fw_init_done_enable_valid = 1;
	req.fw_init_done_enable = 1;

	req.pin_connect_result_enable_valid = 0;
	req.pin_connect_result_enable = 0;

	req_desc.max_msg_len = QMI_WLANFW_IND_REGISTER_REQ_MSG_V01_MAX_LEN;
	req_desc.msg_id = QMI_WLANFW_IND_REGISTER_REQ_V01;
	req_desc.ei_array = qmi_wlanfw_ind_register_req_msg_v01_ei;

	resp_desc.max_msg_len = QMI_WLANFW_IND_REGISTER_RESP_MSG_V01_MAX_LEN;
	resp_desc.msg_id = QMI_WLANFW_IND_REGISTER_RESP_V01;
	resp_desc.ei_array = qmi_wlanfw_ind_register_resp_msg_v01_ei;

	ret = qmi_send_req_wait(sc->qmi.handle, &req_desc, &req,
			sizeof(req), &resp_desc, &resp, sizeof(resp),
			QMI_WLANFW_TIMEOUT_MS);
	if (ret < 0) {
		ath11k_warn(sc, "Failed to send indication register request, err = %d\n",
			    ret);
		goto out;
	}

	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		ath11k_warn(sc, "FW Ind register request failed, result: %d, err: %d\n",
			    resp.resp.result, resp.resp.error);
		ret = resp.resp.result;
		goto out;
	}
	return 0;
out:
	/* TODO: Assert needed?*/
	return ret;
}

static int ath11k_qmi_respond_fw_mem_request(struct ath11k_base *sc)
{
	struct qmi_wlanfw_respond_mem_req_msg_v01 req;
	struct qmi_wlanfw_respond_mem_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	int ret = 0, i;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.mem_seg_len = sc->qmi.mem_seg_count;
	req_desc.max_msg_len = QMI_WLANFW_RESPOND_MEM_REQ_MSG_V01_MAX_LEN;
	req_desc.msg_id = QMI_WLANFW_RESPOND_MEM_REQ_V01;
	req_desc.ei_array = qmi_wlanfw_respond_mem_req_msg_v01_ei;

	for (i = 0; i < req.mem_seg_len ; i++) {
		if (!sc->qmi.target_mem[i].paddr || !sc->qmi.target_mem[i].size) {
			ath11k_warn(sc, "Invalid memory type for target\n");
			ret = -ENOMEM;
			goto out;
		}

		req.mem_seg[i].addr = sc->qmi.target_mem[i].paddr;
		req.mem_seg[i].size = sc->qmi.target_mem[i].size;
		req.mem_seg[i].type = sc->qmi.target_mem[i].type;
	}
	resp_desc.max_msg_len = QMI_WLANFW_RESPOND_MEM_RESP_MSG_V01_MAX_LEN;
	resp_desc.msg_id = QMI_WLANFW_RESPOND_MEM_RESP_V01;
	resp_desc.ei_array = qmi_wlanfw_respond_mem_resp_msg_v01_ei;

	ret = qmi_send_req_wait(sc->qmi.handle, &req_desc, &req,
				sizeof(req), &resp_desc, &resp, sizeof(resp),
				QMI_WLANFW_TIMEOUT_MS);
	if (ret < 0) {
		ath11k_warn(sc, "Failed to respond memory request, err = %d\n",
			    ret);
		goto out;
	}

	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		ath11k_warn(sc, "Respond mem req failed, result: %d, err: %d\n",
			    resp.resp.result, resp.resp.error);
		ret = resp.resp.result;
		goto out;
	}

	return 0;
out:
	return ret;
}

static int ath11k_qmi_alloc_target_mem_chunk(struct ath11k_base *sc)
{
	u32 bdf_location[2] = {0, 0};
	struct device *dev = sc->dev;
	int i, idx, mode = sc->qmi.target_mem_mode;

	if (of_property_read_u32_array(dev->of_node, "qcom,bdf-addr",
				   &bdf_location[0],
				   ARRAY_SIZE(bdf_location))) {
		ath11k_warn(sc, "Error: No bdf_addr in device_tree\n");
		return -ENOMEM;
	}

	for (i = 0, idx = 0; i < sc->qmi.mem_seg_count; i++) {
		switch (sc->qmi.target_mem[i].type) {
		case BDF_MEM_REGION_TYPE:
			sc->qmi.target_mem[idx].paddr = bdf_location[mode];
			sc->qmi.target_mem[idx].vaddr = bdf_location[mode];
			sc->qmi.target_mem[idx].size = sc->qmi.target_mem[i].size;
			sc->qmi.target_mem[idx].type = sc->qmi.target_mem[i].type;
			idx++;
			break;
		case CALDB_MEM_REGION_TYPE:
			if (sc->qmi.target_mem[i].size > Q6_CALDB_SIZE) {
				ath11k_warn(sc, "Error: Need more memory\n");
				return -ENOMEM;
			}
			sc->qmi.target_mem[idx].paddr =
					bdf_location[mode] + CALDATA_OFFSET;
			sc->qmi.target_mem[idx].vaddr =
					bdf_location[mode] + CALDATA_OFFSET;
			sc->qmi.target_mem[idx].size = sc->qmi.target_mem[i].size;
			sc->qmi.target_mem[idx].type = sc->qmi.target_mem[i].type;
			idx++;
			break;
		default:
			ath11k_warn(sc, "Ignore mem req type %d\n",
			       sc->qmi.target_mem[i].type);
			break;
		}
	}
	sc->qmi.mem_seg_count = idx;

	return 0;
}

static int ath11k_qmi_request_target_cap(struct ath11k_base *sc)
{
	struct qmi_wlanfw_cap_req_msg_v01 req;
	struct qmi_wlanfw_cap_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	int ret = 0;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req_desc.max_msg_len = QMI_WLANFW_CAP_REQ_MSG_V01_MAX_LEN;
	req_desc.msg_id = QMI_WLANFW_CAP_REQ_V01;
	req_desc.ei_array = qmi_wlanfw_cap_req_msg_v01_ei;

	resp_desc.max_msg_len = QMI_WLANFW_CAP_RESP_MSG_V01_MAX_LEN;
	resp_desc.msg_id = QMI_WLANFW_CAP_RESP_V01;
	resp_desc.ei_array = qmi_wlanfw_cap_resp_msg_v01_ei;

	ret = qmi_send_req_wait(sc->qmi.handle, &req_desc, &req,
				sizeof(req), &resp_desc, &resp, sizeof(resp),
				QMI_WLANFW_TIMEOUT_MS);
	if (ret < 0) {
		ath11k_warn(sc, "Failed to send target cap request, err = %d\n",
			    ret);
		goto out;
	}

	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		ath11k_warn(sc, "Targetcap req failed, result: %d, err: %d\n",
			    resp.resp.result, resp.resp.error);
		ret = resp.resp.result;
		goto out;
	}

	if (resp.chip_info_valid) {
		sc->qmi.target.chip_id = resp.chip_info.chip_id;
		sc->qmi.target.chip_family = resp.chip_info.chip_family;
	}

	if (resp.board_info_valid)
		sc->qmi.target.board_id = resp.board_info.board_id;
	else
		sc->qmi.target.board_id = 0xFF;

	if (resp.soc_info_valid)
		sc->qmi.target.soc_id = resp.soc_info.soc_id;

	if (resp.fw_version_info_valid)
		sc->qmi.target.fw_version = resp.fw_version_info.fw_version;

	ath11k_warn(sc, "Target: chip_id: 0x%x, chip_family: 0x%x, board_id: 0x%x, soc_id: 0x%x, fw_version: 0x%x\n",
		    sc->qmi.target.chip_id, sc->qmi.target.chip_family,
		    sc->qmi.target.board_id, sc->qmi.target.soc_id,
		    sc->qmi.target.fw_version);

	return 0;
out:
	return ret;
}


static int ath11k_qmi_prepare_bdf_download(struct ath11k_base *sc, int type,
					   struct qmi_wlanfw_bdf_download_req_msg_v01 *req,
					   void *bdf_addr)
{
	struct device *dev = sc->dev;
	char filename[MAX_BDF_FILE_NAME_SIZE];
	const struct firmware *fw_entry;
	struct ath11k_board_data bd = { 0 };
	u32 fw_size;
	int ret = 0;

	switch (type) {
	case ATH11K_QMI_FILE_TYPE_BDF_GOLDEN:
		ret = ath11k_core_fetch_bdf(sc, &bd);
		if (ret) {
			ath11k_warn(sc, "Failed to load BDF\n");
			goto out;
		}

		fw_size = min_t(u32, sc->hw_params.fw.board_size, bd.len);

		memcpy(bdf_addr, bd.data, fw_size);

		ath11k_core_free_bdf(sc, &bd);
		break;
	case ATH11K_QMI_FILE_TYPE_CALDATA:
		snprintf(filename, sizeof(filename),
			 "%s/%s",sc->hw_params.fw.dir, ATH11K_DEFAULT_CAL_FILE);
		ret = request_firmware(&fw_entry, filename, dev);
		if (ret) {
			ath11k_warn(sc, "Failed to load CAL: %s\n", filename);
			goto out;
		}

		fw_size = min_t(u32, sc->hw_params.fw.board_size,
				fw_entry->size);

		memcpy(bdf_addr + CALDATA_OFFSET, fw_entry->data, fw_size);
		ath11k_warn(sc, "Downloading BDF: %s, size: %zu\n",
			    filename, fw_entry->size);

		release_firmware(fw_entry);
		break;
	default:
		ret =-EINVAL;
		goto out;
	}

	req->total_size = fw_size;

out:
	return ret;
}

static int ath11k_qmi_load_bdf(struct ath11k_base *sc)
{
	struct qmi_wlanfw_bdf_download_req_msg_v01 *req;
	struct qmi_wlanfw_bdf_download_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	struct device *dev = sc->dev;
	u32 location[2];
	void __iomem *bdf_addr = NULL;
	int type, ret;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}
	memset(&resp, 0, sizeof(resp));

	if (of_property_read_u32_array(dev->of_node, "qcom,bdf-addr", &location[0],
				       ARRAY_SIZE(location))) {
		ath11k_err(sc, "Error: No bdf_addr in device_tree\n");
		ret =-EINVAL;
		goto out;
	}

	bdf_addr = ioremap(location[sc->qmi.target_mem_mode], BDF_MAX_SIZE);
	if (!bdf_addr) {
		ath11k_warn(sc, "ioremap error for BDF\n");
		ret = -EIO;
		goto out;
	}

	for (type = 0; type < ATH11K_QMI_MAX_FILE_TYPE; type++) {
		req_desc.max_msg_len = QMI_WLANFW_BDF_DOWNLOAD_REQ_MSG_V01_MAX_LEN;
		req_desc.msg_id = QMI_WLANFW_BDF_DOWNLOAD_REQ_V01;
		req_desc.ei_array = qmi_wlanfw_bdf_download_req_msg_v01_ei;

		resp_desc.max_msg_len = QMI_WLANFW_BDF_DOWNLOAD_RESP_MSG_V01_MAX_LEN;
		resp_desc.msg_id = QMI_WLANFW_BDF_DOWNLOAD_RESP_V01;
		resp_desc.ei_array = qmi_wlanfw_bdf_download_resp_msg_v01_ei;

		req->valid = 1;
		req->file_id_valid = 1;
		req->file_id = sc->qmi.target.board_id;
		req->total_size_valid = 1;
		req->seg_id_valid = 1;
		req->seg_id = type;
		req->data_valid = 0;
		req->data_len = MAX_BDF_FILE_NAME_SIZE;
		req->bdf_type = 0;
		req->bdf_type_valid = 0;
		req->end_valid = 1;
		req->end = 1;

		ret = ath11k_qmi_prepare_bdf_download(sc, type, req, bdf_addr);
		if (ret < 0)
			goto out;

		ret = qmi_send_req_wait(sc->qmi.handle, &req_desc,
					req, sizeof(*req), &resp_desc, &resp,
					sizeof(resp), QMI_WLANFW_TIMEOUT_MS);
		if (ret < 0) {
			ath11k_warn(sc, "Failed to send BDF download request, err = %d\n",
				    ret);
			goto out;
		}

		if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
			ath11k_warn(sc, "BDF download request failed, result: %d, err: %d\n",
				   resp.resp.result, resp.resp.error);
			ret = resp.resp.result;
			goto out;
		}
	}
	ath11k_warn(sc, "BDF downloaded. \n");

	iounmap(bdf_addr);
out:
	kfree(req);
	return ret;
}

static int ath11k_qmi_wlanfw_m3_info_send(struct ath11k_base *sc)
{
	struct qmi_wlanfw_m3_info_req_msg_v01 req;
	struct qmi_wlanfw_m3_info_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	int ret = 0;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	req.addr = 0;
	req.size = 0;

	req_desc.max_msg_len = QMI_WLANFW_M3_INFO_REQ_MSG_V01_MAX_MSG_LEN;
	req_desc.msg_id = QMI_WLANFW_M3_INFO_REQ_V01;
	req_desc.ei_array = qmi_wlanfw_m3_info_req_msg_v01_ei;

	resp_desc.max_msg_len = QMI_WLANFW_M3_INFO_RESP_MSG_V01_MAX_MSG_LEN;
	resp_desc.msg_id = QMI_WLANFW_M3_INFO_RESP_V01;
	resp_desc.ei_array = qmi_wlanfw_m3_info_resp_msg_v01_ei;

	ret = qmi_send_req_wait(sc->qmi.handle, &req_desc, &req,
				sizeof(req), &resp_desc, &resp, sizeof(resp),
				QMI_WLANFW_TIMEOUT_MS);
	if (ret < 0) {
		ath11k_warn(sc, "Failed to send M3 information request, err = %d\n",
			    ret);
		goto out;
	}

	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		ath11k_warn(sc, "M3 inforequest failed, result: %d, err: %d\n",
			    resp.resp.result, resp.resp.error);
		ret = resp.resp.result;
		goto out;
	}

	return 0;

out:
	return ret;
}

static int ath11k_qmi_wlanfw_mode_send(struct ath11k_base *sc,
				       u32 mode)
{
	struct qmi_wlanfw_wlan_mode_req_msg_v01 req;
	struct qmi_wlanfw_wlan_mode_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	int ret = 0;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.mode = mode;
	req.hw_debug_valid = 1;
	req.hw_debug = 0;

	req_desc.max_msg_len = QMI_WLANFW_WLAN_MODE_REQ_MSG_V01_MAX_LEN;
	req_desc.msg_id = QMI_WLANFW_WLAN_MODE_REQ_V01;
	req_desc.ei_array = qmi_wlanfw_wlan_mode_req_msg_v01_ei;

	resp_desc.max_msg_len = QMI_WLANFW_WLAN_MODE_RESP_MSG_V01_MAX_LEN;
	resp_desc.msg_id = QMI_WLANFW_WLAN_MODE_RESP_V01;
	resp_desc.ei_array = qmi_wlanfw_wlan_mode_resp_msg_v01_ei;

	ret = qmi_send_req_wait(sc->qmi.handle, &req_desc, &req,
				sizeof(req), &resp_desc, &resp, sizeof(resp),
				QMI_WLANFW_TIMEOUT_MS);
	if (ret < 0) {
		if (mode == ATH11K_FIRMWARE_MODE_OFF && ret == -ENETRESET) {
			ath11k_warn(sc, "WLFW service is disconnected\n");
			return 0;
		}
		ath11k_warn(sc, "Failed to send mode request, mode: %d, err = %d\n",
			    mode, ret);
		goto out;
	}

	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		ath11k_warn(sc, "Mode request failed, mode: %d, result: %d err: %d\n",
			    mode, resp.resp.result, resp.resp.error);
		ret = resp.resp.result;
		goto out;
	}

	return 0;
out:
	return ret;
}

static int ath11k_qmi_wlanfw_wlan_cfg_send(struct ath11k_base *sc)
{
	struct qmi_wlanfw_wlan_cfg_req_msg_v01 req;
	struct qmi_wlanfw_wlan_cfg_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	struct ce_pipe_config *ce_cfg;
	struct service_to_pipe *svc_cfg;
	int ret = 0;
	ce_cfg	= (struct ce_pipe_config *)sc->qmi.ce_cfg.tgt_ce;
	svc_cfg	= (struct service_to_pipe *)sc->qmi.ce_cfg.svc_to_ce_map;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.host_version_valid = 1;
	strlcpy(req.host_version, ATH11K_HOST_VERSION_STRING,
		sizeof(req.host_version));

	req.tgt_cfg_valid = 1;
	/* This is number of CE configs */
	req.tgt_cfg_len = ((sc->qmi.ce_cfg.tgt_ce_len) /
				(sizeof(struct ce_pipe_config))) - 1;
	for (ret = 0; ret <= req.tgt_cfg_len ; ret++) {
		req.tgt_cfg[ret].pipe_num = ce_cfg[ret].pipenum;
		req.tgt_cfg[ret].pipe_dir = ce_cfg[ret].pipedir;
		req.tgt_cfg[ret].nentries = ce_cfg[ret].nentries;
		req.tgt_cfg[ret].nbytes_max = ce_cfg[ret].nbytes_max;
		req.tgt_cfg[ret].flags = ce_cfg[ret].flags;
	}

	req.svc_cfg_valid = 1;
	/* This is number of Service/CE configs */
	req.svc_cfg_len = (sc->qmi.ce_cfg.svc_to_ce_map_len) /
				(sizeof(struct service_to_pipe));
	for (ret = 0; ret < req.svc_cfg_len; ret++) {
		req.svc_cfg[ret].service_id = svc_cfg[ret].service_id;
		req.svc_cfg[ret].pipe_dir = svc_cfg[ret].pipedir;
		req.svc_cfg[ret].pipe_num = svc_cfg[ret].pipenum;
	}
	req.shadow_reg_valid = 0;
	req.shadow_reg_v2_valid = 0;

	req_desc.max_msg_len = QMI_WLANFW_WLAN_CFG_REQ_MSG_V01_MAX_LEN;
	req_desc.msg_id = QMI_WLANFW_WLAN_CFG_REQ_V01;
	req_desc.ei_array = qmi_wlanfw_wlan_cfg_req_msg_v01_ei;

	resp_desc.max_msg_len = QMI_WLANFW_WLAN_CFG_RESP_MSG_V01_MAX_LEN;
	resp_desc.msg_id = QMI_WLANFW_WLAN_CFG_RESP_V01;
	resp_desc.ei_array = qmi_wlanfw_wlan_cfg_resp_msg_v01_ei;

	ret = qmi_send_req_wait(sc->qmi.handle, &req_desc, &req,
				sizeof(req), &resp_desc, &resp, sizeof(resp),
				QMI_WLANFW_TIMEOUT_MS);
	if (ret < 0) {
		ath11k_warn(sc, "Failed to send WLAN config request, err = %d\n",
			    ret);
		goto out;
	}

	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		ath11k_warn(sc, "WLAN config request failed, result: %d, err: %d\n",
			    resp.resp.result, resp.resp.error);
		ret = resp.resp.result;
		goto out;
	}

	return 0;
out:
	return ret;
}

void ath11k_qmi_firmware_stop(struct ath11k_base *sc)
{
	/* TODO: Send QMI_WLFW_OFF_V01 message to target */
	ath11k_qmi_wlanfw_mode_send(sc, ATH11K_FIRMWARE_MODE_OFF);
}

int ath11k_qmi_firmware_start(struct ath11k_base *sc,
			      u32 mode)
{
	int ret = 0;
	ret = ath11k_qmi_wlanfw_wlan_cfg_send(sc);
	if (ret)
		return ret;

	ret = ath11k_qmi_wlanfw_mode_send(sc, mode);
	if (ret)
		return ret;
	return 0;
}

static int ath11k_qmi_notify_event(struct ath11k_base *sc,
				   enum ath11k_qmi_event_type type)
{
	struct ath11k_qmi_event_msg *event_msg;

	event_msg = kzalloc(sizeof(*event_msg), GFP_KERNEL);

	if (!event_msg)
		return -ENOMEM;

	event_msg->type	= type;
	/* TODO: Flsuh this list before cancel event_work before */
	/* TODO: Add data and lentgh latter if necessary in event_msg */
	spin_lock(&sc->qmi.event_msg_lock);
	list_add_tail(&event_msg->list, &sc->qmi.event_msg_list);
	spin_unlock(&sc->qmi.event_msg_lock);

	queue_work(sc->qmi.wq, &sc->qmi.event_work);

	return 0;
}

static void ath11k_qmi_msg_notifier(struct qmi_handle *handle,
				    enum qmi_event_type code,
				    void *notify_data)
{
	struct ath11k_base *sc = notify_data;

	ath11k_dbg(sc, ATH11K_DBG_QMI, "ath11k_qmi_msg_notifier type %d\n",
		   code);
	switch (code) {
	case QMI_RECV_MSG:
		queue_work(sc->qmi.qmi_resp_wq,
			   &sc->qmi.msg_recv_work);
		break;
	case QMI_SERVER_EXIT:
		break;
	default:
		ath11k_warn(sc, "unknown qmi msg notifier received code: %d\n",
			    code);
		break;
	}
}

static void ath11k_qmi_msg_indication_cb(struct qmi_handle *handle,
					 unsigned int msg_type, void *msg,
					 unsigned int msg_len,
					 void *cb_data)
{
	struct ath11k_base *sc = cb_data;
	int i;

	ath11k_dbg(sc, ATH11K_DBG_QMI,
		   "ath11k_qmi_msg_indication_cb msg_type 0x%x len %d\n",
		   msg_type, msg_len);
	switch (msg_type) {
	case QMI_WLFW_REQUEST_MEM_IND_V01:
		{
			struct msg_desc ind_desc;
			struct qmi_wlanfw_request_mem_ind_msg_v01 *ind_msg;
			int ret = 0;

			ind_msg = kzalloc(sizeof(*ind_msg), GFP_KERNEL);
			ind_desc.msg_id = QMI_WLANFW_REQUEST_MEM_IND_V01;
			ind_desc.max_msg_len =
				QMI_WLANFW_REQUEST_MEM_IND_MSG_V01_MAX_LEN;
			ind_desc.ei_array =
					qmi_wlanfw_request_mem_ind_msg_v01_ei;

			ret = qmi_kernel_decode(&ind_desc,
						ind_msg, msg, msg_len);
			if (ret < 0) {
				ath11k_warn(sc, "Failed to decode FWMEM request, msg_len: %u, err = %d\n",
					    ret, msg_len);
				kfree(ind_msg);
				return;
			}

			ath11k_dbg(sc, ATH11K_DBG_QMI, "FWMEM request, msg_len: %u\n", msg_len);
			if (ind_msg->mem_seg_len == 0 ||
			    ind_msg->mem_seg_len > QMI_WLANFW_MAX_NUM_MEM_SEG_V01) {
				ath11k_warn(sc, "Invalid memory segment length: %u\n",
					    ind_msg->mem_seg_len);
				ret = -EINVAL;
			}

			sc->qmi.mem_seg_count = ind_msg->mem_seg_len;

			for (i = 0; i < sc->qmi.mem_seg_count ; i++) {
				sc->qmi.target_mem[i].type = ind_msg->mem_seg[i].type;
				sc->qmi.target_mem[i].size = ind_msg->mem_seg[i].size;
			}

			ath11k_qmi_notify_event(sc,
						ATH11K_QMI_EVENT_REQUEST_MEM);
			kfree(ind_msg);
		}

		break;
	case QMI_WLFW_FW_MEM_READY_IND_V01:
		ath11k_qmi_notify_event(sc, ATH11K_QMI_EVENT_FW_MEM_READY);
		break;
	case QMI_WLFW_COLD_BOOT_CAL_DONE_IND_V01:
		ath11k_qmi_notify_event(sc,
					ATH11K_QMI_EVENT_COLD_BOOT_CAL_DONE);
		break;
	case QMI_WLFW_FW_READY_IND_V01:
		ath11k_qmi_notify_event(sc, ATH11K_QMI_EVENT_FW_READY);
		break;
	default:
		ath11k_warn(sc, "unknown qmi msg type received code: %d\n",
			    msg_type);
		break;
	}
}

static int ath11k_qmi_connect_fw_service(struct ath11k_base *sc)
{
	int ret;

	sc->qmi.handle = qmi_handle_create(ath11k_qmi_msg_notifier, sc);

	if (!sc->qmi.handle) {
		ath11k_warn(sc, "failed to create QMI handle\n");
		return -ENOMEM;
	}

	ret = qmi_connect_to_service(sc->qmi.handle, QMI_WLFW_SERVICE_ID_V01,
				     QMI_WLFW_SERVICE_VERS_V01,
				     QMI_WLFW_SERVICE_INS_ID_V01);
	if (ret) {
		ath11k_warn(sc, "failed to connect QMI service:%d\n", ret);
		goto err_qmi_fw_service;
	}

	ret = qmi_register_ind_cb(sc->qmi.handle, ath11k_qmi_msg_indication_cb,
				  sc);
	if (ret) {
		ath11k_warn(sc, "failed to register QMI msg Cb:%d\n", ret);
		goto err_qmi_fw_service;
	}

	ret = ath11k_qmi_fw_ind_register_send(sc);
	if (ret) {
		ath11k_warn(sc, "failed to send FW indication QMI:%d\n", ret);
		goto err_qmi_fw_service;
	}

	ret = ath11k_qmi_host_cap_send(sc);
	if (ret) {
		ath11k_warn(sc, "failed to send host cap QMI:%d\n", ret);
		goto err_qmi_fw_service;
	}

	return ret;

err_qmi_fw_service:
	qmi_handle_destroy(sc->qmi.handle);
	sc->qmi.handle = NULL;

	return ret;
}

void ath11k_qmi_event_work(struct work_struct *work)
{
	struct ath11k_base *sc = container_of(work, struct ath11k_base,
						qmi.event_work);
	struct ath11k_qmi_event_msg *event_msg, *temp_msg;

	spin_lock(&sc->qmi.event_msg_lock);
	list_for_each_entry_safe(event_msg, temp_msg,
				 &sc->qmi.event_msg_list, list) {
		list_del(&event_msg->list);
		spin_unlock(&sc->qmi.event_msg_lock);

		ath11k_dbg(sc, ATH11K_DBG_QMI, "qmi event type %d\n",
			   event_msg->type);
		switch (event_msg->type) {
		case ATH11K_QMI_EVENT_SERVER_ARRIVE:
			ath11k_qmi_connect_fw_service(sc);
			break;
		case ATH11K_QMI_EVENT_SERVER_EXIT:
			qmi_handle_destroy(sc->qmi.handle);
			sc->qmi.handle = NULL;
			set_bit(ATH11K_FLAG_CRASH_FLUSH, &sc->dev_flags);
			set_bit(ATH11K_FLAG_RECOVERY, &sc->dev_flags);
			break;
		case ATH11K_QMI_EVENT_REQUEST_MEM:
			ath11k_qmi_alloc_target_mem_chunk(sc);
			ath11k_qmi_respond_fw_mem_request(sc);

			break;
		case ATH11K_QMI_EVENT_FW_MEM_READY:
			if (ath11k_qmi_request_target_cap(sc))
				break;
			if (ath11k_qmi_load_bdf(sc))
				break;
			ath11k_qmi_wlanfw_m3_info_send(sc);
			break;
		case ATH11K_QMI_EVENT_FW_READY:
			sc->qmi.cal_done = 1;
			complete(&sc->fw_ready);
			if (test_bit(ATH11K_FLAG_REGISTERED, &sc->dev_flags) &&
			    !test_bit(ATH11K_FLAG_UNREGISTERING, &sc->dev_flags))
				queue_work(sc->workqueue, &sc->restart_work);
			break;
		case ATH11K_QMI_EVENT_COLD_BOOT_CAL_DONE:
			break;
		default:
			ath11k_warn(sc, "unknown qmi event type posted code: %d\n",
				    event_msg->type);
			break;
		}

		kfree(event_msg);

		spin_lock(&sc->qmi.event_msg_lock);
	}

	spin_unlock(&sc->qmi.event_msg_lock);
}

void ath11k_qmi_msg_recv_work(struct work_struct *work)
{
	struct ath11k_base *sc = container_of(work, struct ath11k_base,
			qmi.msg_recv_work);
	int ret = 0;

	do {
		ret = qmi_recv_msg(sc->qmi.handle);
	} while (ret == 0);

}

static int ath11k_qmi_service_notifier(struct notifier_block *nb,
				       unsigned long code, void *cmd)
{
	struct ath11k_base *sc = container_of(nb, struct ath11k_base,
					      qmi.qmi_service_nb);

	switch (code) {
	case QMI_SERVER_ARRIVE:
		ath11k_qmi_notify_event(sc, ATH11K_QMI_EVENT_SERVER_ARRIVE);
		break;
	case QMI_SERVER_EXIT:
		ath11k_qmi_notify_event(sc, ATH11K_QMI_EVENT_SERVER_EXIT);
		break;
	default:
		ath11k_warn(sc, "unknown qmi event type received code: %ld\n",
			    code);
		return 0;
	}

	return 0;
}

void ath11k_qmi_deinit_service(struct ath11k_base *sc)
{
	qmi_svc_event_notifier_unregister(QMI_WLFW_SERVICE_ID_V01,
					  QMI_WLFW_SERVICE_VERS_V01,
					  QMI_WLFW_SERVICE_INS_ID_V01,
					  &sc->qmi.qmi_service_nb);

	cancel_work_sync(&sc->qmi.event_work);
	cancel_work_sync(&sc->qmi.msg_recv_work);

	if (sc->qmi.handle) {
		qmi_handle_destroy(sc->qmi.handle);
		sc->qmi.handle = NULL;
	}
	sc->qmi.event_type = 0;
}

int ath11k_qmi_init_service(struct ath11k_base *sc)
{
	int ret;
	struct device *dev = sc->dev;

	memset(&sc->qmi.target, 0, sizeof(struct target_info));
	memset(&sc->qmi.target_mem, 0, sizeof(struct target_mem_chunk));

	if (of_property_read_u32(dev->of_node,
				 "qcom,tgt-mem-mode",
				 &sc->qmi.target_mem_mode)) {
		ath11k_err(sc, "No ipq8074_tgt_mem_mode entry in dev-tree.\n");
		sc->qmi.target_mem_mode = 0;
	}

	sc->qmi.handle = NULL;
	sc->qmi.qmi_service_nb.notifier_call = ath11k_qmi_service_notifier;

	ret = qmi_svc_event_notifier_register(QMI_WLFW_SERVICE_ID_V01,
					      QMI_WLFW_SERVICE_VERS_V01,
					      QMI_WLFW_SERVICE_INS_ID_V01,
					      &sc->qmi.qmi_service_nb);
	if (ret)
		ath11k_warn(sc, "failed to register qmi service %d\n",
			    ret);

	return ret;
}
