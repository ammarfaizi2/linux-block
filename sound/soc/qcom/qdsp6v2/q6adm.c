/* Copyright (c) 2012-2016, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/* 
 * TODO:
 * 	- Cleanup the usage of global data struct
 * 	- remove atomic usage
 * 	- fixup apis.
 */
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/soc/qcom//apr.h>
#include <linux/platform_device.h>
#include <sound/asound.h>
#include "adsp_err.h"
#include "q6adm-v2.h"
#include "q6afe-v2.h"
#include "common.h"
#define TIMEOUT_MS 1000

#define RESET_COPP_ID 99
#define INVALID_COPP_ID 0xFF
/* Used for inband payload copy, max size is 4k */
/* 2 is to account for module & param ID in payload */
#define ADM_GET_PARAMETER_LENGTH  (4096 - APR_HDR_SIZE - 2 * sizeof(uint32_t))

#define ULL_SUPPORTED_BITS_PER_SAMPLE 16
#define ULL_SUPPORTED_SAMPLE_RATE 48000

#define ADM_CMD_SET_PP_PARAMS_V5                        0x00010328
#define ADM_CMD_DEVICE_OPEN_V5                          0x00010326
#define ADM_CMD_DEVICE_CLOSE_V5                         0x00010327
#define ADM_CMD_SET_PSPD_MTMX_STRTR_PARAMS_V5                        0x00010344
#define ADM_CMDRSP_DEVICE_OPEN_V5                      0x00010329
#define ADM_CMD_GET_PP_PARAMS_V5                                0x0001032A
#define ADM_CMD_ADD_TOPOLOGIES				0x00010335
#define ADM_CMDRSP_GET_PP_PARAMS_V5		0x0001032B
#define ADM_CMD_MATRIX_MAP_ROUTINGS_V5 0x00010325
#define ADM_CMD_STREAM_DEVICE_MAP_ROUTINGS_V5 0x0001033D
#define ADM_CMD_SHARED_MEM_MAP_REGIONS    0x00010322
#define ADM_CMDRSP_SHARED_MEM_MAP_REGIONS 0x00010323
#define ADM_CMD_SHARED_MEM_UNMAP_REGIONS 0x00010324
#define ADM_CMD_GET_PP_TOPO_MODULE_LIST				0x00010349
#define ADM_CMDRSP_GET_PP_TOPO_MODULE_LIST			0x00010350
#define ADM_CMD_CONNECT_AFE_PORT_V5	0x0001032E
#define ADM_CMD_DISCONNECT_AFE_PORT_V5	0x0001032F
#define ADM_CMD_COPP_OPEN_TOPOLOGY_ID_DTS_HPX		0x10015002
#define ADM_CMD_COPP_OPEN_TOPOLOGY_ID_AUDIOSPHERE	0x10028000


#define DOLBY_ADM_COPP_TOPOLOGY_ID	0x0001033B
#define DS2_ADM_COPP_TOPOLOGY_ID	0x1301033B
#define SRS_TRUMEDIA_TOPOLOGY_ID			0x00010D90

#define ADM_ULL_POST_PROCESSING_DEVICE_SESSION		0x8000
/* Definition for a low latency stream session. */
#define ADM_LOW_LATENCY_DEVICE_SESSION			0x2000

/* Definition for a ultra low latency stream session. */
#define ADM_ULTRA_LOW_LATENCY_DEVICE_SESSION		0x4000

#define COMPRESSED_PASSTHROUGH_DEFAULT_TOPOLOGY         0x0001076B
#define VPM_TX_SM_ECNS_COPP_TOPOLOGY			0x00010F71
#define VPM_TX_DM_FLUENCE_COPP_TOPOLOGY			0x00010F72
#define VPM_TX_QMIC_FLUENCE_COPP_TOPOLOGY		0x00010F75
#define VPM_TX_DM_RFECNS_COPP_TOPOLOGY			0x00010F86
/* Definition for a ultra low latency with Post Processing stream session. */

/* Definition for a legacy device session. */
#define ADM_LEGACY_DEVICE_SESSION                                      0
#define ADM_MATRIX_ID_AUDIO_RX              0

#define ADM_MATRIX_ID_AUDIO_TX              1

#define ADM_MATRIX_ID_COMPRESSED_AUDIO_RX   2
/* Enumeration for an audio Tx matrix ID.*/
#define ADM_MATRIX_ID_AUDIOX              1

#define ADM_MAX_COPPS 5

struct adm_session_map_node_v5 {
	u16                  session_id;
/* Handle of the ASM session to be routed. Supported values: 1
* to 8.
*/


	u16                  num_copps;
	/* Number of COPPs to which this session is to be routed.
			Supported values: 0 < num_copps <= ADM_MAX_COPPS.
	*/
} __packed;
struct adm_cmd_matrix_map_routings_v5 {
	struct apr_hdr	hdr;

	u32                  matrix_id;
/* Specifies whether the matrix ID is Audio Rx (0) or Audio Tx
* (1). Use the ADM_MATRIX_ID_AUDIO_RX or ADM_MATRIX_ID_AUDIOX
* macros to set this field.
*/
	u32                  num_sessions;
	/* Number of sessions being updated by this command (optional).*/
} __packed;

struct adm_cmd_connect_afe_port_v5 {
	struct apr_hdr     hdr;
	u8                  mode;
/* ID of the stream router (RX/TX). Use the
 * ADM_STRTR_ID_RX or ADM_STRTR_IDX macros
 * to set this field.
 */

	u8                  session_id;
	/* Session ID of the stream to connect */

	u16                 afe_port_id;
	/* Port ID of the AFE port to connect to.*/
	u32                 num_channels;
/* Number of device channels
 * Supported values: 2(Audio Sample Packet),
 * 8 (HBR Audio Stream Sample Packet)
 */

	u32                 sampling_rate;
/* Device sampling rate
* Supported values: Any
*/
} __packed;


/*  Payload of the #ADM_CMD_SET_PP_PARAMS_V5 command.
 *	If the data_payload_addr_lsw and data_payload_addr_msw element
 *	are NULL, a series of adm_param_datastructures immediately
 *	follows, whose total size is data_payload_size bytes.
 */
struct adm_cmd_set_pp_params_v5 {
	struct apr_hdr hdr;
	u32		payload_addr_lsw;
	/* LSW of parameter data payload address.*/
	u32		payload_addr_msw;
	/* MSW of parameter data payload address.*/

	u32		mem_map_handle;
/* Memory map handle returned by ADM_CMD_SHARED_MEM_MAP_REGIONS
 * command */
/* If mem_map_handle is zero implies the message is in
 * the payload */

	u32		payload_size;
/* Size in bytes of the variable payload accompanying this
 * message or
 * in shared memory. This is used for parsing the parameter
 * payload.
 */
} __packed;

struct adm_cmd_device_open_v5 {
	struct apr_hdr		hdr;
	u16                  flags;
/* Reserved for future use. Clients must set this field
 * to zero.
 */

	u16                  mode_of_operation;
/* Specifies whether the COPP must be opened on the Tx or Rx
 * path. Use the ADM_CMD_COPP_OPEN_MODE_OF_OPERATION_* macros for
 * supported values and interpretation.
 * Supported values:
 * - 0x1 -- Rx path COPP
 * - 0x2 -- Tx path live COPP
 * - 0x3 -- Tx path nonlive COPP
 * Live connections cause sample discarding in the Tx device
 * matrix if the destination output ports do not pull them
 * fast enough. Nonlive connections queue the samples
 * indefinitely.
 */

	u16                  endpoint_id_1;
/* Logical and physical endpoint ID of the audio path.
 * If the ID is a voice processor Tx block, it receives near
 * samples.	Supported values: Any pseudoport, AFE Rx port,
 * or AFE Tx port For a list of valid IDs, refer to
 * @xhyperref{Q4,[Q4]}.
 * Q4 = Hexagon Multimedia: AFE Interface Specification
 */

	u16                  endpoint_id_2;
/* Logical and physical endpoint ID 2 for a voice processor
 * Tx block.
 * This is not applicable to audio COPP.
 * Supported values:
 * - AFE Rx port
 * - 0xFFFF -- Endpoint 2 is unavailable and the voice
 * processor Tx
 * block ignores this endpoint
 * When the voice processor Tx block is created on the audio
 * record path,
 * it can receive far-end samples from an AFE Rx port if the
 * voice call
 * is active. The ID of the AFE port is provided in this
 * field.
 * For a list of valid IDs, refer @xhyperref{Q4,[Q4]}.
 */

	u32                  topology_id;
	/* Audio COPP topology ID; 32-bit GUID. */

	u16                  dev_num_channel;
/* Number of channels the audio COPP sends to/receives from
 * the endpoint.
 * Supported values: 1 to 8.
 * The value is ignored for the voice processor Tx block,
 * where channel
 * configuration is derived from the topology ID.
 */

	u16                  bit_width;
/* Bit width (in bits) that the audio COPP sends to/receives
 * from the
 * endpoint. The value is ignored for the voice processing
 * Tx block,
 * where the PCM width is 16 bits.
 */

	u32                  sample_rate;
/* Sampling rate at which the audio COPP/voice processor
 * Tx block
 * interfaces with the endpoint.
 * Supported values for voice processor Tx: 8000, 16000,
 * 48000 Hz
 * Supported values for audio COPP: >0 and <=192 kHz
 */

	u8                   dev_channel_mapping[8];
/* Array of channel mapping of buffers that the audio COPP
 * sends to the endpoint. Channel[i] mapping describes channel
 * I inside the buffer, where 0 < i < dev_num_channel.
 * This value is relevent only for an audio Rx COPP.
 * For the voice processor block and Tx audio block, this field
 * is set to zero and is ignored.
 */
} __packed;


struct adm_cmd_rsp_device_open_v5 {
	u32                  status;
	/* Status message (error code).*/

	u16                  copp_id;
	/* COPP ID:  Supported values: 0 <= copp_id < ADM_MAX_COPPS*/

	u16                  reserved;
	/* Reserved. This field must be set to zero.*/
} __packed;

/* ENUM for adm_status */
enum adm_cal_status {
	ADM_STATUS_CALIBRATION_REQUIRED = 0,
	ADM_STATUS_MAX,
};

struct adm_copp {
	atomic_t id[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t cnt[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t topology[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t mode[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t stat[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t rate[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t bit_width[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t channels[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t app_type[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t acdb_id[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	wait_queue_head_t wait[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	wait_queue_head_t adm_delay_wait[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	atomic_t adm_delay_stat[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	uint32_t adm_delay[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
	unsigned long adm_status[AFE_MAX_PORTS][MAX_COPPS_PER_PORT];
};



struct adm_ctl {
	void *apr;

	struct adm_copp copp;

	atomic_t matrix_map_stat;
	wait_queue_head_t matrix_map_wait;

	atomic_t adm_stat;
	wait_queue_head_t adm_wait;

	int set_custom_topology;
	int ec_ref_rx;
};

static struct adm_ctl this_adm;

struct adm_multi_ch_map {
	bool set_channel_map;
	char channel_mapping[PCM_FORMAT_MAX_NUM_CHANNEL];
};

#define ADM_MCH_MAP_IDX_PLAYBACK 0
#define ADM_MCH_MAP_IDX_REC 1
static struct adm_multi_ch_map multi_ch_maps[2] = {
							{ false,
							{0, 0, 0, 0, 0, 0, 0, 0}
							},
							{ false,
							{0, 0, 0, 0, 0, 0, 0, 0}
							}
};

static int adm_get_parameters[MAX_COPPS_PER_PORT * ADM_GET_PARAMETER_LENGTH];
static int adm_module_topo_list[
	MAX_COPPS_PER_PORT * ADM_GET_TOPO_MODULE_LIST_LENGTH];

int adm_validate_and_get_port_index(int port_id)
{
	return port_id;
}

static int adm_get_copp_id(int port_idx, int copp_idx)
{
	pr_debug("%s: port_idx:%d copp_idx:%d\n", __func__, port_idx, copp_idx);

	if (copp_idx < 0 || copp_idx >= MAX_COPPS_PER_PORT) {
		pr_err("%s: Invalid copp_num: %d\n", __func__, copp_idx);
		return -EINVAL;
	}
	return atomic_read(&this_adm.copp.id[port_idx][copp_idx]);
}

static int adm_get_idx_if_copp_exists(int port_idx, int topology, int mode,
				 int rate, int bit_width, int app_type)
{
	int idx;

	pr_debug("%s: port_idx-%d, topology-0x%x, mode-%d, rate-%d, bit_width-%d\n",
		 __func__, port_idx, topology, mode, rate, bit_width);

	for (idx = 0; idx < MAX_COPPS_PER_PORT; idx++)
		if ((topology ==
			atomic_read(&this_adm.copp.topology[port_idx][idx])) &&
		    (mode == atomic_read(&this_adm.copp.mode[port_idx][idx])) &&
		    (rate == atomic_read(&this_adm.copp.rate[port_idx][idx])) &&
		    (bit_width ==
			atomic_read(&this_adm.copp.bit_width[port_idx][idx])) &&
		    (app_type ==
			atomic_read(&this_adm.copp.app_type[port_idx][idx])))
			return idx;
	return -EINVAL;
}

static int adm_get_next_available_copp(int port_idx)
{
	int idx;

	pr_debug("%s:\n", __func__);
	for (idx = 0; idx < MAX_COPPS_PER_PORT; idx++) {
		pr_debug("%s: copp_id:0x%x port_idx:%d idx:%d\n", __func__,
			 atomic_read(&this_adm.copp.id[port_idx][idx]),
			 port_idx, idx);
		if (atomic_read(&this_adm.copp.id[port_idx][idx]) ==
								RESET_COPP_ID)
			break;
	}
	return idx;
}

static void adm_callback_debug_print(struct apr_client_data *data)
{
	uint32_t *payload;
	payload = data->payload;

	if (data->payload_size >= 8)
		pr_debug("%s: code = 0x%x PL#0[0x%x], PL#1[0x%x], size = %d\n",
			__func__, data->opcode, payload[0], payload[1],
			data->payload_size);
	else if (data->payload_size >= 4)
		pr_debug("%s: code = 0x%x PL#0[0x%x], size = %d\n",
			__func__, data->opcode, payload[0],
			data->payload_size);
	else
		pr_debug("%s: code = 0x%x, size = %d\n",
			__func__, data->opcode, data->payload_size);
}

static int32_t adm_callback(struct apr_client_data *data, void *priv)
{
	uint32_t *payload;
	int i, j, port_idx, copp_idx, idx, client_id;

	if (data == NULL) {
		pr_err("%s: data paramter is null\n", __func__);
		return -EINVAL;
	}

	payload = data->payload;

	if (data->opcode == RESET_EVENTS) {
		pr_debug("%s: Reset event is received: %d %d apr[%p]\n",
			__func__,
			data->reset_event, data->reset_proc, this_adm.apr);
		if (this_adm.apr) {
			apr_reset(this_adm.apr);
			for (i = 0; i < AFE_MAX_PORTS; i++) {
				for (j = 0; j < MAX_COPPS_PER_PORT; j++) {
					atomic_set(&this_adm.copp.id[i][j],
						   RESET_COPP_ID);
					atomic_set(&this_adm.copp.cnt[i][j], 0);
					atomic_set(
					   &this_adm.copp.topology[i][j], 0);
					atomic_set(&this_adm.copp.mode[i][j],
						   0);
					atomic_set(&this_adm.copp.stat[i][j],
						   0);
					atomic_set(&this_adm.copp.rate[i][j],
						   0);
					atomic_set(
					&this_adm.copp.channels[i][j],
						   0);
					atomic_set(
					    &this_adm.copp.bit_width[i][j], 0);
					atomic_set(
					    &this_adm.copp.app_type[i][j], 0);
					atomic_set(
					   &this_adm.copp.acdb_id[i][j], 0);
					this_adm.copp.adm_status[i][j] =
						ADM_STATUS_CALIBRATION_REQUIRED;
				}
			}
			this_adm.apr = NULL;
		}
		return 0;
	}

	adm_callback_debug_print(data);
	if (data->payload_size) {
		copp_idx = (data->token) & 0XFF;
		port_idx = ((data->token) >> 16) & 0xFF;
		client_id = ((data->token) >> 8) & 0xFF;
		if (port_idx < 0 || port_idx >= AFE_MAX_PORTS) {
			pr_err("%s: Invalid port idx %d token %d\n",
				__func__, port_idx, data->token);
			return 0;
		}
		if (copp_idx < 0 || copp_idx >= MAX_COPPS_PER_PORT) {
			pr_err("%s: Invalid copp idx %d token %d\n",
				__func__, copp_idx, data->token);
			return 0;
		}
		if (client_id < 0 || client_id >= ADM_CLIENT_ID_MAX) {
			pr_err("%s: Invalid client id %d\n", __func__,
				client_id);
			return 0;
		}
		if (data->opcode == APR_BASIC_RSP_RESULT) {
			pr_debug("%s: APR_BASIC_RSP_RESULT id 0x%x\n",
				__func__, payload[0]);
			if (payload[1] != 0) {
				pr_err("%s: cmd = 0x%x returned error = 0x%x\n",
					__func__, payload[0], payload[1]);
			}
			switch (payload[0]) {
			case ADM_CMD_SET_PP_PARAMS_V5:
				pr_debug("%s: ADM_CMD_SET_PP_PARAMS_V5\n",
					__func__);
					break;
				/*
				 * if soft volume is called and already
				 * interrupted break out of the sequence here
				 */
			case ADM_CMD_DEVICE_OPEN_V5:
			case ADM_CMD_DEVICE_CLOSE_V5:
				pr_debug("%s: Basic callback received, wake up.\n",
					__func__);
				atomic_set(&this_adm.copp.stat[port_idx]
						[copp_idx], payload[1]);
				wake_up(
				&this_adm.copp.wait[port_idx][copp_idx]);
				break;
			case ADM_CMD_ADD_TOPOLOGIES:
				pr_debug("%s: callback received, ADM_CMD_ADD_TOPOLOGIES.\n",
					__func__);
				atomic_set(&this_adm.adm_stat, payload[1]);
				wake_up(&this_adm.adm_wait);
				break;
			case ADM_CMD_MATRIX_MAP_ROUTINGS_V5:
			case ADM_CMD_STREAM_DEVICE_MAP_ROUTINGS_V5:
				pr_debug("%s: Basic callback received, wake up.\n",
					__func__);
				atomic_set(&this_adm.matrix_map_stat,
					payload[1]);
				wake_up(&this_adm.matrix_map_wait);
				break;
			case ADM_CMD_SHARED_MEM_UNMAP_REGIONS:
				pr_debug("%s: ADM_CMD_SHARED_MEM_UNMAP_REGIONS\n",
					__func__);
				atomic_set(&this_adm.adm_stat, payload[1]);
				wake_up(&this_adm.adm_wait);
				break;
			case ADM_CMD_SHARED_MEM_MAP_REGIONS:
				pr_debug("%s: ADM_CMD_SHARED_MEM_MAP_REGIONS\n",
					__func__);
				/* Should only come here if there is an APR */
				/* error or malformed APR packet. Otherwise */
				/* response will be returned as */
				if (payload[1] != 0) {
					pr_err("%s: ADM map error, resuming\n",
						__func__);
					atomic_set(&this_adm.adm_stat,
						payload[1]);
					wake_up(&this_adm.adm_wait);
				}
				break;
			case ADM_CMD_GET_PP_PARAMS_V5:
				pr_debug("%s: ADM_CMD_GET_PP_PARAMS_V5\n",
					__func__);
				/* Should only come here if there is an APR */
				/* error or malformed APR packet. Otherwise */
				/* response will be returned as */
				/* ADM_CMDRSP_GET_PP_PARAMS_V5 */
					if (payload[1] != 0) {
						pr_err("%s: ADM get param error = %d, resuming\n",
							__func__, payload[1]);

						//rtac_make_adm_callback(payload,
						//	data->payload_size);
					}
				break;
			case ADM_CMD_SET_PSPD_MTMX_STRTR_PARAMS_V5:
				pr_debug("%s: ADM_CMD_SET_PSPD_MTMX_STRTR_PARAMS_V5\n",
					__func__);
				atomic_set(&this_adm.copp.stat[port_idx]
						[copp_idx], payload[1]);
				wake_up(
				&this_adm.copp.wait[port_idx][copp_idx]);
				break;
			case ADM_CMD_GET_PP_TOPO_MODULE_LIST:
				pr_debug("%s:ADM_CMD_GET_PP_TOPO_MODULE_LIST\n",
					 __func__);
				if (payload[1] != 0)
					pr_err("%s: ADM get topo list error = %d,\n",
						__func__, payload[1]);
				break;
			default:
				pr_err("%s: Unknown Cmd: 0x%x\n", __func__,
								payload[0]);
				break;
			}
			return 0;
		}

		switch (data->opcode) {
		case ADM_CMDRSP_DEVICE_OPEN_V5: {
			struct adm_cmd_rsp_device_open_v5 *open =
			(struct adm_cmd_rsp_device_open_v5 *)data->payload;

			if (open->copp_id == INVALID_COPP_ID) {
				pr_err("%s: invalid coppid rxed %d\n",
					__func__, open->copp_id);
				atomic_set(&this_adm.copp.stat[port_idx]
						[copp_idx], ADSP_EBADPARAM);
				wake_up(
				&this_adm.copp.wait[port_idx][copp_idx]);
				break;
			}
			atomic_set(&this_adm.copp.stat
				[port_idx][copp_idx], payload[0]);
			atomic_set(&this_adm.copp.id[port_idx][copp_idx],
				   open->copp_id);
			pr_debug("%s: coppid rxed=%d\n", __func__,
				 open->copp_id);
			wake_up(&this_adm.copp.wait[port_idx][copp_idx]);
			}
			break;
		case ADM_CMDRSP_GET_PP_PARAMS_V5:
			pr_debug("%s: ADM_CMDRSP_GET_PP_PARAMS_V5\n", __func__);
			if (payload[0] != 0)
				pr_err("%s: ADM_CMDRSP_GET_PP_PARAMS_V5 returned error = 0x%x\n",
					__func__, payload[0]);
				break;

			idx = ADM_GET_PARAMETER_LENGTH * copp_idx;
			if ((payload[0] == 0) && (data->payload_size >
				(4 * sizeof(*payload))) &&
				(data->payload_size - 4 >=
				payload[3]) &&
				(ARRAY_SIZE(adm_get_parameters) >
				idx) &&
				(ARRAY_SIZE(adm_get_parameters)-idx-1 >=
				payload[3])) {
				adm_get_parameters[idx] = payload[3] /
							sizeof(uint32_t);
				/*
				 * payload[3] is param_size which is
				 * expressed in number of bytes
				 */
				pr_debug("%s: GET_PP PARAM:received parameter length: 0x%x\n",
					__func__, adm_get_parameters[idx]);
				/* storing param size then params */
				for (i = 0; i < payload[3] /
						sizeof(uint32_t); i++)
					adm_get_parameters[idx+1+i] =
							payload[4+i];
			} else if (payload[0] == 0) {
				adm_get_parameters[idx] = -1;
				pr_err("%s: Out of band case, setting size to %d\n",
					__func__, adm_get_parameters[idx]);
			} else {
				adm_get_parameters[idx] = -1;
				pr_err("%s: GET_PP_PARAMS failed, setting size to %d\n",
					__func__, adm_get_parameters[idx]);
			}
			atomic_set(&this_adm.copp.stat
				[port_idx][copp_idx], payload[0]);
			wake_up(&this_adm.copp.wait[port_idx][copp_idx]);
			break;
		case ADM_CMDRSP_GET_PP_TOPO_MODULE_LIST:
			pr_debug("%s: ADM_CMDRSP_GET_PP_TOPO_MODULE_LIST\n",
				 __func__);
			if (payload[0] != 0) {
				pr_err("%s: ADM_CMDRSP_GET_PP_TOPO_MODULE_LIST",
					 __func__);
				pr_err(":err = 0x%x\n", payload[0]);
			} else if (payload[1] >
				   ((ADM_GET_TOPO_MODULE_LIST_LENGTH /
				   sizeof(uint32_t)) - 1)) {
				pr_err("%s: ADM_CMDRSP_GET_PP_TOPO_MODULE_LIST",
					 __func__);
				pr_err(":size = %d\n", payload[1]);
			} else {
				idx = ADM_GET_TOPO_MODULE_LIST_LENGTH *
					copp_idx;
				pr_debug("%s:Num modules payload[1] %d\n",
					 __func__, payload[1]);
				adm_module_topo_list[idx] = payload[1];
				for (i = 1; i <= payload[1]; i++) {
					adm_module_topo_list[idx+i] =
						payload[1+i];
					pr_debug("%s:payload[%d] = %x\n",
						 __func__, (i+1), payload[1+i]);
				}
			}
			atomic_set(&this_adm.copp.stat
				[port_idx][copp_idx], payload[0]);
			wake_up(&this_adm.copp.wait[port_idx][copp_idx]);
			break;
		default:
			pr_err("%s: Unknown cmd:0x%x\n", __func__,
				data->opcode);
			break;
		}
	}
	return 0;
}
static void send_adm_custom_topology(void)
{
	return;
}

int adm_connect_afe_port(int mode, int session_id, int port_id)
{
	struct adm_cmd_connect_afe_port_v5	cmd;
	int ret = 0;
	int port_idx, copp_idx = 0;

	pr_debug("%s: port_id: 0x%x session id:%d mode:%d\n", __func__,
				port_id, session_id, mode);

//	port_id = afe_convert_virtual_to_portid(port_id);
	port_idx = adm_validate_and_get_port_index(port_id);
	if (port_idx < 0) {
		pr_err("%s: Invalid port_id 0x%x\n", __func__, port_id);
		return -EINVAL;
	}
	pr_debug("%s: Port ID 0x%x, index %d\n", __func__, port_id, port_idx);

	cmd.hdr.hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
			APR_HDR_LEN(APR_HDR_SIZE), APR_PKT_VER);
	cmd.hdr.pkt_size = sizeof(cmd);
	cmd.hdr.src_svc = APR_SVC_ADM;
	cmd.hdr.src_domain = APR_DOMAIN_APPS;
	cmd.hdr.src_port = port_id;
	cmd.hdr.dest_svc = APR_SVC_ADM;
	cmd.hdr.dest_domain = APR_DOMAIN_ADSP;
	cmd.hdr.dest_port = 0; /* Ignored */
	cmd.hdr.token = port_idx << 16 | copp_idx;
	cmd.hdr.opcode = ADM_CMD_CONNECT_AFE_PORT_V5;

	cmd.mode = mode;
	cmd.session_id = session_id;
	cmd.afe_port_id = port_id;

	atomic_set(&this_adm.copp.stat[port_idx][copp_idx], -1);
	ret = apr_send_pkt(this_adm.apr, (uint32_t *)&cmd);
	if (ret < 0) {
		pr_err("%s: ADM enable for port_id: 0x%x failed ret %d\n",
					__func__, port_id, ret);
		ret = -EINVAL;
		goto fail_cmd;
	}
	/* Wait for the callback with copp id */
	ret = wait_event_timeout(this_adm.copp.wait[port_idx][copp_idx],
		atomic_read(&this_adm.copp.stat[port_idx][copp_idx]) >= 0,
		msecs_to_jiffies(TIMEOUT_MS));
	if (!ret) {
		pr_err("%s: ADM connect timedout for port_id: 0x%x\n",
			__func__, port_id);
		ret = -EINVAL;
		goto fail_cmd;
	} else if (atomic_read(&this_adm.copp.stat
				[port_idx][copp_idx]) > 0) {
		pr_err("%s: DSP returned error[%s]\n",
				__func__, adsp_err_get_err_str(
				atomic_read(&this_adm.copp.stat
				[port_idx][copp_idx])));
		ret = adsp_err_get_lnx_err_code(
				atomic_read(&this_adm.copp.stat
					[port_idx][copp_idx]));
		goto fail_cmd;
	}
	atomic_inc(&this_adm.copp.cnt[port_idx][copp_idx]);
	return 0;

fail_cmd:

	return ret;
}

int adm_arrange_mch_map(struct adm_cmd_device_open_v5 *open, int path,
			 int channel_mode)
{
	int rc = 0, idx;

	memset(open->dev_channel_mapping, 0,
	       PCM_FORMAT_MAX_NUM_CHANNEL);

	if (channel_mode == 1)	{
		open->dev_channel_mapping[0] = PCM_CHANNEL_FC;
	} else if (channel_mode == 2) {
		open->dev_channel_mapping[0] = PCM_CHANNEL_FL;
		open->dev_channel_mapping[1] = PCM_CHANNEL_FR;
	} else if (channel_mode == 3)	{
		open->dev_channel_mapping[0] = PCM_CHANNEL_FL;
		open->dev_channel_mapping[1] = PCM_CHANNEL_FR;
		open->dev_channel_mapping[2] = PCM_CHANNEL_FC;
	} else if (channel_mode == 4) {
		open->dev_channel_mapping[0] = PCM_CHANNEL_FL;
		open->dev_channel_mapping[1] = PCM_CHANNEL_FR;
		open->dev_channel_mapping[2] = PCM_CHANNEL_LS;
		open->dev_channel_mapping[3] = PCM_CHANNEL_RS;
	} else if (channel_mode == 5) {
		open->dev_channel_mapping[0] = PCM_CHANNEL_FL;
		open->dev_channel_mapping[1] = PCM_CHANNEL_FR;
		open->dev_channel_mapping[2] = PCM_CHANNEL_FC;
		open->dev_channel_mapping[3] = PCM_CHANNEL_LS;
		open->dev_channel_mapping[4] = PCM_CHANNEL_RS;
	} else if (channel_mode == 6) {
		open->dev_channel_mapping[0] = PCM_CHANNEL_FL;
		open->dev_channel_mapping[1] = PCM_CHANNEL_FR;
		open->dev_channel_mapping[2] = PCM_CHANNEL_LFE;
		open->dev_channel_mapping[3] = PCM_CHANNEL_FC;
		open->dev_channel_mapping[4] = PCM_CHANNEL_LS;
		open->dev_channel_mapping[5] = PCM_CHANNEL_RS;
	} else if (channel_mode == 8) {
		open->dev_channel_mapping[0] = PCM_CHANNEL_FL;
		open->dev_channel_mapping[1] = PCM_CHANNEL_FR;
		open->dev_channel_mapping[2] = PCM_CHANNEL_LFE;
		open->dev_channel_mapping[3] = PCM_CHANNEL_FC;
		open->dev_channel_mapping[4] = PCM_CHANNEL_LS;
		open->dev_channel_mapping[5] = PCM_CHANNEL_RS;
		open->dev_channel_mapping[6] = PCM_CHANNEL_LB;
		open->dev_channel_mapping[7] = PCM_CHANNEL_RB;
	} else {
		pr_err("%s: invalid num_chan %d\n", __func__,
			channel_mode);
		rc = -EINVAL;
		goto inval_ch_mod;
	}

	switch (path) {
	case ADM_PATH_PLAYBACK:
		idx = ADM_MCH_MAP_IDX_PLAYBACK;
		break;
	case ADM_PATH_LIVE_REC:
		idx = ADM_MCH_MAP_IDX_REC;
		break;
	default:
		goto non_mch_path;
		break;
	};

	if ((open->dev_num_channel > 2) && multi_ch_maps[idx].set_channel_map)
		memcpy(open->dev_channel_mapping,
		       multi_ch_maps[idx].channel_mapping,
		       PCM_FORMAT_MAX_NUM_CHANNEL);

non_mch_path:
inval_ch_mod:
	return rc;
}

int adm_open(int port_id, int path, int rate, int channel_mode, int topology,
	     int perf_mode, uint16_t bit_width, int app_type, int acdb_id)
{
	struct adm_cmd_device_open_v5	open;
	int ret = 0;
	int port_idx, copp_idx, flags;
	//int tmp_port = q6audio_get_port_id(port_id);
	int tmp_port = q6afe_get_port_id(port_id);

	pr_info("%s:port %#x path:%d rate:%d mode:%d perf_mode:%d,topo_id %d\n",
		 __func__, port_id, path, rate, channel_mode, perf_mode,
		 topology);

	/* For DTS EAGLE only, force 24 bit */
	if ((topology == ADM_CMD_COPP_OPEN_TOPOLOGY_ID_DTS_HPX) &&
		(perf_mode == LEGACY_PCM_MODE)) {
		bit_width = 24;
		pr_debug("%s: Force open adm in 24-bit for DTS HPX topology 0x%x\n",
			__func__, topology);
	}
//	port_id = q6audio_convert_virtual_to_portid(port_id);
	port_idx = adm_validate_and_get_port_index(port_id);
	if (port_idx < 0) {
		pr_err("%s: Invalid port_id 0x%x\n", __func__, port_id);
		return -EINVAL;
	}

	if (perf_mode == ULL_POST_PROCESSING_PCM_MODE) {
		flags = ADM_ULL_POST_PROCESSING_DEVICE_SESSION;
		if ((topology == DOLBY_ADM_COPP_TOPOLOGY_ID) ||
		    (topology == DS2_ADM_COPP_TOPOLOGY_ID) ||
		    (topology == SRS_TRUMEDIA_TOPOLOGY_ID) ||
		    (topology == ADM_CMD_COPP_OPEN_TOPOLOGY_ID_DTS_HPX))
			topology = DEFAULT_COPP_TOPOLOGY;
	} else if (perf_mode == ULTRA_LOW_LATENCY_PCM_MODE) {
		flags = ADM_ULTRA_LOW_LATENCY_DEVICE_SESSION;
		topology = NULL_COPP_TOPOLOGY;
		rate = ULL_SUPPORTED_SAMPLE_RATE;
		bit_width = ULL_SUPPORTED_BITS_PER_SAMPLE;
	} else if (perf_mode == LOW_LATENCY_PCM_MODE) {
		flags = ADM_LOW_LATENCY_DEVICE_SESSION;
		if ((topology == DOLBY_ADM_COPP_TOPOLOGY_ID) ||
		    (topology == DS2_ADM_COPP_TOPOLOGY_ID) ||
		    (topology == SRS_TRUMEDIA_TOPOLOGY_ID) ||
		    (topology == ADM_CMD_COPP_OPEN_TOPOLOGY_ID_DTS_HPX))
			topology = DEFAULT_COPP_TOPOLOGY;
	} else {
		if (path == ADM_PATH_COMPRESSED_RX)
			flags = 0;
		else
			flags = ADM_LEGACY_DEVICE_SESSION;
	}

	if ((topology == VPM_TX_SM_ECNS_COPP_TOPOLOGY) ||
	    (topology == VPM_TX_DM_FLUENCE_COPP_TOPOLOGY) ||
	    (topology == VPM_TX_DM_RFECNS_COPP_TOPOLOGY))
		rate = 16000;

	copp_idx = adm_get_idx_if_copp_exists(port_idx, topology, perf_mode,
						rate, bit_width, app_type);
	if (copp_idx < 0) {
		copp_idx = adm_get_next_available_copp(port_idx);
		if (copp_idx >= MAX_COPPS_PER_PORT) {
			pr_err("%s: exceeded copp id %d\n",
				 __func__, copp_idx);
			return -EINVAL;
		} else {
			atomic_set(&this_adm.copp.cnt[port_idx][copp_idx], 0);
			atomic_set(&this_adm.copp.topology[port_idx][copp_idx],
				   topology);
			atomic_set(&this_adm.copp.mode[port_idx][copp_idx],
				   perf_mode);
			atomic_set(&this_adm.copp.rate[port_idx][copp_idx],
				   rate);
			atomic_set(&this_adm.copp.channels[port_idx][copp_idx],
				   channel_mode);
			atomic_set(&this_adm.copp.bit_width[port_idx][copp_idx],
				   bit_width);
			atomic_set(&this_adm.copp.app_type[port_idx][copp_idx],
				   app_type);
			atomic_set(&this_adm.copp.acdb_id[port_idx][copp_idx],
				   acdb_id);
			set_bit(ADM_STATUS_CALIBRATION_REQUIRED,
			(void *)&this_adm.copp.adm_status[port_idx][copp_idx]);
			if (path != ADM_PATH_COMPRESSED_RX)
				send_adm_custom_topology();
		}
	}

	if (this_adm.copp.adm_delay[port_idx][copp_idx] &&
		perf_mode == LEGACY_PCM_MODE) {
		atomic_set(&this_adm.copp.adm_delay_stat[port_idx][copp_idx],
			   1);
		this_adm.copp.adm_delay[port_idx][copp_idx] = 0;
		wake_up(&this_adm.copp.adm_delay_wait[port_idx][copp_idx]);
	}

	/* Create a COPP if port id are not enabled */
	if (atomic_read(&this_adm.copp.cnt[port_idx][copp_idx]) == 0) {
		pr_debug("%s: open ADM: port_idx: %d, copp_idx: %d\n", __func__,
			 port_idx, copp_idx);
		open.hdr.hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
						   APR_HDR_LEN(APR_HDR_SIZE),
						   APR_PKT_VER);
		open.hdr.pkt_size = sizeof(open);
		open.hdr.src_svc = APR_SVC_ADM;
		open.hdr.src_domain = APR_DOMAIN_APPS;
		open.hdr.src_port = tmp_port;
		open.hdr.dest_svc = APR_SVC_ADM;
		open.hdr.dest_domain = APR_DOMAIN_ADSP;
		open.hdr.dest_port = tmp_port;
		open.hdr.token = port_idx << 16 | copp_idx;
		open.hdr.opcode = ADM_CMD_DEVICE_OPEN_V5;
		open.flags = flags;
		open.mode_of_operation = path;
		open.endpoint_id_1 = tmp_port;

		if (this_adm.ec_ref_rx == -1) {
			open.endpoint_id_2 = 0xFFFF;
		} else if (this_adm.ec_ref_rx && (path != 1)) {
			open.endpoint_id_2 = this_adm.ec_ref_rx;
			this_adm.ec_ref_rx = -1;
		}

		open.topology_id = topology;

		open.dev_num_channel = channel_mode & 0x00FF;
		open.bit_width = bit_width;
		WARN_ON((perf_mode == ULTRA_LOW_LATENCY_PCM_MODE) &&
			(rate != ULL_SUPPORTED_SAMPLE_RATE));
		open.sample_rate  = rate;

		ret = adm_arrange_mch_map(&open, path, channel_mode);

		if (ret)
			return ret;

		pr_debug("%s: port_id=0x%x rate=%d topology_id=0x%X\n",
			__func__, open.endpoint_id_1, open.sample_rate,
			open.topology_id);

		atomic_set(&this_adm.copp.stat[port_idx][copp_idx], -1);

		ret = apr_send_pkt(this_adm.apr, (uint32_t *)&open);
		if (ret < 0) {
			pr_err("%s: port_id: 0x%x for[0x%x] failed %d\n",
			__func__, tmp_port, port_id, ret);
			return -EINVAL;
		}
		/* Wait for the callback with copp id */
		ret = wait_event_timeout(this_adm.copp.wait[port_idx][copp_idx],
			atomic_read(&this_adm.copp.stat
			[port_idx][copp_idx]) >= 0,
			msecs_to_jiffies(TIMEOUT_MS));
		if (!ret) {
			pr_err("%s: ADM open timedout for port_id: 0x%x for [0x%x]\n",
						__func__, tmp_port, port_id);
			return -EINVAL;
		} else if (atomic_read(&this_adm.copp.stat
					[port_idx][copp_idx]) > 0) {
			pr_err("%s: DSP returned error[%s]\n",
				__func__, adsp_err_get_err_str(
				atomic_read(&this_adm.copp.stat
				[port_idx][copp_idx])));
			return adsp_err_get_lnx_err_code(
					atomic_read(&this_adm.copp.stat
						[port_idx][copp_idx]));
		}
	}
	atomic_inc(&this_adm.copp.cnt[port_idx][copp_idx]);
	return copp_idx;
}

int adm_matrix_map(int path, struct route_payload payload_map, int perf_mode)
{
	struct adm_cmd_matrix_map_routings_v5	*route;
	struct adm_session_map_node_v5 *node;
	uint16_t *copps_list;
	int cmd_size = 0;
	int ret = 0, i = 0;
	void *payload = NULL;
	void *matrix_map = NULL;
	int port_idx, copp_idx;

	/* Assumes port_ids have already been validated during adm_open */
	cmd_size = (sizeof(struct adm_cmd_matrix_map_routings_v5) +
			sizeof(struct adm_session_map_node_v5) +
			(sizeof(uint32_t) * payload_map.num_copps));
	matrix_map = kzalloc(cmd_size, GFP_KERNEL);
	if (matrix_map == NULL) {
		pr_err("%s: Mem alloc failed\n", __func__);
		ret = -EINVAL;
		return ret;
	}
	route = (struct adm_cmd_matrix_map_routings_v5 *)matrix_map;

	route->hdr.hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
				APR_HDR_LEN(APR_HDR_SIZE), APR_PKT_VER);
	route->hdr.pkt_size = cmd_size;
	route->hdr.src_svc = 0;
	route->hdr.src_domain = APR_DOMAIN_APPS;
	route->hdr.src_port = 0; /* Ignored */;
	route->hdr.dest_svc = APR_SVC_ADM;
	route->hdr.dest_domain = APR_DOMAIN_ADSP;
	route->hdr.dest_port = 0; /* Ignored */;
	route->hdr.token = 0;
	if (path == ADM_PATH_COMPRESSED_RX) {
		pr_debug("%s: ADM_CMD_STREAM_DEVICE_MAP_ROUTINGS_V5 0x%x\n",
			 __func__, ADM_CMD_STREAM_DEVICE_MAP_ROUTINGS_V5);
		route->hdr.opcode = ADM_CMD_STREAM_DEVICE_MAP_ROUTINGS_V5;
	} else {
		pr_debug("%s: DM_CMD_MATRIX_MAP_ROUTINGS_V5 0x%x\n",
			 __func__, ADM_CMD_MATRIX_MAP_ROUTINGS_V5);
		route->hdr.opcode = ADM_CMD_MATRIX_MAP_ROUTINGS_V5;
	}
	route->num_sessions = 1;

	switch (path) {
	case ADM_PATH_PLAYBACK:
		route->matrix_id = ADM_MATRIX_ID_AUDIO_RX;
		break;
	case ADM_PATH_LIVE_REC:
	case ADM_PATH_NONLIVE_REC:
		route->matrix_id = ADM_MATRIX_ID_AUDIO_TX;
		break;
	case ADM_PATH_COMPRESSED_RX:
		route->matrix_id = ADM_MATRIX_ID_COMPRESSED_AUDIO_RX;
		break;
	default:
		pr_err("%s: Wrong path set[%d]\n", __func__, path);
		break;
	}
	payload = ((u8 *)matrix_map +
			sizeof(struct adm_cmd_matrix_map_routings_v5));
	node = (struct adm_session_map_node_v5 *)payload;

	node->session_id = payload_map.session_id;
	node->num_copps = payload_map.num_copps;
	payload = (u8 *)node + sizeof(struct adm_session_map_node_v5);
	copps_list = (uint16_t *)payload;
	for (i = 0; i < payload_map.num_copps; i++) {
		port_idx =
		adm_validate_and_get_port_index(payload_map.port_id[i]);
		if (port_idx < 0) {
			pr_err("%s: Invalid port_id 0x%x\n", __func__,
				payload_map.port_id[i]);
			return -EINVAL;
		}
		copp_idx = payload_map.copp_idx[i];
		copps_list[i] = atomic_read(&this_adm.copp.id[port_idx]
							     [copp_idx]);
	}
	atomic_set(&this_adm.matrix_map_stat, -1);

	ret = apr_send_pkt(this_adm.apr, (uint32_t *)matrix_map);
	if (ret < 0) {
		pr_err("%s: routing for syream %d failed ret %d\n",
			__func__, payload_map.session_id, ret);
		ret = -EINVAL;
		goto fail_cmd;
	}
	ret = wait_event_timeout(this_adm.matrix_map_wait,
				atomic_read(&this_adm.matrix_map_stat) >= 0,
				msecs_to_jiffies(TIMEOUT_MS));
	if (!ret) {
		pr_err("%s: routing for syream %d failed\n", __func__,
			payload_map.session_id);
		ret = -EINVAL;
		goto fail_cmd;
	} else if (atomic_read(&this_adm.matrix_map_stat) > 0) {
		pr_err("%s: DSP returned error[%s]\n", __func__,
			adsp_err_get_err_str(atomic_read(
			&this_adm.matrix_map_stat)));
		ret = adsp_err_get_lnx_err_code(
				atomic_read(&this_adm.matrix_map_stat));
		goto fail_cmd;
	}

	if ((perf_mode != ULTRA_LOW_LATENCY_PCM_MODE) &&
		 (path != ADM_PATH_COMPRESSED_RX)) {
		for (i = 0; i < payload_map.num_copps; i++) {
			pr_err("DEBUG::: %s  port id %d \n", __func__, payload_map.port_id[i]);
			//port_idx = afe_get_port_index(payload_map.port_id[i]);
			port_idx = payload_map.port_id[i];
			copp_idx = payload_map.copp_idx[i];
			if (atomic_read(
				&this_adm.copp.topology[port_idx][copp_idx]) ==
				ADM_CMD_COPP_OPEN_TOPOLOGY_ID_DTS_HPX)
				continue;

			if (!test_bit(ADM_STATUS_CALIBRATION_REQUIRED,
				(void *)&this_adm.copp.adm_status[port_idx]
								[copp_idx])) {
				pr_debug("%s: adm copp[0x%x][%d] already sent",
						__func__, port_idx, copp_idx);
				continue;
			}
			//send_adm_cal(payload_map.port_id[i], copp_idx,
			//	     get_cal_path(path), perf_mode,
			//	     payload_map.app_type,
			//	     payload_map.acdb_dev_id,
			//	     payload_map.sample_rate);
			/* ADM COPP calibration is already sent */
			clear_bit(ADM_STATUS_CALIBRATION_REQUIRED,
				(void *)&this_adm.copp.
				adm_status[port_idx][copp_idx]);
			pr_debug("%s: copp_id: %d\n", __func__,
				 atomic_read(&this_adm.copp.id[port_idx]
							      [copp_idx]));
		}
	}

fail_cmd:
	kfree(matrix_map);
	return ret;
}

int adm_close(int port_id, int perf_mode, int copp_idx)
{
	struct apr_hdr close;

	int ret = 0, port_idx;
	int copp_id = RESET_COPP_ID;

	pr_debug("%s: port_id=0x%x perf_mode: %d copp_idx: %d\n", __func__,
		 port_id, perf_mode, copp_idx);

//	port_id = q6audio_convert_virtual_to_portid(port_id);
	port_idx = adm_validate_and_get_port_index(port_id);
	if (port_idx < 0) {
		pr_err("%s: Invalid port_id 0x%x\n",
			__func__, port_id);
		return -EINVAL;
	}

	if ((copp_idx < 0) || (copp_idx >= MAX_COPPS_PER_PORT)) {
		pr_err("%s: Invalid copp idx: %d\n", __func__, copp_idx);
		return -EINVAL;
	}

	if (this_adm.copp.adm_delay[port_idx][copp_idx] && perf_mode
		== LEGACY_PCM_MODE) {
		atomic_set(&this_adm.copp.adm_delay_stat[port_idx][copp_idx],
			   1);
		this_adm.copp.adm_delay[port_idx][copp_idx] = 0;
		wake_up(&this_adm.copp.adm_delay_wait[port_idx][copp_idx]);
	}

	atomic_dec(&this_adm.copp.cnt[port_idx][copp_idx]);
	if (!(atomic_read(&this_adm.copp.cnt[port_idx][copp_idx]))) {
		copp_id = adm_get_copp_id(port_idx, copp_idx);
		pr_debug("%s: Closing ADM port_idx:%d copp_idx:%d copp_id:0x%x\n",
			 __func__, port_idx, copp_idx, copp_id);

		close.hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
						APR_HDR_LEN(APR_HDR_SIZE),
						APR_PKT_VER);
		close.pkt_size = sizeof(close);
		close.src_svc = APR_SVC_ADM;
		close.src_domain = APR_DOMAIN_APPS;
		close.src_port = port_id;
		close.dest_svc = APR_SVC_ADM;
		close.dest_domain = APR_DOMAIN_ADSP;
		close.dest_port = copp_id;
		close.token = port_idx << 16 | copp_idx;
		close.opcode = ADM_CMD_DEVICE_CLOSE_V5;

		atomic_set(&this_adm.copp.id[port_idx][copp_idx],
			   RESET_COPP_ID);
		atomic_set(&this_adm.copp.cnt[port_idx][copp_idx], 0);
		atomic_set(&this_adm.copp.topology[port_idx][copp_idx], 0);
		atomic_set(&this_adm.copp.mode[port_idx][copp_idx], 0);
		atomic_set(&this_adm.copp.stat[port_idx][copp_idx], -1);
		atomic_set(&this_adm.copp.rate[port_idx][copp_idx], 0);
		atomic_set(&this_adm.copp.channels[port_idx][copp_idx], 0);
		atomic_set(&this_adm.copp.bit_width[port_idx][copp_idx], 0);
		atomic_set(&this_adm.copp.app_type[port_idx][copp_idx], 0);

		clear_bit(ADM_STATUS_CALIBRATION_REQUIRED,
			(void *)&this_adm.copp.adm_status[port_idx][copp_idx]);

		ret = apr_send_pkt(this_adm.apr, (uint32_t *)&close);
		if (ret < 0) {
			pr_err("%s: ADM close failed %d\n", __func__, ret);
			return -EINVAL;
		}

		ret = wait_event_timeout(this_adm.copp.wait[port_idx][copp_idx],
			atomic_read(&this_adm.copp.stat
			[port_idx][copp_idx]) >= 0,
			msecs_to_jiffies(TIMEOUT_MS));
		if (!ret) {
			pr_err("%s: ADM cmd Route timedout for port 0x%x\n",
				__func__, port_id);
			return -EINVAL;
		} else if (atomic_read(&this_adm.copp.stat
					[port_idx][copp_idx]) > 0) {
			pr_err("%s: DSP returned error[%s]\n",
				__func__, adsp_err_get_err_str(
				atomic_read(&this_adm.copp.stat
				[port_idx][copp_idx])));
			return adsp_err_get_lnx_err_code(
					atomic_read(&this_adm.copp.stat
						[port_idx][copp_idx]));
		}
	}

	return 0;
}

static int q6adm_probe(struct platform_device *pdev)
{
	int i = 0, j, ret;
	this_adm.apr = NULL;
	this_adm.ec_ref_rx = -1;
	atomic_set(&this_adm.matrix_map_stat, 0);
	init_waitqueue_head(&this_adm.matrix_map_wait);
	atomic_set(&this_adm.adm_stat, 0);
	init_waitqueue_head(&this_adm.adm_wait);

	for (i = 0; i < AFE_MAX_PORTS; i++) {
		for (j = 0; j < MAX_COPPS_PER_PORT; j++) {
			atomic_set(&this_adm.copp.id[i][j], RESET_COPP_ID);
			atomic_set(&this_adm.copp.cnt[i][j], 0);
			atomic_set(&this_adm.copp.topology[i][j], 0);
			atomic_set(&this_adm.copp.mode[i][j], 0);
			atomic_set(&this_adm.copp.stat[i][j], 0);
			atomic_set(&this_adm.copp.rate[i][j], 0);
			atomic_set(&this_adm.copp.channels[i][j], 0);
			atomic_set(&this_adm.copp.bit_width[i][j], 0);
			atomic_set(&this_adm.copp.app_type[i][j], 0);
			atomic_set(&this_adm.copp.acdb_id[i][j], 0);
			init_waitqueue_head(&this_adm.copp.wait[i][j]);
			atomic_set(&this_adm.copp.adm_delay_stat[i][j], 0);
			init_waitqueue_head(
				&this_adm.copp.adm_delay_wait[i][j]);
			atomic_set(&this_adm.copp.topology[i][j], 0);
			this_adm.copp.adm_delay[i][j] = 0;
			this_adm.copp.adm_status[i][j] =
				ADM_STATUS_CALIBRATION_REQUIRED;
		}
	}

	this_adm.apr = apr_register(&pdev->dev, "ADSP", "ADM", adm_callback,
					0xFFFFFFFF, &this_adm);
	if (this_adm.apr == NULL) {
		pr_err("%s: Unable to register ADM\n", __func__);
		ret = -ENODEV;
		return ret;
	}

	return 0;
}

static int qcom_q6adm_exit(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id qcom_q6adm_match[] = {
	{ .compatible = "qcom,q6adm",},
	{ }
};

static struct platform_driver qcom_q6adm_driver = {
	.probe = q6adm_probe,
	.remove = qcom_q6adm_exit,
	.driver = {
		.name = "qcom-q6adm",
		.of_match_table = qcom_q6adm_match,
	},
};
module_platform_driver(qcom_q6adm_driver);
