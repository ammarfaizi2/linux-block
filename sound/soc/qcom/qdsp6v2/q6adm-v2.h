/* Copyright (c) 2012-2015, The Linux Foundation. All rights reserved.
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
#ifndef __Q6_ADM_V2_H__
#define __Q6_ADM_V2_H__


#define ADM_PATH_PLAYBACK 0x1
#define ADM_PATH_LIVE_REC 0x2
#define ADM_PATH_NONLIVE_REC 0x3
#define ADM_PATH_COMPRESSED_RX 0x5

#define MAX_MODULES_IN_TOPO 16
#define ADM_GET_TOPO_MODULE_LIST_LENGTH\
		((MAX_MODULES_IN_TOPO + 1) * sizeof(uint32_t))
#define AUD_PROC_BLOCK_SIZE	4096
#define AUD_VOL_BLOCK_SIZE	4096
#define AUDIO_RX_CALIBRATION_SIZE	(AUD_PROC_BLOCK_SIZE + \
						AUD_VOL_BLOCK_SIZE)
enum {
	ADM_CUSTOM_TOP_CAL = 0,
	ADM_AUDPROC_CAL,
	ADM_AUDVOL_CAL,
	ADM_RTAC_INFO_CAL,
	ADM_RTAC_APR_CAL,
	ADM_DTS_EAGLE,
	ADM_SRS_TRUMEDIA,
	ADM_RTAC_AUDVOL_CAL,
	ADM_MAX_CAL_TYPES
};

enum {
	ADM_CLIENT_ID_DEFAULT = 0,
	ADM_CLIENT_ID_SOURCE_TRACKING,
	ADM_CLIENT_ID_MAX,
};

#define MAX_COPPS_PER_PORT 0x8
#define ADM_MAX_CHANNELS 8
#define PCM_FORMAT_MAX_NUM_CHANNEL  8

#define NULL_COPP_TOPOLOGY				0x00010312
#define DEFAULT_COPP_TOPOLOGY				0x00010314

/* multiple copp per stream. */
struct route_payload {
	unsigned int copp_idx[MAX_COPPS_PER_PORT];
	unsigned short num_copps;
	unsigned int session_id;


	unsigned int port_id[MAX_COPPS_PER_PORT];
	int app_type;
	int acdb_dev_id;
	int sample_rate;
};

int adm_open(int port, int path, int rate, int mode, int topology,
			   int perf_mode, uint16_t bits_per_sample,
			   int app_type, int acdbdev_id);

int adm_close(int port, int topology, int perf_mode);

int adm_matrix_map(int path, struct route_payload payload_map,
		   int perf_mode);

int adm_connect_afe_port(int mode, int session_id, int port_id);


#endif /* __Q6_ADM_V2_H__ */
