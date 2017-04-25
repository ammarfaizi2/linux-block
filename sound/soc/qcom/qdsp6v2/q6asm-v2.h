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
#ifndef __Q6_ASM_V2_H__
#define __Q6_ASM_V2_H__

#include <linux/soc/qcom/apr.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#define IN                      0x000
#define OUT                     0x001
#define CH_MODE_MONO            0x001
#define CH_MODE_STEREO          0x002

#define FORMAT_LINEAR_PCM   0x0000
#define FORMAT_DTMF         0x0001
#define FORMAT_ADPCM	    0x0002
#define FORMAT_YADPCM       0x0003
#define FORMAT_MP3          0x0004
#define FORMAT_MPEG4_AAC    0x0005
#define FORMAT_AMRNB	    0x0006
#define FORMAT_AMRWB	    0x0007
#define FORMAT_V13K	    0x0008
#define FORMAT_EVRC	    0x0009
#define FORMAT_EVRCB	    0x000a
#define FORMAT_EVRCWB	    0x000b
#define FORMAT_MIDI	    0x000c
#define FORMAT_SBC	    0x000d
#define FORMAT_WMA_V10PRO   0x000e
#define FORMAT_WMA_V9	    0x000f
#define FORMAT_AMR_WB_PLUS  0x0010
#define FORMAT_MPEG4_MULTI_AAC 0x0011
#define FORMAT_MULTI_CHANNEL_LINEAR_PCM 0x0012
#define FORMAT_AC3          0x0013
#define FORMAT_EAC3         0x0014
#define FORMAT_MP2          0x0015
#define FORMAT_FLAC         0x0016
#define FORMAT_ALAC         0x0017
#define FORMAT_VORBIS       0x0018
#define FORMAT_APE          0x0019

#define ENCDEC_SBCBITRATE   0x0001
#define ENCDEC_IMMEDIATE_DECODE 0x0002
#define ENCDEC_CFG_BLK          0x0003

#define CMD_PAUSE          0x0001
#define CMD_FLUSH          0x0002
#define CMD_EOS            0x0003
#define CMD_CLOSE          0x0004
#define CMD_OUT_FLUSH      0x0005
#define CMD_SUSPEND        0x0006

/* bit 0:1 represents priority of stream */
#define STREAM_PRIORITY_NORMAL	0x0000
#define STREAM_PRIORITY_LOW	0x0001
#define STREAM_PRIORITY_HIGH	0x0002

/* bit 4 represents META enable of encoded data buffer */
#define BUFFER_META_ENABLE	0x0010

/* Enable Sample_Rate/Channel_Mode notification event from Decoder */
#define SR_CM_NOTIFY_ENABLE	0x0004

#define TUN_WRITE_IO_MODE 0x0008 /* tunnel read write mode */
#define TUN_READ_IO_MODE  0x0004 /* tunnel read write mode */
#define SYNC_IO_MODE	0x0001
#define ASYNC_IO_MODE	0x0002
#define COMPRESSED_IO	0x0040
#define COMPRESSED_STREAM_IO	0x0080
#define NT_MODE        0x0400

#define NO_TIMESTAMP    0xFF00
#define SET_TIMESTAMP   0x0000

#define SOFT_PAUSE_ENABLE	1
#define SOFT_PAUSE_DISABLE	0

#define SESSION_MAX		0x08
#define ASM_CONTROL_SESSION	0x0F

#define ASM_SHIFT_GAPLESS_MODE_FLAG	31
#define ASM_SHIFT_LAST_BUFFER_FLAG	30

/* payload structure bytes */
#define READDONE_IDX_STATUS 0
#define READDONE_IDX_BUFADD_LSW 1
#define READDONE_IDX_BUFADD_MSW 2
#define READDONE_IDX_MEMMAP_HDL 3
#define READDONE_IDX_SIZE 4
#define READDONE_IDX_OFFSET 5
#define READDONE_IDX_LSW_TS 6
#define READDONE_IDX_MSW_TS 7
#define READDONE_IDX_FLAGS 8
#define READDONE_IDX_NUMFRAMES 9
#define READDONE_IDX_SEQ_ID 10

#define SOFT_PAUSE_PERIOD       30   /* ramp up/down for 30ms    */
#define SOFT_PAUSE_STEP         0 /* Step value 0ms or 0us */
enum {
	SOFT_PAUSE_CURVE_LINEAR = 0,
	SOFT_PAUSE_CURVE_EXP,
	SOFT_PAUSE_CURVE_LOG,
};

#define SOFT_VOLUME_PERIOD       30   /* ramp up/down for 30ms    */
#define SOFT_VOLUME_STEP         0 /* Step value 0ms or 0us */
enum {
	SOFT_VOLUME_CURVE_LINEAR = 0,
	SOFT_VOLUME_CURVE_EXP,
	SOFT_VOLUME_CURVE_LOG,
};

#define SOFT_VOLUME_INSTANCE_1	1
#define SOFT_VOLUME_INSTANCE_2	2

/* make sure this matches with msm_audio_calibration */
#define SP_V2_NUM_MAX_SPKR 2

/* Allows a client to connect the desired stream to
 * the desired AFE port through the stream router
 *
 * This command allows the client to connect specified session to
 * specified AFE port. This is used for compressed streams only
 * opened using the #ASM_STREAM_CMD_OPEN_WRITE_COMPRESSED or
 * #ASM_STREAM_CMD_OPEN_READ_COMPRESSED command.
 *
 * @prerequisites
 * Session ID and AFE Port ID must be valid.
 * #ASM_STREAM_CMD_OPEN_WRITE_COMPRESSED or
 * #ASM_STREAM_CMD_OPEN_READ_COMPRESSED
 * must have been called on this session.
 */

#define ADSP_MEMORY_MAP_SHMEM8_4K_POOL      3
/*
* Definition of virtual memory flag
*/
#define ADSP_MEMORY_MAP_VIRTUAL_MEMORY 1

#define DEFAULT_POPP_TOPOLOGY				0x00010BE4

struct avs_cmd_shared_mem_map_regions {
	struct apr_hdr hdr;
	u16                  mem_pool_id;
/* Type of memory on which this memory region is mapped.
 *
 * Supported values: - #ADSP_MEMORY_MAP_EBI_POOL -
 * #ADSP_MEMORY_MAP_SMI_POOL - #ADSP_MEMORY_MAP_IMEM_POOL
 * (unsupported) - #ADSP_MEMORY_MAP_SHMEM8_4K_POOL - Other values
 * are reserved
 *
 * The memory ID implicitly defines the characteristics of the
 * memory. Characteristics may include alignment type, permissions,
 * etc.
 *
 * SHMEM8_4K is shared memory, byte addressable, and 4 KB aligned.
 */

	u16                  num_regions;
	/* Number of regions to map.*/

	u32                  property_flag;
/* Configures one common property for all the regions in the
 * payload. No two regions in the same memory map regions cmd can
 * have differnt property. Supported values: - 0x00000000 to
 * 0x00000001
 *
 * b0 - bit 0 indicates physical or virtual mapping 0 shared memory
 * address provided in avs_shared_map_regions_payload is physical
 * address. The shared memory needs to be mapped( hardware TLB
 * entry)
 *
 * and a software entry needs to be added for internal book keeping.
 *
 * 1 Shared memory address provided in MayPayload[usRegions] is
 * virtual address. The shared memory must not be mapped (since
 * hardware TLB entry is already available) but a software entry
 * needs to be added for internal book keeping. This can be useful
 * if two services with in ADSP is communicating via APR. They can
 * now directly communicate via the Virtual address instead of
 * Physical address. The virtual regions must be contiguous.
 *
 * b31-b1 - reserved bits. must be set to zero
 */

} __packed;

struct avs_shared_map_region_payload {
	u32                  shm_addr_lsw;
/* least significant word of shared memory address of the memory
 * region to map. It must be contiguous memory, and it must be 4 KB
 * aligned.
 */

	u32                  shm_addr_msw;
/* most significant word of shared memory address of the memory
 * region to map. For 32 bit shared memory address, this field must
 * tbe set to zero. For 36 bit shared memory address, bit31 to bit 4
 * must be set to zero
 */

	u32                  mem_size_bytes;
/* Number of bytes in the region.
 *
 * The aDSP will always map the regions as virtual contiguous
 * memory, but the memory size must be in multiples of 4 KB to avoid
 * gaps in the virtually contiguous mapped memory.
 */

} __packed;

struct avs_cmd_shared_mem_unmap_regions {
	struct apr_hdr       hdr;
	u32                  mem_map_handle;
/* memory map handle returned by ASM_CMD_SHARED_MEM_MAP_REGIONS
 * , ADM_CMD_SHARED_MEM_MAP_REGIONS, commands
 */

} __packed;

/* Memory map command response payload used by the
 * #ASM_CMDRSP_SHARED_MEM_MAP_REGIONS
 * ,#ADM_CMDRSP_SHARED_MEM_MAP_REGIONS
 */

struct avs_cmdrsp_shared_mem_map_regions {
	u32                  mem_map_handle;
/* A memory map handle encapsulating shared memory attributes is
 * returned
 */

} __packed;

#define ASM_END_POINT_DEVICE_MATRIX     0

#define ASM_MEDIA_FMT_MULTI_CHANNEL_PCM_V2 0x00010DA5

#define ASM_MEDIA_FMT_EVRCB_FS 0x00010BEF

#define ASM_MEDIA_FMT_EVRCWB_FS 0x00010BF0

#define ASM_MAX_EQ_BANDS 12

#define ASM_DATA_CMD_MEDIA_FMT_UPDATE_V2 0x00010D98

struct asm_data_cmd_media_fmt_update_v2 {
u32                    fmt_blk_size;
	/* Media format block size in bytes.*/
}  __packed;

struct asm_multi_channel_pcm_fmt_blk_v2 {
	struct apr_hdr hdr;
	struct asm_data_cmd_media_fmt_update_v2 fmt_blk;

	u16  num_channels;
	/* Number of channels. Supported values: 1 to 8 */
	u16  bits_per_sample;
/* Number of bits per sample per channel. * Supported values:
 * 16, 24 * When used for playback, the client must send 24-bit
 * samples packed in 32-bit words. The 24-bit samples must be placed
 * in the most significant 24 bits of the 32-bit word. When used for
 * recording, the aDSP sends 24-bit samples packed in 32-bit words.
 * The 24-bit samples are placed in the most significant 24 bits of
 * the 32-bit word.
 */

	u32  sample_rate;
/* Number of samples per second (in Hertz).
 * Supported values: 2000 to 48000
 */

	u16  is_signed;
	/* Flag that indicates the samples are signed (1). */

	u16  reserved;
	/* reserved field for 32 bit alignment. must be set to zero. */

	u8   channel_mapping[8];
/* Channel array of size 8.
 * Supported values:
 * - #PCM_CHANNEL_L
 * - #PCM_CHANNEL_R
 * - #PCM_CHANNEL_C
 * - #PCM_CHANNEL_LS
 * - #PCM_CHANNEL_RS
 * - #PCM_CHANNEL_LFE
 * - #PCM_CHANNEL_CS
 * - #PCM_CHANNEL_LB
 * - #PCM_CHANNEL_RB
 * - #PCM_CHANNELS
 * - #PCM_CHANNEL_CVH
 * - #PCM_CHANNEL_MS
 * - #PCM_CHANNEL_FLC
 * - #PCM_CHANNEL_FRC
 * - #PCM_CHANNEL_RLC
 * - #PCM_CHANNEL_RRC
 *
 * Channel[i] mapping describes channel I. Each element i of the
 * array describes channel I inside the buffer where 0 @le I <
 * num_channels. An unused channel is set to zero.
 */
} __packed;

struct asm_stream_cmd_set_encdec_param {
	u32                  param_id;
	/* ID of the parameter. */

	u32                  param_size;
/* Data size of this parameter, in bytes. The size is a multiple
 * of 4 bytes.
 */

} __packed;

struct asm_enc_cfg_blk_param_v2 {
	u32                  frames_per_buf;
/* Number of encoded frames to pack into each buffer.
 *
 * @note1hang This is only guidance information for the aDSP. The
 * number of encoded frames put into each buffer (specified by the
 * client) is less than or equal to this number.
 */

	u32                  enc_cfg_blk_size;
/* Size in bytes of the encoder configuration block that follows
 * this member.
 */

} __packed;

/* @brief Multichannel PCM encoder configuration structure used
 * in the #ASM_PARAM_ID_ENCDEC_ENC_CFG_BLK_V2 command.
 */

struct asm_multi_channel_pcm_enc_cfg_v2 {
	struct apr_hdr hdr;
	struct asm_stream_cmd_set_encdec_param  encdec;
	struct asm_enc_cfg_blk_param_v2	encblk;
	uint16_t  num_channels;
/*< Number of PCM channels.
 *
 * Supported values: - 0 -- Native mode - 1 -- 8 Native mode
 * indicates that encoding must be performed with the number of
 * channels at the input.
 */

	uint16_t  bits_per_sample;
/*< Number of bits per sample per channel.
 * Supported values: 16, 24
 */

	uint32_t  sample_rate;
/*< Number of samples per second (in Hertz).
 *
 * Supported values: 0, 8000 to 48000 A value of 0 indicates the
 * native sampling rate. Encoding is performed at the input sampling
 * rate.
 */

	uint16_t  is_signed;
/*< Specifies whether the samples are signed (1). Currently,
 * only signed samples are supported.
 */

	uint16_t  reserved;
/*< reserved field for 32 bit alignment. must be set to zero.*/

	uint8_t   channel_mapping[8];
} __packed;

#define ASM_MEDIA_FMT_MP3 0x00010BE9
#define ASM_MEDIA_FMT_AAC_V2 0x00010DA6

/* @xreflabel
 * {hdr:AsmMediaFmtDolbyAac} Media format ID for the
 * Dolby AAC decoder. This format ID is be used if the client wants
 * to use the Dolby AAC decoder to decode MPEG2 and MPEG4 AAC
 * contents.
 */

#define ASM_MEDIA_FMT_AMRNB_FS                  0x00010BEB

/* Enumeration for 4.75 kbps AMR-NB Encoding mode. */
#define ASM_MEDIA_FMT_AMRNB_FS_ENCODE_MODE_MR475                0

/* Enumeration for 5.15 kbps AMR-NB Encoding mode. */
#define ASM_MEDIA_FMT_AMRNB_FS_ENCODE_MODE_MR515                1

/* Enumeration for 5.90 kbps AMR-NB Encoding mode. */
#define ASM_MEDIA_FMT_AMRNB_FS_ENCODE_MODE_MMR59                2

/* Enumeration for 6.70 kbps AMR-NB Encoding mode. */
#define ASM_MEDIA_FMT_AMRNB_FS_ENCODE_MODE_MMR67                3

/* Enumeration for 7.40 kbps AMR-NB Encoding mode. */
#define ASM_MEDIA_FMT_AMRNB_FS_ENCODE_MODE_MMR74                4

/* Enumeration for 7.95 kbps AMR-NB Encoding mode. */
#define ASM_MEDIA_FMT_AMRNB_FS_ENCODE_MODE_MMR795               5

/* Enumeration for 10.20 kbps AMR-NB Encoding mode. */
#define ASM_MEDIA_FMT_AMRNB_FS_ENCODE_MODE_MMR102               6

/* Enumeration for 12.20 kbps AMR-NB Encoding mode. */
#define ASM_MEDIA_FMT_AMRNB_FS_ENCODE_MODE_MMR122               7

/* Enumeration for AMR-NB Discontinuous Transmission mode off. */
#define ASM_MEDIA_FMT_AMRNB_FS_DTX_MODE_OFF                     0

/* Enumeration for AMR-NB DTX mode VAD1. */
#define ASM_MEDIA_FMT_AMRNB_FS_DTX_MODE_VAD1                    1

/* Enumeration for AMR-NB DTX mode VAD2. */
#define ASM_MEDIA_FMT_AMRNB_FS_DTX_MODE_VAD2                    2

/* Enumeration for AMR-NB DTX mode auto.
	*/
#define ASM_MEDIA_FMT_AMRNB_FS_DTX_MODE_AUTO                    3

#define ASM_MEDIA_FMT_AMRWB_FS                  0x00010BEC

/* Enumeration for 6.6 kbps AMR-WB Encoding mode. */
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR66                 0

/* Enumeration for 8.85 kbps AMR-WB Encoding mode. */
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR885                1

/* Enumeration for 12.65 kbps AMR-WB Encoding mode. */
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR1265               2

/* Enumeration for 14.25 kbps AMR-WB Encoding mode. */
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR1425               3

/* Enumeration for 15.85 kbps AMR-WB Encoding mode. */
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR1585               4

/* Enumeration for 18.25 kbps AMR-WB Encoding mode. */
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR1825               5

/* Enumeration for 19.85 kbps AMR-WB Encoding mode. */
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR1985               6

/* Enumeration for 23.05 kbps AMR-WB Encoding mode. */
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR2305               7

/* Enumeration for 23.85 kbps AMR-WB Encoding mode.
	*/
#define ASM_MEDIA_FMT_AMRWB_FS_ENCODE_MODE_MR2385               8


#define ASM_MEDIA_FMT_V13K_FS                      0x00010BED

/* Enumeration for 14.4 kbps V13K Encoding mode. */
#define ASM_MEDIA_FMT_V13K_FS_ENCODE_MODE_MR1440                0

/* Enumeration for 12.2 kbps V13K Encoding mode. */
#define ASM_MEDIA_FMT_V13K_FS_ENCODE_MODE_MR1220                1

/* Enumeration for 11.2 kbps V13K Encoding mode. */
#define ASM_MEDIA_FMT_V13K_FS_ENCODE_MODE_MR1120                2

/* Enumeration for 9.0 kbps V13K Encoding mode. */
#define ASM_MEDIA_FMT_V13K_FS_ENCODE_MODE_MR90                  3

/* Enumeration for 7.2 kbps V13K eEncoding mode. */
#define ASM_MEDIA_FMT_V13K_FS_ENCODE_MODE_MR720                 4

/* Enumeration for 1/8 vocoder rate.*/
#define ASM_MEDIA_FMT_VOC_ONE_EIGHTH_RATE          1

/* Enumeration for 1/4 vocoder rate. */
#define ASM_MEDIA_FMT_VOC_ONE_FOURTH_RATE       2

/* Enumeration for 1/2 vocoder rate. */
#define ASM_MEDIA_FMT_VOC_HALF_RATE             3

/* Enumeration for full vocoder rate.
	*/
#define ASM_MEDIA_FMT_VOC_FULL_RATE             4


#define ASM_MEDIA_FMT_EVRC_FS                   0x00010BEE


#define ASM_MEDIA_FMT_WMA_V10PRO_V2                0x00010DA7


#define ASM_MEDIA_FMT_WMA_V9_V2                    0x00010DA8

#define ASM_MEDIA_FMT_WMA_V8                    0x00010D91

#define ASM_MEDIA_FMT_AMR_WB_PLUS_V2               0x00010DA9

#define ASM_MEDIA_FMT_AC3			0x00010DEE
#define ASM_MEDIA_FMT_EAC3			0x00010DEF
#define ASM_MEDIA_FMT_DTS                    0x00010D88
#define ASM_MEDIA_FMT_MP2                    0x00010DE9
#define ASM_MEDIA_FMT_FLAC                   0x00010C16
#define ASM_MEDIA_FMT_ALAC                   0x00012F31
#define ASM_MEDIA_FMT_VORBIS                 0x00010C15
#define ASM_MEDIA_FMT_APE                    0x00012F32

/* Media format ID for adaptive transform acoustic coding. This
 * ID is used by the #ASM_STREAM_CMD_OPEN_WRITE_COMPRESSED command
 * only.
 */

#define ASM_MEDIA_FMT_ATRAC                  0x00010D89

/* Media format ID for metadata-enhanced audio transmission.
 * This ID is used by the #ASM_STREAM_CMD_OPEN_WRITE_COMPRESSED
 * command only.
 */

#define ASM_MEDIA_FMT_MAT                    0x00010D8A

/*  adsp_media_fmt.h */

#define ASM_DATA_CMD_WRITE_V2 0x00010DAB

struct asm_data_cmd_write_v2 {
	struct apr_hdr hdr;
	u32                  buf_addr_lsw;
/* The 64 bit address msw-lsw should be a valid, mapped address.
 * 64 bit address should be a multiple of 32 bytes
 */

	u32                  buf_addr_msw;
/* The 64 bit address msw-lsw should be a valid, mapped address.
 * 64 bit address should be a multiple of 32 bytes.
 * -Address of the buffer containing the data to be decoded.
 * The buffer should be aligned to a 32 byte boundary.
 * -In the case of 32 bit Shared memory address, msw field must
 * -be set to zero.
 * -In the case of 36 bit shared memory address, bit 31 to bit 4
 * -of msw must be set to zero.
 */
	u32                  mem_map_handle;
/* memory map handle returned by DSP through
 * ASM_CMD_SHARED_MEM_MAP_REGIONS command
 */
	u32                  buf_size;
/* Number of valid bytes available in the buffer for decoding. The
 * first byte starts at buf_addr.
 */

	u32                  seq_id;
	/* Optional buffer sequence ID. */

	u32                  timestamp_lsw;
/* Lower 32 bits of the 64-bit session time in microseconds of the
 * first buffer sample.
 */

	u32                  timestamp_msw;
/* Upper 32 bits of the 64-bit session time in microseconds of the
 * first buffer sample.
 */

	u32                  flags;
/* Bitfield of flags.
 * Supported values for bit 31:
 * - 1 -- Valid timestamp.
 * - 0 -- Invalid timestamp.
 * - Use #ASM_BIT_MASKIMESTAMP_VALID_FLAG as the bitmask and
 * #ASM_SHIFTIMESTAMP_VALID_FLAG as the shift value to set this bit.
 * Supported values for bit 30:
 * - 1 -- Last buffer.
 * - 0 -- Not the last buffer.
 *
 * Supported values for bit 29:
 * - 1 -- Continue the timestamp from the previous buffer.
 * - 0 -- Timestamp of the current buffer is not related
 * to the timestamp of the previous buffer.
 * - Use #ASM_BIT_MASKS_CONTINUE_FLAG and #ASM_SHIFTS_CONTINUE_FLAG
 * to set this bit.
 *
 * Supported values for bit 4:
 * - 1 -- End of the frame.
 * - 0 -- Not the end of frame, or this information is not known.
 * - Use #ASM_BIT_MASK_EOF_FLAG as the bitmask and #ASM_SHIFT_EOF_FLAG
 * as the shift value to set this bit.
 *
 * All other bits are reserved and must be set to 0.
 *
 * If bit 31=0 and bit 29=1: The timestamp of the first sample in
 * this buffer continues from the timestamp of the last sample in
 * the previous buffer. If there is no previous buffer (i.e., this
 * is the first buffer sent after opening the stream or after a
 * flush operation), or if the previous buffer does not have a valid
 * timestamp, the samples in the current buffer also do not have a
 * valid timestamp. They are played out as soon as possible.
 *
 *
 * If bit 31=0 and bit 29=0: No timestamp is associated with the
 * first sample in this buffer. The samples are played out as soon
 * as possible.
 *
 *
 * If bit 31=1 and bit 29 is ignored: The timestamp specified in
 * this payload is honored.
 *
 *
 * If bit 30=0: Not the last buffer in the stream. This is useful
 * in removing trailing samples.
 *
 *
 * For bit 4: The client can set this flag for every buffer sent in
 * which the last byte is the end of a frame. If this flag is set,
 * the buffer can contain data from multiple frames, but it should
 * always end at a frame boundary. Restrictions allow the aDSP to
 * detect an end of frame without requiring additional processing.
 */

} __packed;

#define ASM_DATA_CMD_READ_V2 0x00010DAC

struct asm_data_cmd_read_v2 {
	struct apr_hdr       hdr;
	u32                  buf_addr_lsw;
/* the 64 bit address msw-lsw should be a valid mapped address
 * and should be a multiple of 32 bytes
 */

	u32                  buf_addr_msw;
/* the 64 bit address msw-lsw should be a valid mapped address
 * and should be a multiple of 32 bytes.
* - Address of the buffer where the DSP puts the encoded data,
* potentially, at an offset specified by the uOffset field in
* ASM_DATA_EVENT_READ_DONE structure. The buffer should be aligned
* to a 32 byte boundary.
*- In the case of 32 bit Shared memory address, msw field must
*- be set to zero.
*- In the case of 36 bit shared memory address, bit 31 to bit
*- 4 of msw must be set to zero.
*/
	u32                  mem_map_handle;
/* memory map handle returned by DSP through
 * ASM_CMD_SHARED_MEM_MAP_REGIONS command.
 */

	u32                  buf_size;
/* Number of bytes available for the aDSP to write. The aDSP
 * starts writing from buf_addr.
 */

	u32                  seq_id;
	/* Optional buffer sequence ID.
			*/
} __packed;

#define ASM_DATA_CMD_EOS               0x00010BDB
#define ASM_DATA_EVENT_RENDERED_EOS    0x00010C1C
#define ASM_DATA_EVENT_EOS             0x00010BDD

#define ASM_DATA_EVENT_WRITE_DONE_V2 0x00010D99
struct asm_data_event_write_done_v2 {
	u32                  buf_addr_lsw;
	/* lsw of the 64 bit address */
	u32                  buf_addr_msw;
	/* msw of the 64 bit address. address given by the client in
	* ASM_DATA_CMD_WRITE_V2 command.
	*/
	u32                  mem_map_handle;
	/* memory map handle in the ASM_DATA_CMD_WRITE_V2  */

	u32                  status;
/* Status message (error code) that indicates whether the
 * referenced buffer has been successfully consumed.
 * Supported values: Refer to @xhyperref{Q3,[Q3]}
 */
} __packed;

#define ASM_DATA_EVENT_READ_DONE_V2 0x00010D9A

/* Definition of the frame metadata flag bitmask.*/
#define ASM_BIT_MASK_FRAME_METADATA_FLAG (0x40000000UL)

/* Definition of the frame metadata flag shift value. */
#define ASM_SHIFT_FRAME_METADATA_FLAG 30

struct asm_data_event_read_done_v2 {
	u32                  status;
/* Status message (error code).
 * Supported values: Refer to @xhyperref{Q3,[Q3]}
 */

u32                  buf_addr_lsw;
/* 64 bit address msw-lsw is a valid, mapped address. 64 bit
 * address is a multiple of 32 bytes.
 */

u32                  buf_addr_msw;
/* 64 bit address msw-lsw is a valid, mapped address. 64 bit
* address is a multiple of 32 bytes.
*
* -Same address provided by the client in ASM_DATA_CMD_READ_V2
* -In the case of 32 bit Shared memory address, msw field is set to
* zero.
* -In the case of 36 bit shared memory address, bit 31 to bit 4
* -of msw is set to zero.
*/

u32                  mem_map_handle;
/* memory map handle in the ASM_DATA_CMD_READ_V2  */

u32                  enc_framesotal_size;
/* Total size of the encoded frames in bytes.
 * Supported values: >0
 */

u32                  offset;
/* Offset (from buf_addr) to the first byte of the first encoded
 * frame. All encoded frames are consecutive, starting from this
 * offset.
 * Supported values: > 0
 */

u32                  timestamp_lsw;
/* Lower 32 bits of the 64-bit session time in microseconds of
 * the first sample in the buffer. If Bit 5 of mode_flags flag of
 * ASM_STREAM_CMD_OPEN_READ_V2 is 1 then the 64 bit timestamp is
 * absolute capture time otherwise it is relative session time. The
 * absolute timestamp doesnt reset unless the system is reset.
 */

u32                  timestamp_msw;
/* Upper 32 bits of the 64-bit session time in microseconds of
 * the first sample in the buffer.
 */

u32                  flags;
/* Bitfield of flags. Bit 30 indicates whether frame metadata is
 * present. If frame metadata is present, num_frames consecutive
 * instances of @xhyperref{hdr:FrameMetaData,Frame metadata} start
 * at the buffer address.
 * Supported values for bit 31:
 * - 1 -- Timestamp is valid.
 * - 0 -- Timestamp is invalid.
 * - Use #ASM_BIT_MASKIMESTAMP_VALID_FLAG and
 * #ASM_SHIFTIMESTAMP_VALID_FLAG to set this bit.
 *
 * Supported values for bit 30:
 * - 1 -- Frame metadata is present.
 * - 0 -- Frame metadata is absent.
 * - Use #ASM_BIT_MASK_FRAME_METADATA_FLAG and
 * #ASM_SHIFT_FRAME_METADATA_FLAG to set this bit.
 *
 * All other bits are reserved; the aDSP sets them to 0.
 */

u32                  num_frames;
/* Number of encoded frames in the buffer. */

u32                  seq_id;
/* Optional buffer sequence ID.	*/
} __packed;

struct asm_data_read_buf_metadata_v2 {
	u32          offset;
/* Offset from buf_addr in #ASM_DATA_EVENT_READ_DONE_PAYLOAD to
 * the frame associated with this metadata.
 * Supported values: > 0
 */

u32          frm_size;
/* Size of the encoded frame in bytes.
 * Supported values: > 0
 */

u32          num_encoded_pcm_samples;
/* Number of encoded PCM samples (per channel) in the frame
 * associated with this metadata.
 * Supported values: > 0
 */

u32          timestamp_lsw;
/* Lower 32 bits of the 64-bit session time in microseconds of the
 * first sample for this frame.
 * If Bit 5 of mode_flags flag of ASM_STREAM_CMD_OPEN_READ_V2 is 1
 * then the 64 bit timestamp is absolute capture time otherwise it
 * is relative session time. The absolute timestamp doesnt reset
 * unless the system is reset.
 */

u32          timestamp_msw;
/* Lower 32 bits of the 64-bit session time in microseconds of the
 * first sample for this frame.
 */

u32          flags;
/* Frame flags.
 * Supported values for bit 31:
 * - 1 -- Time stamp is valid
 * - 0 -- Time stamp is not valid
 * - All other bits are reserved; the aDSP sets them to 0.
*/
} __packed;

/* Notifies the client of a change in the data sampling rate or
 * Channel mode. This event is raised by the decoder service. The
 * event is enabled through the mode flags of
 * #ASM_STREAM_CMD_OPEN_WRITE_V2 or
 * #ASM_STREAM_CMD_OPEN_READWRITE_V2. - The decoder detects a change
 * in the output sampling frequency or the number/positioning of
 * output channels, or if it is the first frame decoded.The new
 * sampling frequency or the new channel configuration is
 * communicated back to the client asynchronously.
 */

#define ASM_DATA_EVENT_SR_CM_CHANGE_NOTIFY 0x00010C65

/*  Payload of the #ASM_DATA_EVENT_SR_CM_CHANGE_NOTIFY event.
 * This event is raised when the following conditions are both true:
 * - The event is enabled through the mode_flags of
 * #ASM_STREAM_CMD_OPEN_WRITE_V2 or
 * #ASM_STREAM_CMD_OPEN_READWRITE_V2. - The decoder detects a change
 * in either the output sampling frequency or the number/positioning
 * of output channels, or if it is the first frame decoded.
 * This event is not raised (even if enabled) if the decoder is
 * MIDI, because
 */

struct asm_data_event_sr_cm_change_notify {
	u32                  sample_rate;
/* New sampling rate (in Hertz) after detecting a change in the
 * bitstream.
 * Supported values: 2000 to 48000
 */

	u16                  num_channels;
/* New number of channels after detecting a change in the
 * bitstream.
 * Supported values: 1 to 8
 */

	u16                  reserved;
	/* Reserved for future use. This field must be set to 0.*/

	u8                   channel_mapping[8];

} __packed;

/* Notifies the client of a data sampling rate or channel mode
 * change. This event is raised by the encoder service.
 * This event is raised when :
 * - Native mode encoding was requested in the encoder
 * configuration (i.e., the channel number was 0), the sample rate
 * was 0, or both were 0.
 *
 * - The input data frame at the encoder is the first one, or the
 * sampling rate/channel mode is different from the previous input
 * data frame.
 *
 */
#define ASM_DATA_EVENT_ENC_SR_CM_CHANGE_NOTIFY 0x00010BDE

#define ASM_DATA_CMD_IEC_60958_FRAME_RATE 0x00010D87

/* Payload of the #ASM_DATA_CMD_IEC_60958_FRAME_RATE command,
 * which is used to indicate the IEC 60958 frame rate of a given
 * packetized audio stream.
 */
/* adsp_asm_data_commands.h*/
/* Definition of the stream ID bitmask.*/
#define ASM_BIT_MASK_STREAM_ID                 (0x000000FFUL)

/* Definition of the stream ID shift value.*/
#define ASM_SHIFT_STREAM_ID                    0

/* Definition of the session ID bitmask.*/
#define ASM_BIT_MASK_SESSION_ID                (0x0000FF00UL)

/* Definition of the session ID shift value.*/
#define ASM_SHIFT_SESSION_ID                   8

/* Definition of the service ID bitmask.*/
#define ASM_BIT_MASK_SERVICE_ID                (0x00FF0000UL)

/* Definition of the service ID shift value.*/
#define ASM_SHIFT_SERVICE_ID                   16

/* Definition of the domain ID bitmask.*/
#define ASM_BIT_MASK_DOMAIN_ID                (0xFF000000UL)

/* Definition of the domain ID shift value.*/
#define ASM_SHIFT_DOMAIN_ID                    24

#define ASM_CMD_SHARED_MEM_MAP_REGIONS               0x00010D92
#define ASM_CMDRSP_SHARED_MEM_MAP_REGIONS     0x00010D93
#define ASM_CMD_SHARED_MEM_UNMAP_REGIONS              0x00010D94

/* adsp_asm_service_commands.h */

#define ASM_MAX_SESSION_ID  (15)

/* Maximum number of sessions.*/
#define ASM_MAX_NUM_SESSIONS                ASM_MAX_SESSION_ID

/* Maximum number of streams per session.*/
#define ASM_MAX_STREAMS_PER_SESSION (8)
#define ASM_SESSION_CMD_RUN_V2                   0x00010DAA
#define ASM_SESSION_CMD_RUN_STARTIME_RUN_IMMEDIATE  0
#define ASM_SESSION_CMD_RUN_STARTIME_RUN_AT_ABSOLUTEIME 1
#define ASM_SESSION_CMD_RUN_STARTIME_RUN_AT_RELATIVEIME 2
#define ASM_SESSION_CMD_RUN_STARTIME_RUN_WITH_DELAY     3

#define ASM_BIT_MASK_RUN_STARTIME                 (0x00000003UL)

/* Bit shift value used to specify the start time for the
 * ASM_SESSION_CMD_RUN_V2 command.
 */
#define ASM_SHIFT_RUN_STARTIME 0
struct asm_session_cmd_run_v2 {
	struct apr_hdr hdr;
	u32                  flags;
/* Specifies whether to run immediately or at a specific
 * rendering time or with a specified delay. Run with delay is
 * useful for delaying in case of ASM loopback opened through
 * ASM_STREAM_CMD_OPEN_LOOPBACK_V2. Use #ASM_BIT_MASK_RUN_STARTIME
 * and #ASM_SHIFT_RUN_STARTIME to set this 2-bit flag.
 *
 *
 *Bits 0 and 1 can take one of four possible values:
 *
 *- #ASM_SESSION_CMD_RUN_STARTIME_RUN_IMMEDIATE
 *- #ASM_SESSION_CMD_RUN_STARTIME_RUN_AT_ABSOLUTEIME
 *- #ASM_SESSION_CMD_RUN_STARTIME_RUN_AT_RELATIVEIME
 *- #ASM_SESSION_CMD_RUN_STARTIME_RUN_WITH_DELAY
 *
 *All other bits are reserved; clients must set them to zero.
 */

	u32                  time_lsw;
/* Lower 32 bits of the time in microseconds used to align the
 * session origin time. When bits 0-1 of flags is
 * ASM_SESSION_CMD_RUN_START_RUN_WITH_DELAY, time lsw is the lsw of
 * the delay in us. For ASM_SESSION_CMD_RUN_START_RUN_WITH_DELAY,
 * maximum value of the 64 bit delay is 150 ms.
 */

	u32                  time_msw;
/* Upper 32 bits of the time in microseconds used to align the
 * session origin time. When bits 0-1 of flags is
 * ASM_SESSION_CMD_RUN_START_RUN_WITH_DELAY, time msw is the msw of
 * the delay in us. For ASM_SESSION_CMD_RUN_START_RUN_WITH_DELAY,
 * maximum value of the 64 bit delay is 150 ms.
 */

} __packed;

#define ASM_SESSION_CMD_PAUSE 0x00010BD3
#define ASM_SESSION_CMD_SUSPEND 0x00010DEC
#define ASM_SESSION_CMD_GET_SESSIONTIME_V3 0x00010D9D
#define ASM_SESSION_CMD_REGISTER_FOR_RX_UNDERFLOW_EVENTS 0x00010BD5

struct asm_session_cmd_rgstr_rx_underflow {
	struct apr_hdr hdr;
	u16                  enable_flag;
/* Specifies whether a client is to receive events when an Rx
 * session underflows.
 * Supported values:
 * - 0 -- Do not send underflow events
 * - 1 -- Send underflow events
 */
	u16                  reserved;
	/* Reserved. This field must be set to zero.*/
} __packed;

#define ASM_SESSION_CMD_REGISTER_FORX_OVERFLOW_EVENTS 0x00010BD6

struct asm_session_cmd_regx_overflow {
	struct apr_hdr hdr;
	u16                  enable_flag;
/* Specifies whether a client is to receive events when a Tx
* session overflows.
 * Supported values:
 * - 0 -- Do not send overflow events
 * - 1 -- Send overflow events
 */

	u16                  reserved;
	/* Reserved. This field must be set to zero.*/
} __packed;

#define ASM_SESSION_EVENT_RX_UNDERFLOW        0x00010C17
#define ASM_SESSION_EVENTX_OVERFLOW           0x00010C18
#define ASM_SESSION_CMDRSP_GET_SESSIONTIME_V3 0x00010D9E
#define ASM_SESSION_CMD_ADJUST_SESSION_CLOCK_V2     0x00010D9F
#define ASM_SESSION_CMDRSP_ADJUST_SESSION_CLOCK_V2    0x00010DA0
#define ASM_SESSION_CMD_GET_PATH_DELAY_V2	 0x00010DAF
#define ASM_SESSION_CMDRSP_GET_PATH_DELAY_V2 0x00010DB0

/* adsp_asm_session_command.h*/
#define ASM_STREAM_CMD_OPEN_WRITE_V3       0x00010DB3

#define ASM_LOW_LATENCY_STREAM_SESSION				0x10000000

#define ASM_ULTRA_LOW_LATENCY_STREAM_SESSION			0x20000000

#define ASM_ULL_POST_PROCESSING_STREAM_SESSION			0x40000000

#define ASM_LEGACY_STREAM_SESSION                                      0

struct asm_stream_cmd_open_write_v3 {
	struct apr_hdr			hdr;
	uint32_t                    mode_flags;
/* Mode flags that configure the stream to notify the client
 * whenever it detects an SR/CM change at the input to its POPP.
 * Supported values for bits 0 to 1:
 * - Reserved; clients must set them to zero.
 * Supported values for bit 2:
 * - 0 -- SR/CM change notification event is disabled.
 * - 1 -- SR/CM change notification event is enabled.
 * - Use #ASM_BIT_MASK_SR_CM_CHANGE_NOTIFY_FLAG and
 * #ASM_SHIFT_SR_CM_CHANGE_NOTIFY_FLAG to set or get this bit.
 *
 * Supported values for bit 31:
 * - 0 -- Stream to be opened in on-Gapless mode.
 * - 1 -- Stream to be opened in Gapless mode. In Gapless mode,
 * successive streams must be opened with same session ID but
 * different stream IDs.
 *
 * - Use #ASM_BIT_MASK_GAPLESS_MODE_FLAG and
 * #ASM_SHIFT_GAPLESS_MODE_FLAG to set or get this bit.
 *
 *
 * @note1hang MIDI and DTMF streams cannot be opened in Gapless mode.
 */

	uint16_t                    sink_endpointype;
/*< Sink point type.
 * Supported values:
 * - 0 -- Device matrix
 * - Other values are reserved.
 *
 * The device matrix is the gateway to the hardware ports.
 */

	uint16_t                    bits_per_sample;
/*< Number of bits per sample processed by ASM modules.
 * Supported values: 16 and 24 bits per sample
 */

	uint32_t                    postprocopo_id;
/*< Specifies the topology (order of processing) of
 * postprocessing algorithms. <i>None</i> means no postprocessing.
 * Supported values:
 * - #ASM_STREAM_POSTPROCOPO_ID_DEFAULT
 * - #ASM_STREAM_POSTPROCOPO_ID_MCH_PEAK_VOL
 * - #ASM_STREAM_POSTPROCOPO_ID_NONE
 *
 * This field can also be enabled through SetParams flags.
 */

	uint32_t                    dec_fmt_id;
/*< Configuration ID of the decoder media format.
 *
 * Supported values:
 * - #ASM_MEDIA_FMT_MULTI_CHANNEL_PCM_V2
 * - #ASM_MEDIA_FMT_ADPCM
 * - #ASM_MEDIA_FMT_MP3
 * - #ASM_MEDIA_FMT_AAC_V2
 * - #ASM_MEDIA_FMT_DOLBY_AAC
 * - #ASM_MEDIA_FMT_AMRNB_FS
 * - #ASM_MEDIA_FMT_AMRWB_FS
 * - #ASM_MEDIA_FMT_AMR_WB_PLUS_V2
 * - #ASM_MEDIA_FMT_V13K_FS
 * - #ASM_MEDIA_FMT_EVRC_FS
 * - #ASM_MEDIA_FMT_EVRCB_FS
 * - #ASM_MEDIA_FMT_EVRCWB_FS
 * - #ASM_MEDIA_FMT_SBC
 * - #ASM_MEDIA_FMT_WMA_V10PRO_V2
 * - #ASM_MEDIA_FMT_WMA_V9_V2
 * - #ASM_MEDIA_FMT_AC3
 * - #ASM_MEDIA_FMT_EAC3
 * - #ASM_MEDIA_FMT_G711_ALAW_FS
 * - #ASM_MEDIA_FMT_G711_MLAW_FS
 * - #ASM_MEDIA_FMT_G729A_FS
 * - #ASM_MEDIA_FMT_FR_FS
 * - #ASM_MEDIA_FMT_VORBIS
 * - #ASM_MEDIA_FMT_FLAC
 * - #ASM_MEDIA_FMT_ALAC
 * - #ASM_MEDIA_FMT_APE
 * - #ASM_MEDIA_FMT_EXAMPLE
 */
} __packed;

#define ASM_STREAM_CMD_OPEN_READ_V3                 0x00010DB4

/* Definition of the timestamp type flag bitmask */
#define ASM_BIT_MASKIMESTAMPYPE_FLAG        (0x00000020UL)

/* Definition of the timestamp type flag shift value. */
#define ASM_SHIFTIMESTAMPYPE_FLAG 5

/* Relative timestamp is identified by this value.*/
#define ASM_RELATIVEIMESTAMP      0

/* Absolute timestamp is identified by this value.*/
#define ASM_ABSOLUTEIMESTAMP      1

/* Bit value for Low Latency Tx stream subfield */
#define ASM_LOW_LATENCY_TX_STREAM_SESSION			1

/* Bit shift for the stream_perf_mode subfield. */
#define ASM_SHIFT_STREAM_PERF_MODE_FLAG_IN_OPEN_READ              29

struct asm_stream_cmd_open_read_v3 {
	struct apr_hdr hdr;
	u32                    mode_flags;
/* Mode flags that indicate whether meta information per encoded
 * frame is to be provided.
 * Supported values for bit 4:
 *
 * - 0 -- Return data buffer contains all encoded frames only; it
 * does not contain frame metadata.
 *
 * - 1 -- Return data buffer contains an array of metadata and
 * encoded frames.
 *
 * - Use #ASM_BIT_MASK_META_INFO_FLAG as the bitmask and
 * #ASM_SHIFT_META_INFO_FLAG as the shift value for this bit.
 *
 *
 * Supported values for bit 5:
 *
 * - ASM_RELATIVEIMESTAMP -- ASM_DATA_EVENT_READ_DONE_V2 will have
 * - relative time-stamp.
 * - ASM_ABSOLUTEIMESTAMP -- ASM_DATA_EVENT_READ_DONE_V2 will
 * - have absolute time-stamp.
 *
 * - Use #ASM_BIT_MASKIMESTAMPYPE_FLAG as the bitmask and
 * #ASM_SHIFTIMESTAMPYPE_FLAG as the shift value for this bit.
 *
 * All other bits are reserved; clients must set them to zero.
 */

	u32                    src_endpointype;
/* Specifies the endpoint providing the input samples.
 * Supported values:
 * - 0 -- Device matrix
 * - All other values are reserved; clients must set them to zero.
 * Otherwise, an error is returned.
 * The device matrix is the gateway from the tunneled Tx ports.
 */

	u32                    preprocopo_id;
/* Specifies the topology (order of processing) of preprocessing
 * algorithms. <i>None</i> means no preprocessing.
 * Supported values:
 * - #ASM_STREAM_PREPROCOPO_ID_DEFAULT
 * - #ASM_STREAM_PREPROCOPO_ID_NONE
 *
 * This field can also be enabled through SetParams flags.
 */

	u32                    enc_cfg_id;
/* Media configuration ID for encoded output.
 * Supported values:
 * - #ASM_MEDIA_FMT_MULTI_CHANNEL_PCM_V2
 * - #ASM_MEDIA_FMT_AAC_V2
 * - #ASM_MEDIA_FMT_AMRNB_FS
 * - #ASM_MEDIA_FMT_AMRWB_FS
 * - #ASM_MEDIA_FMT_V13K_FS
 * - #ASM_MEDIA_FMT_EVRC_FS
 * - #ASM_MEDIA_FMT_EVRCB_FS
 * - #ASM_MEDIA_FMT_EVRCWB_FS
 * - #ASM_MEDIA_FMT_SBC
 * - #ASM_MEDIA_FMT_G711_ALAW_FS
 * - #ASM_MEDIA_FMT_G711_MLAW_FS
 * - #ASM_MEDIA_FMT_G729A_FS
 * - #ASM_MEDIA_FMT_EXAMPLE
 * - #ASM_MEDIA_FMT_WMA_V8
 */

	u16                    bits_per_sample;
/* Number of bits per sample processed by ASM modules.
 * Supported values: 16 and 24 bits per sample
 */

	u16                    reserved;
/* Reserved for future use. This field must be set to zero.*/
} __packed;

#define ASM_POPP_OUTPUT_SR_NATIVE_RATE                                  0

/* Enumeration for the maximum sampling rate at the POPP output.*/
#define ASM_POPP_OUTPUT_SR_MAX_RATE             48000

#define ASM_STREAM_CMD_OPEN_READWRITE_V2        0x00010D8D
#define ASM_STREAM_CMD_OPEN_READWRITE_V2        0x00010D8D

struct asm_stream_cmd_open_readwrite_v2 {
	struct apr_hdr         hdr;
	u32                    mode_flags;
/* Mode flags.
 * Supported values for bit 2:
 * - 0 -- SR/CM change notification event is disabled.
 * - 1 -- SR/CM change notification event is enabled. Use
 * #ASM_BIT_MASK_SR_CM_CHANGE_NOTIFY_FLAG and
 * #ASM_SHIFT_SR_CM_CHANGE_NOTIFY_FLAG to set or
 * getting this flag.
 *
 * Supported values for bit 4:
 * - 0 -- Return read data buffer contains all encoded frames only; it
 * does not contain frame metadata.
 * - 1 -- Return read data buffer contains an array of metadata and
 * encoded frames.
 *
 * All other bits are reserved; clients must set them to zero.
 */

	u32                    postprocopo_id;
/* Specifies the topology (order of processing) of postprocessing
 * algorithms. <i>None</i> means no postprocessing.
 *
 * Supported values:
 * - #ASM_STREAM_POSTPROCOPO_ID_DEFAULT
 * - #ASM_STREAM_POSTPROCOPO_ID_MCH_PEAK_VOL
 * - #ASM_STREAM_POSTPROCOPO_ID_NONE
 */

	u32                    dec_fmt_id;
/* Specifies the media type of the input data. PCM indicates that
 * no decoding must be performed, e.g., this is an NT encoder
 * session.
 * Supported values:
 * - #ASM_MEDIA_FMT_MULTI_CHANNEL_PCM_V2
 * - #ASM_MEDIA_FMT_ADPCM
 * - #ASM_MEDIA_FMT_MP3
 * - #ASM_MEDIA_FMT_AAC_V2
 * - #ASM_MEDIA_FMT_DOLBY_AAC
 * - #ASM_MEDIA_FMT_AMRNB_FS
 * - #ASM_MEDIA_FMT_AMRWB_FS
 * - #ASM_MEDIA_FMT_V13K_FS
 * - #ASM_MEDIA_FMT_EVRC_FS
 * - #ASM_MEDIA_FMT_EVRCB_FS
 * - #ASM_MEDIA_FMT_EVRCWB_FS
 * - #ASM_MEDIA_FMT_SBC
 * - #ASM_MEDIA_FMT_WMA_V10PRO_V2
 * - #ASM_MEDIA_FMT_WMA_V9_V2
 * - #ASM_MEDIA_FMT_AMR_WB_PLUS_V2
 * - #ASM_MEDIA_FMT_AC3
 * - #ASM_MEDIA_FMT_G711_ALAW_FS
 * - #ASM_MEDIA_FMT_G711_MLAW_FS
 * - #ASM_MEDIA_FMT_G729A_FS
 * - #ASM_MEDIA_FMT_EXAMPLE
 */

	u32                    enc_cfg_id;
/* Specifies the media type for the output of the stream. PCM
 * indicates that no encoding must be performed, e.g., this is an NT
 * decoder session.
 * Supported values:
 * - #ASM_MEDIA_FMT_MULTI_CHANNEL_PCM_V2
 * - #ASM_MEDIA_FMT_AAC_V2
 * - #ASM_MEDIA_FMT_AMRNB_FS
 * - #ASM_MEDIA_FMT_AMRWB_FS
 * - #ASM_MEDIA_FMT_V13K_FS
 * - #ASM_MEDIA_FMT_EVRC_FS
 * - #ASM_MEDIA_FMT_EVRCB_FS
 * - #ASM_MEDIA_FMT_EVRCWB_FS
 * - #ASM_MEDIA_FMT_SBC
 * - #ASM_MEDIA_FMT_G711_ALAW_FS
 * - #ASM_MEDIA_FMT_G711_MLAW_FS
 * - #ASM_MEDIA_FMT_G729A_FS
 * - #ASM_MEDIA_FMT_EXAMPLE
 * - #ASM_MEDIA_FMT_WMA_V8
 */

	u16                    bits_per_sample;
/* Number of bits per sample processed by ASM modules.
 * Supported values: 16 and 24 bits per sample
 */

	u16                    reserved;
/* Reserved for future use. This field must be set to zero.*/

} __packed;

#define ASM_STREAM_CMD_OPEN_LOOPBACK_V2 0x00010D8E
struct asm_stream_cmd_open_loopback_v2 {
	struct apr_hdr         hdr;
	u32                    mode_flags;
/* Mode flags.
 * Bit 0-31: reserved; client should set these bits to 0
 */
	u16                    src_endpointype;
	/* Endpoint type. 0 = Tx Matrix */
	u16                    sink_endpointype;
	/* Endpoint type. 0 = Rx Matrix */
	u32                    postprocopo_id;
/* Postprocessor topology ID. Specifies the topology of
 * postprocessing algorithms.
 */

	u16                    bits_per_sample;
/* The number of bits per sample processed by ASM modules
 * Supported values: 16 and 24 bits per sample
 */
	u16                    reserved;
/* Reserved for future use. This field must be set to zero. */
} __packed;

#define ASM_STREAM_CMD_CLOSE             0x00010BCD
#define ASM_STREAM_CMD_FLUSH             0x00010BCE

#define ASM_STREAM_CMD_FLUSH_READBUFS   0x00010C09
#define ASM_STREAM_CMD_SET_PP_PARAMS_V2 0x00010DA1

struct asm_stream_cmd_set_pp_params_v2 {
	u32                  data_payload_addr_lsw;
/* LSW of parameter data payload address. Supported values: any. */
	u32                  data_payload_addr_msw;
/* MSW of Parameter data payload address. Supported values: any.
 * - Must be set to zero for in-band data.
 * - In the case of 32 bit Shared memory address, msw  field must be
 * - set to zero.
 * - In the case of 36 bit shared memory address, bit 31 to bit 4 of
 * msw
 *
 * - must be set to zero.
 */
	u32                  mem_map_handle;
/* Supported Values: Any.
* memory map handle returned by DSP through
* ASM_CMD_SHARED_MEM_MAP_REGIONS
* command.
* if mmhandle is NULL, the ParamData payloads are within the
* message payload (in-band).
* If mmhandle is non-NULL, the ParamData payloads begin at the
* address specified in the address msw and lsw (out-of-band).
*/

	u32                  data_payload_size;
/* Size in bytes of the variable payload accompanying the
message, or in shared memory. This field is used for parsing the
parameter payload. */

} __packed;

struct asm_stream_param_data_v2 {
	u32                  module_id;
	/* Unique module ID. */

	u32                  param_id;
	/* Unique parameter ID. */

	u16                  param_size;
/* Data size of the param_id/module_id combination. This is
 * a multiple of 4 bytes.
 */

	u16                  reserved;
/* Reserved for future enhancements. This field must be set to
 * zero.
 */

} __packed;

#define ASM_STREAM_CMD_GET_PP_PARAMS_V2		0x00010DA2
#define ASM_STREAM_CMD_SET_ENCDEC_PARAM 0x00010C10
#define ASM_PARAM_ID_ENCDEC_BITRATE     0x00010C13
#define ASM_PARAM_ID_ENCDEC_ENC_CFG_BLK_V2 0x00010DA3
#define ASM_PARAM_ID_AAC_SBR_PS_FLAG		 0x00010C63

/* Flag to turn off both SBR and PS processing, if they are
 * present in the bitstream.
 */

#define ASM_AAC_SBR_OFF_PS_OFF (2)

/* Flag to turn on SBR but turn off PS processing,if they are
 * present in the bitstream.
 */

#define ASM_AAC_SBR_ON_PS_OFF  (1)

/* Flag to turn on both SBR and PS processing, if they are
 * present in the bitstream (default behavior).
 */

#define ASM_AAC_SBR_ON_PS_ON   (0)

/* Structure for an AAC SBR PS processing flag. */

/*  Payload of the #ASM_PARAM_ID_AAC_SBR_PS_FLAG parameter in the
 * #ASM_STREAM_CMD_SET_ENCDEC_PARAM command.
 */
#define ASM_PARAM_ID_AAC_DUAL_MONO_MAPPING                      0x00010C64

/*	First single channel element in a dual mono bitstream.*/
#define ASM_AAC_DUAL_MONO_MAP_SCE_1                                 (1)

/*	Second single channel element in a dual mono bitstream.*/
#define ASM_AAC_DUAL_MONO_MAP_SCE_2                                 (2)

/* Structure for AAC decoder dual mono channel mapping. */
#define ASM_STREAM_CMDRSP_GET_PP_PARAMS_V2 0x00010DA4
#define ASM_PARAM_ID_AC3_KARAOKE_MODE 0x00010D73

/* Enumeration for both vocals in a karaoke stream.*/
#define AC3_KARAOKE_MODE_NO_VOCAL     (0)

/* Enumeration for only the left vocal in a karaoke stream.*/
#define AC3_KARAOKE_MODE_LEFT_VOCAL   (1)

/* Enumeration for only the right vocal in a karaoke stream.*/
#define AC3_KARAOKE_MODE_RIGHT_VOCAL (2)

/* Enumeration for both vocal channels in a karaoke stream.*/
#define AC3_KARAOKE_MODE_BOTH_VOCAL             (3)
#define ASM_PARAM_ID_AC3_DRC_MODE               0x00010D74
/* Enumeration for the Custom Analog mode.*/
#define AC3_DRC_MODE_CUSTOM_ANALOG              (0)

/* Enumeration for the Custom Digital mode.*/
#define AC3_DRC_MODE_CUSTOM_DIGITAL             (1)
/* Enumeration for the Line Out mode (light compression).*/
#define AC3_DRC_MODE_LINE_OUT  (2)

/* Enumeration for the RF remodulation mode (heavy compression).*/
#define AC3_DRC_MODE_RF_REMOD                         (3)
#define ASM_PARAM_ID_AC3_DUAL_MONO_MODE               0x00010D75

/* Enumeration for playing dual mono in stereo mode.*/
#define AC3_DUAL_MONO_MODE_STEREO                     (0)

/* Enumeration for playing left mono.*/
#define AC3_DUAL_MONO_MODE_LEFT_MONO                  (1)

/* Enumeration for playing right mono.*/
#define AC3_DUAL_MONO_MODE_RIGHT_MONO                 (2)

/* Enumeration for mixing both dual mono channels and playing them.*/
#define AC3_DUAL_MONO_MODE_MIXED_MONO        (3)
#define ASM_PARAM_ID_AC3_STEREO_DOWNMIX_MODE 0x00010D76

/* Enumeration for using the Downmix mode indicated in the bitstream. */

#define AC3_STEREO_DOWNMIX_MODE_AUTO_DETECT  (0)

/* Enumeration for Surround Compatible mode (preserves the
 * surround information).
 */

#define AC3_STEREO_DOWNMIX_MODE_LT_RT        (1)
/* Enumeration for Mono Compatible mode (if the output is to be
 * further downmixed to mono).
 */

#define AC3_STEREO_DOWNMIX_MODE_LO_RO (2)

/* ID of the AC3 PCM scale factor parameter in the
 * #ASM_STREAM_CMD_SET_ENCDEC_PARAM command.
 */
#define ASM_PARAM_ID_AC3_PCM_SCALEFACTOR 0x00010D78

/* ID of the AC3 DRC boost scale factor parameter in the
 * #ASM_STREAM_CMD_SET_ENCDEC_PARAM command.
 */
#define ASM_PARAM_ID_AC3_DRC_BOOST_SCALEFACTOR 0x00010D79

/* ID of the AC3 DRC cut scale factor parameter in the
 * #ASM_STREAM_CMD_SET_ENCDEC_PARAM command.
 */
#define ASM_PARAM_ID_AC3_DRC_CUT_SCALEFACTOR 0x00010D7A

/* Structure for AC3 Generic Parameter. */

/*  Payload of the AC3 parameters in the
 * #ASM_STREAM_CMD_SET_ENCDEC_PARAM command.
 */
/* Enumeration for Raw mode (no downmixing), which specifies
 * that all channels in the bitstream are to be played out as is
 * without any downmixing. (Default)
 */

#define WMAPRO_CHANNEL_MASK_RAW (-1)

/* Enumeration for setting the channel mask to 0. The 7.1 mode
 * (Home Theater) is assigned.
 */

#define WMAPRO_CHANNEL_MASK_ZERO 0x0000

/* Speaker layout mask for one channel (Home Theater, mono).
 * - Speaker front center
 */
#define WMAPRO_CHANNEL_MASK_1_C 0x0004

/* Speaker layout mask for two channels (Home Theater, stereo).
 * - Speaker front left
 * - Speaker front right
 */
#define WMAPRO_CHANNEL_MASK_2_L_R 0x0003

/* Speaker layout mask for three channels (Home Theater).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 */
#define WMAPRO_CHANNEL_MASK_3_L_C_R 0x0007

/* Speaker layout mask for two channels (stereo).
 * - Speaker back left
 * - Speaker back right
 */
#define WMAPRO_CHANNEL_MASK_2_Bl_Br  0x0030

/* Speaker layout mask for four channels.
 * - Speaker front left
 * - Speaker front right
 * - Speaker back left
 * - Speaker back right
*/
#define WMAPRO_CHANNEL_MASK_4_L_R_Bl_Br 0x0033

/* Speaker layout mask for four channels (Home Theater).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker back center
*/
#define WMAPRO_CHANNEL_MASK_4_L_R_C_Bc_HT 0x0107
/* Speaker layout mask for five channels.
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker back left
 * - Speaker back right
 */
#define WMAPRO_CHANNEL_MASK_5_L_C_R_Bl_Br  0x0037

/* Speaker layout mask for five channels (5 mode, Home Theater).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker side left
 * - Speaker side right
 */
#define WMAPRO_CHANNEL_MASK_5_L_C_R_Sl_Sr_HT   0x0607
/* Speaker layout mask for six channels (5.1 mode).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker low frequency
 * - Speaker back left
 * - Speaker back right
 */
#define WMAPRO_CHANNEL_MASK_5DOT1_L_C_R_Bl_Br_SLF  0x003F
/* Speaker layout mask for six channels (5.1 mode, Home Theater).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker low frequency
 * - Speaker side left
 * - Speaker side right
 */
#define WMAPRO_CHANNEL_MASK_5DOT1_L_C_R_Sl_Sr_SLF_HT  0x060F
/* Speaker layout mask for six channels (5.1 mode, no LFE).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker back left
 * - Speaker back right
 * - Speaker back center
 */
#define WMAPRO_CHANNEL_MASK_5DOT1_L_C_R_Bl_Br_Bc  0x0137
/* Speaker layout mask for six channels (5.1 mode, Home Theater,
  * no LFE).
  * - Speaker front left
  * - Speaker front right
  * - Speaker front center
  * - Speaker back center
  * - Speaker side left
  * - Speaker side right
 */
#define WMAPRO_CHANNEL_MASK_5DOT1_L_C_R_Sl_Sr_Bc_HT   0x0707

/* Speaker layout mask for seven channels (6.1 mode).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker low frequency
 * - Speaker back left
 * - Speaker back right
 * - Speaker back center
 */
#define WMAPRO_CHANNEL_MASK_6DOT1_L_C_R_Bl_Br_Bc_SLF   0x013F

/* Speaker layout mask for seven channels (6.1 mode, Home
  * Theater).
  * - Speaker front left
  * - Speaker front right
  * - Speaker front center
  * - Speaker low frequency
  * - Speaker back center
  * - Speaker side left
  * - Speaker side right
*/
#define WMAPRO_CHANNEL_MASK_6DOT1_L_C_R_Sl_Sr_Bc_SLF_HT 0x070F

/* Speaker layout mask for seven channels (6.1 mode, no LFE).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker back left
 * - Speaker back right
 * - Speaker front left of center
 * - Speaker front right of center
*/
#define WMAPRO_CHANNEL_MASK_6DOT1_L_C_R_Bl_Br_SFLOC_SFROC   0x00F7

/* Speaker layout mask for seven channels (6.1 mode, Home
 * Theater, no LFE).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker side left
 * - Speaker side right
 * - Speaker front left of center
 * - Speaker front right of center
*/
#define WMAPRO_CHANNEL_MASK_6DOT1_L_C_R_Sl_Sr_SFLOC_SFROC_HT 0x0637

/* Speaker layout mask for eight channels (7.1 mode).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker back left
 * - Speaker back right
 * - Speaker low frequency
 * - Speaker front left of center
 * - Speaker front right of center
 */
#define WMAPRO_CHANNEL_MASK_7DOT1_L_C_R_Bl_Br_SLF_SFLOC_SFROC \
					0x00FF

/* Speaker layout mask for eight channels (7.1 mode, Home Theater).
 * - Speaker front left
 * - Speaker front right
 * - Speaker front center
 * - Speaker side left
 * - Speaker side right
 * - Speaker low frequency
 * - Speaker front left of center
 * - Speaker front right of center
 *
*/
#define WMAPRO_CHANNEL_MASK_7DOT1_L_C_R_Sl_Sr_SLF_SFLOC_SFROC_HT \
					0x063F

#define ASM_PARAM_ID_DEC_OUTPUT_CHAN_MAP  0x00010D82

/*	Maximum number of decoder output channels.*/
#define MAX_CHAN_MAP_CHANNELS  16

/* Structure for decoder output channel mapping. */

/* Payload of the #ASM_PARAM_ID_DEC_OUTPUT_CHAN_MAP parameter in the
 * #ASM_STREAM_CMD_SET_ENCDEC_PARAM command.
 */
struct asm_dec_out_chan_map_param {
	struct apr_hdr hdr;
	struct asm_stream_cmd_set_encdec_param  encdec;
	u32                 num_channels;
/* Number of decoder output channels.
 * Supported values: 0 to #MAX_CHAN_MAP_CHANNELS
 *
 * A value of 0 indicates native channel mapping, which is valid
 * only for NT mode. This means the output of the decoder is to be
 * preserved as is.
 */
	u8                  channel_mapping[MAX_CHAN_MAP_CHANNELS];
} __packed;

#define ASM_STREAM_CMD_OPEN_WRITE_COMPRESSED  0x00010D84

/* Bitmask for the IEC 61937 enable flag.*/
#define ASM_BIT_MASK_IEC_61937_STREAM_FLAG   (0x00000001UL)

/* Shift value for the IEC 61937 enable flag.*/
#define ASM_SHIFT_IEC_61937_STREAM_FLAG  0

/* Bitmask for the IEC 60958 enable flag.*/
#define ASM_BIT_MASK_IEC_60958_STREAM_FLAG   (0x00000002UL)

/* Shift value for the IEC 60958 enable flag.*/
#define ASM_SHIFT_IEC_60958_STREAM_FLAG   1

/* Payload format for open write compressed comand */

/* Payload format for the #ASM_STREAM_CMD_OPEN_WRITE_COMPRESSED
 * comand, which opens a stream for a given session ID and stream ID
 * to be rendered in the compressed format.
 */

/*
    Indicates the number of samples per channel to be removed from the
    beginning of the stream.
*/
#define ASM_DATA_CMD_REMOVE_INITIAL_SILENCE 0x00010D67
/*
    Indicates the number of samples per channel to be removed from
    the end of the stream.
*/
#define ASM_DATA_CMD_REMOVE_TRAILING_SILENCE 0x00010D68
struct asm_data_cmd_remove_silence {
	struct apr_hdr hdr;
	u32	num_samples_to_remove;
	/**< Number of samples per channel to be removed.

	   @values 0 to (2@sscr{32}-1) */
} __packed;

#define ASM_STREAM_CMD_OPEN_READ_COMPRESSED                        0x00010D95

/* adsp_asm_stream_commands.h*/

/* adsp_asm_api.h (no changes)*/
#define ASM_STREAM_POSTPROCOPO_ID_DEFAULT \
								0x00010BE4
#define ASM_STREAM_POSTPROCOPO_ID_PEAKMETER \
								0x00010D83
#define ASM_STREAM_POSTPROCOPO_ID_NONE \
								0x00010C68
#define ASM_STREAM_POSTPROCOPO_ID_MCH_PEAK_VOL \
								0x00010D8B
#define ASM_STREAM_PREPROCOPO_ID_DEFAULT \
			ASM_STREAM_POSTPROCOPO_ID_DEFAULT
#define ASM_STREAM_PREPROCOPO_ID_NONE \
			ASM_STREAM_POSTPROCOPO_ID_NONE
#define ADM_CMD_COPP_OPENOPOLOGY_ID_NONE_AUDIO_COPP \
			0x00010312
#define ADM_CMD_COPP_OPENOPOLOGY_ID_SPEAKER_MONO_AUDIO_COPP \
								0x00010313
#define ADM_CMD_COPP_OPENOPOLOGY_ID_SPEAKER_STEREO_AUDIO_COPP \
								0x00010314
#define ADM_CMD_COPP_OPENOPOLOGY_ID_SPEAKER_STEREO_IIR_AUDIO_COPP\
								0x00010704
#define ADM_CMD_COPP_OPENOPOLOGY_ID_SPEAKER_MONO_AUDIO_COPP_MBDRCV2\
								0x0001070D
#define ADM_CMD_COPP_OPENOPOLOGY_ID_SPEAKER_STEREO_AUDIO_COPP_MBDRCV2\
								0x0001070E
#define ADM_CMD_COPP_OPENOPOLOGY_ID_SPEAKER_STEREO_IIR_AUDIO_COPP_MBDRCV2\
								0x0001070F
#define ADM_CMD_COPP_OPENOPOLOGY_ID_SPEAKER_STEREO_AUDIO_COPP_MBDRC_V3 \
								0x11000000
#define ADM_CMD_COPP_OPENOPOLOGY_ID_SPEAKER_MCH_PEAK_VOL \
								0x0001031B
#define ADM_CMD_COPP_OPENOPOLOGY_ID_MIC_MONO_AUDIO_COPP  0x00010315
#define ADM_CMD_COPP_OPENOPOLOGY_ID_MIC_STEREO_AUDIO_COPP 0x00010316
#define AUDPROC_COPPOPOLOGY_ID_MCHAN_IIR_AUDIO           0x00010715
#define ADM_CMD_COPP_OPENOPOLOGY_ID_DEFAULT_AUDIO_COPP   0x00010BE3
#define ADM_CMD_COPP_OPENOPOLOGY_ID_PEAKMETER_AUDIO_COPP 0x00010317
#define AUDPROC_MODULE_ID_AIG   0x00010716
#define AUDPROC_PARAM_ID_AIG_ENABLE		0x00010717
#define AUDPROC_PARAM_ID_AIG_CONFIG		0x00010718
/* end_addtogroup audio_pp_module_ids */

/* @ingroup audio_pp_module_ids
 * ID of the Volume Control module pre/postprocessing block.
 * This module supports the following parameter IDs:
 * - #ASM_PARAM_ID_VOL_CTRL_MASTER_GAIN
 * - #ASM_PARAM_ID_MULTICHANNEL_GAIN
 * - #ASM_PARAM_ID_VOL_CTRL_MUTE_CONFIG
 * - #ASM_PARAM_ID_SOFT_VOL_STEPPING_PARAMETERS
 * - #ASM_PARAM_ID_SOFT_PAUSE_PARAMETERS
 * - #ASM_PARAM_ID_MULTICHANNEL_GAIN
 * - #ASM_PARAM_ID_MULTICHANNEL_MUTE
 */
#define ASM_MODULE_ID_VOL_CTRL   0x00010BFE
#define ASM_MODULE_ID_VOL_CTRL2  0x00010910
#define AUDPROC_MODULE_ID_VOL_CTRL ASM_MODULE_ID_VOL_CTRL

/* @addtogroup audio_pp_param_ids */
/* ID of the master gain parameter used by the #ASM_MODULE_ID_VOL_CTRL
 * module.
 * @messagepayload
 * @structure{asm_volume_ctrl_master_gain}
 * @tablespace
 * @inputtable{Audio_Postproc_ASM_PARAM_ID_VOL_CTRL_MASTER_GAIN.tex}
 */
#define ASM_PARAM_ID_VOL_CTRL_MASTER_GAIN    0x00010BFF
#define AUDPROC_PARAM_ID_VOL_CTRL_MASTER_GAIN ASM_PARAM_ID_VOL_CTRL_MASTER_GAIN

/* ID of the left/right channel gain parameter used by the
 * #ASM_MODULE_ID_VOL_CTRL module.
 * @messagepayload
 * @structure{asm_volume_ctrl_lr_chan_gain}
 * @tablespace
 * @inputtable{Audio_Postproc_ASM_PARAM_ID_MULTICHANNEL_GAIN.tex}
 */
#define ASM_PARAM_ID_VOL_CTRL_LR_CHANNEL_GAIN     0x00010C00

/* ID of the mute configuration parameter used by the
 * #ASM_MODULE_ID_VOL_CTRL module.
 * @messagepayload
 * @structure{asm_volume_ctrl_mute_config}
 * @tablespace
 * @inputtable{Audio_Postproc_ASM_PARAM_ID_VOL_CTRL_MUTE_CONFIG.tex}
 */
#define ASM_PARAM_ID_VOL_CTRL_MUTE_CONFIG   0x00010C01

/* ID of the soft stepping volume parameters used by the
 * #ASM_MODULE_ID_VOL_CTRL module.
 * @messagepayload
 * @structure{asm_soft_step_volume_params}
 * @tablespace
 * @inputtable{Audio_Postproc_ASM_PARAM_ID_SOFT_VOL_STEPPING_PARAMET
 * ERS.tex}
 */
#define ASM_PARAM_ID_SOFT_VOL_STEPPING_PARAMETERS  0x00010C29
#define AUDPROC_PARAM_ID_SOFT_VOL_STEPPING_PARAMETERS\
			ASM_PARAM_ID_SOFT_VOL_STEPPING_PARAMETERS

/* ID of the soft pause parameters used by the #ASM_MODULE_ID_VOL_CTRL
 * module.
 */
#define ASM_PARAM_ID_SOFT_PAUSE_PARAMETERS   0x00010D6A

/* ID of the multiple-channel volume control parameters used by the
 * #ASM_MODULE_ID_VOL_CTRL module.
 */
#define ASM_PARAM_ID_MULTICHANNEL_GAIN  0x00010713

/* ID of the multiple-channel mute configuration parameters used by the
 * #ASM_MODULE_ID_VOL_CTRL module.
 */

#define ASM_PARAM_ID_MULTICHANNEL_MUTE  0x00010714

/* Structure for the master gain parameter for a volume control
 * module.
 */

/* @brief Payload of the #ASM_PARAM_ID_VOL_CTRL_MASTER_GAIN
 * parameter used by the Volume Control module.
 */

struct asm_volume_ctrl_master_gain {
	struct apr_hdr	hdr;
	struct asm_stream_cmd_set_pp_params_v2 param;
	struct asm_stream_param_data_v2 data;
	uint16_t                  master_gain;
	/*< Linear gain in Q13 format. */

	uint16_t                  reserved;
	/*< Clients must set this field to zero.
		*/
} __packed;

struct asm_volume_ctrl_lr_chan_gain {
	struct apr_hdr	hdr;
	struct asm_stream_cmd_set_pp_params_v2 param;
	struct asm_stream_param_data_v2 data;

	uint16_t                  l_chan_gain;
	/*< Linear gain in Q13 format for the left channel. */

	uint16_t                  r_chan_gain;
	/*< Linear gain in Q13 format for the right channel.*/
} __packed;

/* Structure for the mute configuration parameter for a
	volume control module. */

/* @brief Payload of the #ASM_PARAM_ID_VOL_CTRL_MUTE_CONFIG
 * parameter used by the Volume Control module.
 */

struct asm_volume_ctrl_mute_config {
	struct apr_hdr	hdr;
	struct asm_stream_cmd_set_pp_params_v2 param;
	struct asm_stream_param_data_v2 data;
	uint32_t                  mute_flag;
/*< Specifies whether mute is disabled (0) or enabled (nonzero).*/

} __packed;

/*
 * Supported parameters for a soft stepping linear ramping curve.
 */
#define ASM_PARAM_SVC_RAMPINGCURVE_LINEAR  0

/*
 * Exponential ramping curve.
 */
#define ASM_PARAM_SVC_RAMPINGCURVE_EXP    1

/*
 * Logarithmic ramping curve.
 */
#define ASM_PARAM_SVC_RAMPINGCURVE_LOG    2

/* Structure for holding soft stepping volume parameters. */

/*  Payload of the #ASM_PARAM_ID_SOFT_VOL_STEPPING_PARAMETERS
 * parameters used by the Volume Control module.
 */
/* Structure for holding soft pause parameters. */

/* Payload of the #ASM_PARAM_ID_SOFT_PAUSE_PARAMETERS
 * parameters used by the Volume Control module.
 */

/* Maximum number of channels.*/
#define VOLUME_CONTROL_MAX_CHANNELS                       8

/* Structure for holding one channel type - gain pair. */

/* Payload of the #ASM_PARAM_ID_MULTICHANNEL_GAIN channel
 * type/gain pairs used by the Volume Control module. \n \n This
 * structure immediately follows the
 * asm_volume_ctrl_multichannel_gain structure.
 */

struct asm_volume_ctrl_channeltype_gain_pair {
	uint8_t                   channeltype;
	/*
	 * Channel type for which the gain setting is to be applied.
	 * Supported values:
	 * - #PCM_CHANNEL_L
	 * - #PCM_CHANNEL_R
	 * - #PCM_CHANNEL_C
	 * - #PCM_CHANNEL_LS
	 * - #PCM_CHANNEL_RS
	 * - #PCM_CHANNEL_LFE
	 * - #PCM_CHANNEL_CS
	 * - #PCM_CHANNEL_LB
	 * - #PCM_CHANNEL_RB
	 * - #PCM_CHANNELS
	 * - #PCM_CHANNEL_CVH
	 * - #PCM_CHANNEL_MS
	 * - #PCM_CHANNEL_FLC
	 * - #PCM_CHANNEL_FRC
	 * - #PCM_CHANNEL_RLC
	 * - #PCM_CHANNEL_RRC
	 */

	uint8_t                   reserved1;
	/* Clients must set this field to zero. */

	uint8_t                   reserved2;
	/* Clients must set this field to zero. */

	uint8_t                   reserved3;
	/* Clients must set this field to zero. */

	uint32_t                  gain;
	/*
	 * Gain value for this channel in Q28 format.
	 * Supported values: Any
	 */
} __packed;

/* Structure for the multichannel gain command */

/* Payload of the #ASM_PARAM_ID_MULTICHANNEL_GAIN
 * parameters used by the Volume Control module.
 */

struct asm_volume_ctrl_multichannel_gain {
	struct apr_hdr	hdr;
	struct asm_stream_cmd_set_pp_params_v2 param;
	struct asm_stream_param_data_v2 data;
	uint32_t                  num_channels;
	/*
	 * Number of channels for which gain values are provided. Any
	 * channels present in the data for which gain is not provided are
	 * set to unity gain.
	 * Supported values: 1 to 8
	 */

	struct asm_volume_ctrl_channeltype_gain_pair
		gain_data[VOLUME_CONTROL_MAX_CHANNELS];
	/* Array of channel type/gain pairs.*/
} __packed;

/* Structure for holding one channel type - mute pair. */

/* Payload of the #ASM_PARAM_ID_MULTICHANNEL_MUTE channel
 * type/mute setting pairs used by the Volume Control module. \n \n
 * This structure immediately follows the
 * asm_volume_ctrl_multichannel_mute structure.
 */

/* Structure for the multichannel mute command */

/* @brief Payload of the #ASM_PARAM_ID_MULTICHANNEL_MUTE
 * parameters used by the Volume Control module.
 */

/* audio_pp_module_ids
 * ID of the IIR Tuning Filter module.
 * This module supports the following parameter IDs:
 * - #ASM_PARAM_ID_IIRUNING_FILTER_ENABLE_CONFIG
 * - #ASM_PARAM_ID_IIRUNING_FILTER_PRE_GAIN
 * - #ASM_PARAM_ID_IIRUNING_FILTER_CONFIG_PARAMS
 */
#define ASM_MODULE_ID_IIRUNING_FILTER   0x00010C02

/* @addtogroup audio_pp_param_ids */
/* ID of the IIR tuning filter enable parameter used by the
 * #ASM_MODULE_ID_IIRUNING_FILTER module.
 * @messagepayload
 * @structure{asm_iiruning_filter_enable}
 * @tablespace
 * @inputtable{Audio_Postproc_ASM_PARAM_ID_IIRUNING_FILTER_ENABLE_CO
 * NFIG.tex}
 */
#define ASM_PARAM_ID_IIRUNING_FILTER_ENABLE_CONFIG   0x00010C03

/* ID of the IIR tuning filter pregain parameter used by the
 * #ASM_MODULE_ID_IIRUNING_FILTER module.
 */
#define ASM_PARAM_ID_IIRUNING_FILTER_PRE_GAIN  0x00010C04

/* ID of the IIR tuning filter configuration parameters used by the
 * #ASM_MODULE_ID_IIRUNING_FILTER module.
 */
#define ASM_PARAM_ID_IIRUNING_FILTER_CONFIG_PARAMS  0x00010C05

/* Structure for an enable configuration parameter for an
 * IIR tuning filter module.
 */

/* @brief Payload of the #ASM_PARAM_ID_IIRUNING_FILTER_ENABLE_CONFIG
 * parameter used by the IIR Tuning Filter module.
 */

/* Structure for the pregain parameter for an IIR tuning filter module. */

/* Payload of the #ASM_PARAM_ID_IIRUNING_FILTER_PRE_GAIN
 * parameters used by the IIR Tuning Filter module.
 */
/* Structure for the configuration parameter for an IIR tuning filter
 * module.
 */

/* @brief Payload of the #ASM_PARAM_ID_IIRUNING_FILTER_CONFIG_PARAMS
 * parameters used by the IIR Tuning Filter module. \n
 * \n
 * This structure is followed by the IIR filter coefficients: \n
 * - Sequence of int32_t FilterCoeffs \n
 * Five coefficients for each band. Each coefficient is in int32_t format, in
 * the order of b0, b1, b2, a1, a2.
 * - Sequence of int16_t NumShiftFactor \n
 * One int16_t per band. The numerator shift factor is related to the Q
 * factor of the filter coefficients.
 * - Sequence of uint16_t PanSetting \n
 * One uint16_t per band, indicating if the filter is applied to left (0),
 * right (1), or both (2) channels.
 */
/* audio_pp_module_ids
 * ID of the Multiband Dynamic Range Control (MBDRC) module on the Tx/Rx
 * paths.
 * This module supports the following parameter IDs:
 * - #ASM_PARAM_ID_MBDRC_ENABLE
 * - #ASM_PARAM_ID_MBDRC_CONFIG_PARAMS
 */
#define ASM_MODULE_ID_MBDRC   0x00010C06

/* audio_pp_param_ids */
/* ID of the MBDRC enable parameter used by the #ASM_MODULE_ID_MBDRC module.
 * @messagepayload
 * @structure{asm_mbdrc_enable}
 * @tablespace
 * @inputtable{Audio_Postproc_ASM_PARAM_ID_MBDRC_ENABLE.tex}
 */
#define ASM_PARAM_ID_MBDRC_ENABLE   0x00010C07

/* ID of the MBDRC configuration parameters used by the
 * #ASM_MODULE_ID_MBDRC module.
 * @messagepayload
 * @structure{asm_mbdrc_config_params}
 * @tablespace
 * @inputtable{Audio_Postproc_ASM_PARAM_ID_MBDRC_CONFIG_PARAMS.tex}
 *
 * @parspace Sub-band DRC configuration parameters
 * @structure{asm_subband_drc_config_params}
 * @tablespace
 * @inputtable{Audio_Postproc_ASM_PARAM_ID_MBDRC_CONFIG_PARAMS_subband_DRC.tex}
 *
 * @keep{6}
 * To obtain legacy ADRC from MBDRC, use the calibration tool to:
 *
 * - Enable MBDRC (EnableFlag = TRUE)
 * - Set number of bands to 1 (uiNumBands = 1)
 * - Enable the first MBDRC band (DrcMode[0] = DRC_ENABLED = 1)
 * - Clear the first band mute flag (MuteFlag[0] = 0)
 * - Set the first band makeup gain to unity (compMakeUpGain[0] = 0x2000)
 * - Use the legacy ADRC parameters to calibrate the rest of the MBDRC
 * parameters.
 */
#define ASM_PARAM_ID_MBDRC_CONFIG_PARAMS  0x00010C08

/* end_addtogroup audio_pp_param_ids */

/* audio_pp_module_ids
 * ID of the MMBDRC module version 2 pre/postprocessing block.
 * This module differs from the original MBDRC (#ASM_MODULE_ID_MBDRC) in
 * the length of the filters used in each sub-band.
 * This module supports the following parameter ID:
 * - #ASM_PARAM_ID_MBDRC_CONFIG_PARAMS_IMPROVED_FILTBANK_V2
 */
#define ASM_MODULE_ID_MBDRCV2                                0x0001070B

/* @addtogroup audio_pp_param_ids */
/* ID of the configuration parameters used by the
 * #ASM_MODULE_ID_MBDRCV2 module for the improved filter structure
 * of the MBDRC v2 pre/postprocessing block.
 * The update to this configuration structure from the original
 * MBDRC is the number of filter coefficients in the filter
 * structure. The sequence for is as follows:
 * - 1 band = 0 FIR coefficient + 1 mute flag + uint16_t padding
 * - 2 bands = 141 FIR coefficients + 2 mute flags + uint16_t padding
 * - 3 bands = 141+81 FIR coefficients + 3 mute flags + uint16_t padding
 * - 4 bands = 141+81+61 FIR coefficients + 4 mute flags + uint16_t
 * padding
 * - 5 bands = 141+81+61+61 FIR coefficients + 5 mute flags +
 * uint16_t padding
 *	This block uses the same parameter structure as
 *	#ASM_PARAM_ID_MBDRC_CONFIG_PARAMS.
 */
#define ASM_PARAM_ID_MBDRC_CONFIG_PARAMS_IMPROVED_FILTBANK_V2 \
								0x0001070C

#define ASM_MODULE_ID_MBDRCV3					0x0001090B
/*
 * ID of the MMBDRC module version 3 pre/postprocessing block.
 * This module differs from MBDRCv2 (#ASM_MODULE_ID_MBDRCV2) in
 * that it supports both 16- and 24-bit data.
 * This module supports the following parameter ID:
 * - #ASM_PARAM_ID_MBDRC_ENABLE
 * - #ASM_PARAM_ID_MBDRC_CONFIG_PARAMS
 * - #ASM_PARAM_ID_MBDRC_CONFIG_PARAMS_V3
 * - #ASM_PARAM_ID_MBDRC_FILTER_XOVER_FREQS
 */

/* Structure for the enable parameter for an MBDRC module. */

/* Payload of the #ASM_PARAM_ID_MBDRC_ENABLE parameter used by the
 * MBDRC module.
 */

/* Structure for the configuration parameters for an MBDRC module. */

/* Payload of the #ASM_PARAM_ID_MBDRC_CONFIG_PARAMS
 * parameters used by the MBDRC module. \n \n Following this
 * structure is the payload for sub-band DRC configuration
 * parameters (asm_subband_drc_config_params). This sub-band
 * structure must be repeated for each band.
 */

/* DRC configuration structure for each sub-band of an MBDRC module. */

/* Payload of the #ASM_PARAM_ID_MBDRC_CONFIG_PARAMS DRC
 * configuration parameters for each sub-band in the MBDRC module.
 * After this DRC structure is configured for valid bands, the next
 * MBDRC setparams expects the sequence of sub-band MBDRC filter
 * coefficients (the length depends on the number of bands) plus the
 * mute flag for that band plus uint16_t padding.
 *
 * @keep{10}
 * The filter coefficient and mute flag are of type int16_t:
 * - FIR coefficient = int16_t firFilter
 * - Mute flag = int16_t fMuteFlag
 *
 * The sequence is as follows:
 * - 1 band = 0 FIR coefficient + 1 mute flag + uint16_t padding
 * - 2 bands = 97 FIR coefficients + 2 mute flags + uint16_t padding
 * - 3 bands = 97+33 FIR coefficients + 3 mute flags + uint16_t padding
 * - 4 bands = 97+33+33 FIR coefficients + 4 mute flags + uint16_t padding
 * - 5 bands = 97+33+33+33 FIR coefficients + 5 mute flags + uint16_t padding
 *
 * For improved filterbank, the sequence is as follows:
 * - 1 band = 0 FIR coefficient + 1 mute flag + uint16_t padding
 * - 2 bands = 141 FIR coefficients + 2 mute flags + uint16_t padding
 * - 3 bands = 141+81 FIR coefficients + 3 mute flags + uint16_t padding
 * - 4 bands = 141+81+61 FIR coefficients + 4 mute flags + uint16_t padding
 * - 5 bands = 141+81+61+61 FIR coefficients + 5 mute flags + uint16_t padding
 */

#define ASM_MODULE_ID_EQUALIZER            0x00010C27
#define ASM_PARAM_ID_EQUALIZER_PARAMETERS  0x00010C28

#define ASM_MAX_EQ_BANDS 12

struct asm_eq_per_band_params {
	uint32_t                  band_idx;
/*< Band index.
 * Supported values: 0 to 11
 */

	uint32_t                  filterype;
/*< Type of filter.
 * Supported values:
 * - #ASM_PARAM_EQYPE_NONE
 * - #ASM_PARAM_EQ_BASS_BOOST
 * - #ASM_PARAM_EQ_BASS_CUT
 * - #ASM_PARAM_EQREBLE_BOOST
 * - #ASM_PARAM_EQREBLE_CUT
 * - #ASM_PARAM_EQ_BAND_BOOST
 * - #ASM_PARAM_EQ_BAND_CUT
 */

	uint32_t                  center_freq_hz;
	/*< Filter band center frequency in Hertz. */

	int32_t                   filter_gain;
/*< Filter band initial gain.
 * Supported values: +12 to -12 dB in 1 dB increments
 */

	int32_t                   q_factor;
/*< Filter band quality factor expressed as a Q8 number, i.e., a
 * fixed-point number with q factor of 8. For example, 3000/(2^8).
 */
} __packed;

struct asm_eq_params {
	struct apr_hdr	hdr;
	struct asm_stream_cmd_set_pp_params_v2 param;
	struct asm_stream_param_data_v2 data;
		uint32_t                  enable_flag;
/*< Specifies whether the equalizer module is disabled (0) or enabled
 * (nonzero).
 */

		uint32_t                  num_bands;
/*< Number of bands.
 * Supported values: 1 to 12
 */
	struct asm_eq_per_band_params eq_bands[ASM_MAX_EQ_BANDS];

} __packed;

/*	No equalizer effect.*/
#define ASM_PARAM_EQYPE_NONE      0

/*	Bass boost equalizer effect.*/
#define ASM_PARAM_EQ_BASS_BOOST     1

/*Bass cut equalizer effect.*/
#define ASM_PARAM_EQ_BASS_CUT       2

/*	Treble boost equalizer effect */
#define ASM_PARAM_EQREBLE_BOOST   3

/*	Treble cut equalizer effect.*/
#define ASM_PARAM_EQREBLE_CUT     4

/*	Band boost equalizer effect.*/
#define ASM_PARAM_EQ_BAND_BOOST     5

/*	Band cut equalizer effect.*/
#define ASM_PARAM_EQ_BAND_CUT       6

/* Set Q6 topologies */
#define ASM_CMD_ADD_TOPOLOGIES				0x00010DBE
/* structure used for both ioctls */
struct cmd_set_topologies {
	struct apr_hdr hdr;
	u32		payload_addr_lsw;
	/* LSW of parameter data payload address.*/
	u32		payload_addr_msw;
	/* MSW of parameter data payload address.*/
	u32		mem_map_handle;
	/* Memory map handle returned by mem map command */
	u32		payload_size;
	/* Size in bytes of the variable payload in shared memory */
} __packed;

/* This module represents the Rx processing of Feedback speaker protection.
 * It contains the excursion control, thermal protection,
 * analog clip manager features in it.
 * This module id will support following param ids.
 * - AFE_PARAM_ID_FBSP_MODE_RX_CFG
 */

struct asm_fbsp_mode_rx_cfg {
	uint32_t minor_version;
	uint32_t mode;
} __packed;

/* This module represents the VI processing of feedback speaker protection.
 * It will receive Vsens and Isens from codec and generates necessary
 * parameters needed by Rx processing.
 * This module id will support following param ids.
 * - AFE_PARAM_ID_SPKR_CALIB_VI_PROC_CFG
 * - AFE_PARAM_ID_CALIB_RES_CFG
 * - AFE_PARAM_ID_FEEDBACK_PATH_CFG
 */

struct asm_spkr_calib_vi_proc_cfg {
	uint32_t minor_version;
	uint32_t operation_mode;
	uint32_t r0_t0_selection_flag[SP_V2_NUM_MAX_SPKR];
	int32_t r0_cali_q24[SP_V2_NUM_MAX_SPKR];
	int16_t	t0_cali_q6[SP_V2_NUM_MAX_SPKR];
	uint32_t quick_calib_flag;
} __packed;

struct asm_calib_res_cfg {
	uint32_t minor_version;
	int32_t	r0_cali_q24[SP_V2_NUM_MAX_SPKR];
	uint32_t th_vi_ca_state;
} __packed;

struct asm_feedback_path_cfg {
	uint32_t minor_version;
	int32_t	dst_portid;
	int32_t	num_channels;
	int32_t	chan_info[4];
} __packed;

struct asm_mode_vi_proc_cfg {
	uint32_t minor_version;
	uint32_t cal_mode;
} __packed;

#define AUDPROC_PARAM_ID_ENABLE		0x00010904
#define ASM_STREAM_POSTPROC_TOPO_ID_SA_PLUS 0x1000FFFF
/* DTS Eagle */
#define AUDPROC_MODULE_ID_DTS_HPX_PREMIX 0x0001077C
#define AUDPROC_MODULE_ID_DTS_HPX_POSTMIX 0x0001077B
#define ASM_STREAM_POSTPROC_TOPO_ID_DTS_HPX 0x00010DED
#define ASM_STREAM_POSTPROC_TOPO_ID_HPX_PLUS  0x10015000
#define ASM_STREAM_POSTPROC_TOPO_ID_HPX_MASTER  0x10015001
/* Command for Matrix or Stream Router */
#define ASM_SESSION_CMD_SET_MTMX_STRTR_PARAMS_V2    0x00010DCE
/* Module for AVSYNC */
#define ASM_SESSION_MTMX_STRTR_MODULE_ID_AVSYNC    0x00010DC6

/* Parameter used by #ASM_SESSION_MTMX_STRTR_MODULE_ID_AVSYNC to specify the
 * render window start value. This parameter is supported only for a Set
 * command (not a Get command) in the Rx direction
 * (#ASM_SESSION_CMD_SET_MTMX_STRTR_PARAMS_V2).
 * Render window start is a value (session time minus timestamp, or ST-TS)
 * below which frames are held, and after which frames are immediately
 * rendered.
 */
#define ASM_SESSION_MTMX_STRTR_PARAM_RENDER_WINDOW_START_V2 0x00010DD1

/* Parameter used by #ASM_SESSION_MTMX_STRTR_MODULE_ID_AVSYNC to specify the
 * render window end value. This parameter is supported only for a Set
 * command (not a Get command) in the Rx direction
 * (#ASM_SESSION_CMD_SET_MTMX_STRTR_PARAMS_V2). Render window end is a value
 * (session time minus timestamp) above which frames are dropped, and below
 * which frames are immediately rendered.
 */
#define ASM_SESSION_MTMX_STRTR_PARAM_RENDER_WINDOW_END_V2   0x00010DD2

/* Generic payload of the window parameters in the
 * #ASM_SESSION_MTMX_STRTR_MODULE_ID_AVSYNC module.
 * This payload is supported only for a Set command
 * (not a Get command) on the Rx path.
 */
struct asm_session_mtmx_strtr_param_window_v2_t {
	u32    window_lsw;
	/* Lower 32 bits of the render window start value. */

	u32    window_msw;
	/* Upper 32 bits of the render window start value.

	 * The 64-bit number formed by window_lsw and window_msw specifies a
	 * signed 64-bit window value in microseconds. The sign extension is
	 * necessary. This value is used by the following parameter IDs:
	 * #ASM_SESSION_MTMX_STRTR_PARAM_RENDER_WINDOW_START_V2
	 * #ASM_SESSION_MTMX_STRTR_PARAM_RENDER_WINDOW_END_V2
	 * #ASM_SESSION_MTMX_STRTR_PARAM_STAT_WINDOW_START_V2
	 * #ASM_SESSION_MTMX_STRTR_PARAM_STAT_WINDOW_END_V2
	 * The value depends on which parameter ID is used.
	 * The aDSP honors the windows at a granularity of 1 ms.
	 */
};

struct asm_session_cmd_set_mtmx_strstr_params_v2 {
	uint32_t                  data_payload_addr_lsw;
	/* Lower 32 bits of the 64-bit data payload address. */

	uint32_t                  data_payload_addr_msw;
	/* Upper 32 bits of the 64-bit data payload address.
	 * If the address is not sent (NULL), the message is in the payload.
	 * If the address is sent (non-NULL), the parameter data payloads
	 * begin at the specified address.
	 */

	uint32_t                  mem_map_handle;
	/* Unique identifier for an address. This memory map handle is returned
	 * by the aDSP through the #ASM_CMD_SHARED_MEM_MAP_REGIONS command.
	 * values
	 * - NULL -- Parameter data payloads are within the message payload
	 * (in-band).
	 * - Non-NULL -- Parameter data payloads begin at the address specified
	 * in the data_payload_addr_lsw and data_payload_addr_msw fields
	 * (out-of-band).
	 */

	uint32_t                  data_payload_size;
	/* Actual size of the variable payload accompanying the message, or in
	 * shared memory. This field is used for parsing the parameter payload.
	 * values > 0 bytes
	 */

	uint32_t                  direction;
	/* Direction of the entity (matrix mixer or stream router) on which
	 * the parameter is to be set.
	 * values
	 * - 0 -- Rx (for Rx stream router or Rx matrix mixer)
	 * - 1 -- Tx (for Tx stream router or Tx matrix mixer)
	 */
};

struct asm_mtmx_strtr_params {
	struct apr_hdr  hdr;
	struct asm_session_cmd_set_mtmx_strstr_params_v2 param;
	struct asm_stream_param_data_v2 data;
	u32 window_lsw;
	u32 window_msw;
} __packed;

#define ASM_SESSION_CMD_GET_MTMX_STRTR_PARAMS_V2 0x00010DCF
#define ASM_SESSION_CMDRSP_GET_MTMX_STRTR_PARAMS_V2 0x00010DD0

#define ASM_SESSION_MTMX_STRTR_PARAM_SESSION_TIME_V3 0x00012F0B
#define ASM_SESSION_MTMX_STRTR_PARAM_STIME_TSTMP_FLG_BMASK (0x80000000UL)

struct asm_session_cmd_get_mtmx_strstr_params_v2 {
	uint32_t                  data_payload_addr_lsw;
	/* Lower 32 bits of the 64-bit data payload address. */

	uint32_t                  data_payload_addr_msw;
	/*
	 * Upper 32 bits of the 64-bit data payload address.
	 * If the address is not sent (NULL), the message is in the payload.
	 * If the address is sent (non-NULL), the parameter data payloads
	 * begin at the specified address.
	 */

	uint32_t                  mem_map_handle;
	/*
	 * Unique identifier for an address. This memory map handle is returned
	 * by the aDSP through the #ASM_CMD_SHARED_MEM_MAP_REGIONS command.
	 * values
	 * - NULL -- Parameter data payloads are within the message payload
	 * (in-band).
	 * - Non-NULL -- Parameter data payloads begin at the address specified
	 * in the data_payload_addr_lsw and data_payload_addr_msw fields
	 * (out-of-band).
	 */
	uint32_t                  direction;
	/*
	 * Direction of the entity (matrix mixer or stream router) on which
	 * the parameter is to be set.
	 * values
	 * - 0 -- Rx (for Rx stream router or Rx matrix mixer)
	 * - 1 -- Tx (for Tx stream router or Tx matrix mixer)
	 */
	uint32_t                  module_id;
	/* Unique module ID. */

	uint32_t                  param_id;
	/* Unique parameter ID. */

	uint32_t                  param_max_size;
};

struct asm_session_mtmx_strtr_param_session_time_v3_t {
	uint32_t                  session_time_lsw;
	/* Lower 32 bits of the current session time in microseconds */

	uint32_t                  session_time_msw;
	/*
	 * Upper 32 bits of the current session time in microseconds.
	 * The 64-bit number formed by session_time_lsw and session_time_msw
	 * is treated as signed.
	 */

	uint32_t                  absolute_time_lsw;
	/*
	 * Lower 32 bits of the 64-bit absolute time in microseconds.
	 * This is the time when the sample corresponding to the
	 * session_time_lsw is rendered to the hardware. This absolute
	 * time can be slightly in the future or past.
	 */

	uint32_t                  absolute_time_msw;
	/*
	 * Upper 32 bits of the 64-bit absolute time in microseconds.
	 * This is the time when the sample corresponding to the
	 * session_time_msw is rendered to hardware. This absolute
	 * time can be slightly in the future or past. The 64-bit number
	 * formed by absolute_time_lsw and absolute_time_msw is treated as
	 * unsigned.
	 */

	uint32_t                  time_stamp_lsw;
	/* Lower 32 bits of the last processed timestamp in microseconds */

	uint32_t                  time_stamp_msw;
	/*
	 * Upper 32 bits of the last processed timestamp in microseconds.
	 * The 64-bit number formed by time_stamp_lsw and time_stamp_lsw
	 * is treated as unsigned.
	 */

	uint32_t                  flags;
	/*
	 * Keeps track of any additional flags needed.
	 * @values{for bit 31}
	 * - 0 -- Uninitialized/invalid
	 * - 1 -- Valid
	 * All other bits are reserved; clients must set them to zero.
	 */
};

union asm_session_mtmx_strtr_data_type {
	struct asm_session_mtmx_strtr_param_session_time_v3_t session_time;
};

struct asm_mtmx_strtr_get_params {
	struct apr_hdr hdr;
	struct asm_session_cmd_get_mtmx_strstr_params_v2 param_info;
} __packed;

struct asm_mtmx_strtr_get_params_cmdrsp {
	uint32_t err_code;
	struct asm_stream_param_data_v2 param_info;
	union asm_session_mtmx_strtr_data_type param_data;
} __packed;

typedef void (*app_cb)(uint32_t opcode, uint32_t token,
			uint32_t *payload, void *priv);

struct audio_buffer {
	dma_addr_t phys;
	void       *data;
	uint32_t   used;
	uint32_t   size;/* size of buffer */
	uint32_t   actual_size; /* actual number of bytes read by DSP */
	struct      ion_handle *handle;
	struct      ion_client *client;
};

struct audio_aio_write_param {
	phys_addr_t   paddr;
	uint32_t      len;
	uint32_t      uid;
	uint32_t      lsw_ts;
	uint32_t      msw_ts;
	uint32_t      flags;
	uint32_t      metadata_len;
	uint32_t      last_buffer;
};

struct audio_aio_read_param {
	phys_addr_t   paddr;
	uint32_t      len;
	uint32_t      uid;
};

struct audio_port_data {
	struct audio_buffer *buf;
	uint32_t	    max_buf_cnt;
	uint32_t	    dsp_buf;
	uint32_t	    cpu_buf;
	struct list_head    mem_map_handle;
	uint32_t	    tmp_hdl;
	/* read or write locks */
	struct mutex	    lock;
	spinlock_t	    dsp_lock;
};

struct audio_client {
	int                    session;
	app_cb		       cb;
	atomic_t	       cmd_state;
	/* Relative or absolute TS */
	atomic_t	       time_flag;
	atomic_t	       nowait_cmd_cnt;
	struct list_head       no_wait_que;
	spinlock_t             no_wait_que_spinlock;
	atomic_t               mem_state;
	void		       *priv;
	uint32_t               io_mode;
	uint64_t	       time_stamp;
	struct apr_svc         *apr;
	struct apr_svc         *mmap_apr;
	struct apr_svc         *apr2;
	struct mutex	       cmd_lock;
	/* idx:1 out port, 0: in port*/
	struct audio_port_data port[2];
	wait_queue_head_t      cmd_wait;
	wait_queue_head_t      time_wait;
	wait_queue_head_t      mem_wait;
	int                    perf_mode;
	int					   stream_id;
	struct device *dev;
	int		       topology;
	int		       app_type;
	/* audio cache operations fptr*/
	int (*fptr_cache_ops)(struct audio_buffer *abuff, int cache_op);
	atomic_t               unmap_cb_success;
	atomic_t               reset;
	/* holds latest DSP pipeline delay */
	uint32_t               path_delay;
};

void q6asm_audio_client_free(struct audio_client *ac);

struct audio_client *q6asm_audio_client_alloc(struct device *dev, app_cb cb, void *priv);

struct audio_client *q6asm_get_audio_client(int session_id);

int q6asm_audio_client_map_memory_regions(unsigned int dir
				/* 1:Out,0:In */,
				struct audio_client *ac,
				void *data, 
				dma_addr_t phys,
				unsigned int bufsz,
				unsigned int bufcnt);

int q6asm_audio_client_unmap_memory_regions(unsigned int dir,
			struct audio_client *ac);

int q6asm_open_read(struct audio_client *ac, uint32_t format
		/*, uint16_t bits_per_sample*/);

int q6asm_open_read_v2(struct audio_client *ac, uint32_t format,
			uint16_t bits_per_sample);

int q6asm_open_write(struct audio_client *ac, uint32_t format
		/*, uint16_t bits_per_sample*/);

int q6asm_open_write_v2(struct audio_client *ac, uint32_t format,
			uint16_t bits_per_sample);

int q6asm_stream_open_write_v2(struct audio_client *ac, uint32_t format,
				uint16_t bits_per_sample, int32_t stream_id,
				bool is_gapless_mode);

int q6asm_open_write_compressed(struct audio_client *ac, uint32_t format,
				uint32_t passthrough_flag);

int q6asm_open_read_write(struct audio_client *ac,
			uint32_t rd_format,
			uint32_t wr_format);

int q6asm_open_read_write_v2(struct audio_client *ac, uint32_t rd_format,
			     uint32_t wr_format, bool is_meta_data_mode,
			     uint32_t bits_per_sample, bool overwrite_topology,
			     int topology);

int q6asm_open_loopback_v2(struct audio_client *ac,
			   uint16_t bits_per_sample);

int q6asm_write(struct audio_client *ac, uint32_t len, uint32_t msw_ts,
				uint32_t lsw_ts, uint32_t flags);
int q6asm_write_nolock(struct audio_client *ac, uint32_t len, uint32_t msw_ts,
				uint32_t lsw_ts, uint32_t flags);

int q6asm_async_write(struct audio_client *ac,
					  struct audio_aio_write_param *param);

int q6asm_async_read(struct audio_client *ac,
					  struct audio_aio_read_param *param);

int q6asm_read(struct audio_client *ac);
int q6asm_read_v2(struct audio_client *ac, uint32_t len);
int q6asm_read_nolock(struct audio_client *ac);

int q6asm_memory_map(struct audio_client *ac, phys_addr_t buf_add,
			int dir, uint32_t bufsz, uint32_t bufcnt);

int q6asm_memory_unmap(struct audio_client *ac, phys_addr_t buf_add,
							int dir);

int q6asm_send_cal(struct audio_client *ac);

int q6asm_run(struct audio_client *ac, uint32_t flags,
		uint32_t msw_ts, uint32_t lsw_ts);

int q6asm_run_nowait(struct audio_client *ac, uint32_t flags,
		uint32_t msw_ts, uint32_t lsw_ts);

int q6asm_stream_run_nowait(struct audio_client *ac, uint32_t flags,
		uint32_t msw_ts, uint32_t lsw_ts, uint32_t stream_id);

int q6asm_reg_tx_overflow(struct audio_client *ac, uint16_t enable);

int q6asm_reg_rx_underflow(struct audio_client *ac, uint16_t enable);

int q6asm_cmd(struct audio_client *ac, int cmd);

int q6asm_stream_cmd(struct audio_client *ac, int cmd, uint32_t stream_id);

int q6asm_cmd_nowait(struct audio_client *ac, int cmd);

int q6asm_stream_cmd_nowait(struct audio_client *ac, int cmd,
			    uint32_t stream_id);

void *q6asm_is_cpu_buf_avail(int dir, struct audio_client *ac,
				uint32_t *size, uint32_t *idx);

void *q6asm_is_cpu_buf_avail_nolock(int dir, struct audio_client *ac,
					uint32_t *size, uint32_t *idx);

int q6asm_is_dsp_buf_avail(int dir, struct audio_client *ac);

/* File format specific configurations to be added below */

int q6asm_enc_cfg_blk_pcm(struct audio_client *ac,
			uint32_t rate, uint32_t channels);

int q6asm_enc_cfg_blk_pcm_v2(struct audio_client *ac,
			uint32_t rate, uint32_t channels,
			uint16_t bits_per_sample,
			bool use_default_chmap, bool use_back_flavor,
			u8 *channel_map);

int q6asm_enc_cfg_blk_pcm_format_support(struct audio_client *ac,
			uint32_t rate, uint32_t channels,
			uint16_t bits_per_sample);

int q6asm_set_encdec_chan_map(struct audio_client *ac,
		uint32_t num_channels);

int q6asm_enc_cfg_blk_pcm_native(struct audio_client *ac,
			uint32_t rate, uint32_t channels);

int q6asm_enable_sbrps(struct audio_client *ac,
			uint32_t sbr_ps);

int q6asm_enc_cfg_blk_qcelp(struct audio_client *ac, uint32_t frames_per_buf,
		uint16_t min_rate, uint16_t max_rate,
		uint16_t reduced_rate_level, uint16_t rate_modulation_cmd);

int q6asm_enc_cfg_blk_evrc(struct audio_client *ac, uint32_t frames_per_buf,
		uint16_t min_rate, uint16_t max_rate,
		uint16_t rate_modulation_cmd);

int q6asm_enc_cfg_blk_amrnb(struct audio_client *ac, uint32_t frames_per_buf,
		uint16_t band_mode, uint16_t dtx_enable);

int q6asm_enc_cfg_blk_amrwb(struct audio_client *ac, uint32_t frames_per_buf,
		uint16_t band_mode, uint16_t dtx_enable);

int q6asm_media_format_block_pcm(struct audio_client *ac,
			uint32_t rate, uint32_t channels);

int q6asm_media_format_block_pcm_format_support(struct audio_client *ac,
			uint32_t rate, uint32_t channels,
			uint16_t bits_per_sample);

int q6asm_media_format_block_pcm_format_support_v2(struct audio_client *ac,
				uint32_t rate, uint32_t channels,
				uint16_t bits_per_sample, int stream_id,
				bool use_default_chmap, char *channel_map);

int q6asm_media_format_block_multi_ch_pcm(struct audio_client *ac,
			uint32_t rate, uint32_t channels,
			bool use_default_chmap, char *channel_map);

int q6asm_media_format_block_multi_ch_pcm_v2(
			struct audio_client *ac,
			uint32_t rate, uint32_t channels,
			bool use_default_chmap, char *channel_map,
			uint16_t bits_per_sample);

int q6asm_media_format_block_wma(struct audio_client *ac,
			void *cfg, int stream_id);

int q6asm_media_format_block_wmapro(struct audio_client *ac,
			void *cfg, int stream_id);

/* PP specific */
int q6asm_equalizer(struct audio_client *ac, void *eq);

/* Send Volume Command */
int q6asm_set_volume(struct audio_client *ac, int volume);

/* Send Volume Command */
int q6asm_set_volume_v2(struct audio_client *ac, int volume, int instance);

/* Send left-right channel gain */
int q6asm_set_lrgain(struct audio_client *ac, int left_gain, int right_gain);

/* Send multi channel gain */
int q6asm_set_multich_gain(struct audio_client *ac, uint32_t channels,
			   uint32_t *gains, uint8_t *ch_map, bool use_default);

/* Enable Mute/unmute flag */
int q6asm_set_mute(struct audio_client *ac, int muteflag);

int q6asm_get_session_time(struct audio_client *ac, uint64_t *tstamp);

/* Get Service ID for APR communication */
int q6asm_get_apr_service_id(int session_id);

/* Common format block without any payload
*/
int q6asm_media_format_block(struct audio_client *ac, uint32_t format);

/* Send the meta data to remove initial and trailing silence */
int q6asm_send_meta_data(struct audio_client *ac, uint32_t initial_samples,
		uint32_t trailing_samples);

/* Send the stream meta data to remove initial and trailing silence */
int q6asm_stream_send_meta_data(struct audio_client *ac, uint32_t stream_id,
		uint32_t initial_samples, uint32_t trailing_samples);

int q6asm_get_asm_topology(int session_id);
int q6asm_get_asm_app_type(int session_id);

int q6asm_send_mtmx_strtr_window(struct audio_client *ac,
		struct asm_session_mtmx_strtr_param_window_v2_t *window_param,
		uint32_t param_id);

/* Retrieve the current DSP path delay */
int q6asm_get_path_delay(struct audio_client *ac);

#endif /* __Q6_ASM_H__ */
