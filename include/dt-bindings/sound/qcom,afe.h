
#ifndef __DT_AFE_H__
#define __DT_AFE_H__

//FIXME Align with Indexes from downstream
#define AFE_PORT_HDMI_RX 		8

#define AFE_PORT_MAX		9

/*
 * Audio Front End (AFE)
 */

/* Port ID. Update afe_get_port_index when a new port is added here. */
#define PRIMARY_I2S_RX 0		/* index = 0 */
#define PRIMARY_I2S_TX 1		/* index = 1 */
#define PCM_RX 2			/* index = 2 */
#define PCM_TX 3			/* index = 3 */
#define SECONDARY_I2S_RX 4		/* index = 4 */
#define SECONDARY_I2S_TX 5		/* index = 5 */
#define MI2S_RX 6			/* index = 6 */
#define MI2S_TX 7			/* index = 7 */
#define HDMI_RX 8			/* index = 8 */
#define RSVD_2 9			/* index = 9 */
#define RSVD_3 10			/* index = 10 */
#define DIGI_MIC_TX 11			/* index = 11 */
#define VOICE2_PLAYBACK_TX 0x8002
#define VOICE_RECORD_RX 0x8003		/* index = 12 */
#define VOICE_RECORD_TX 0x8004		/* index = 13 */
#define VOICE_PLAYBACK_TX 0x8005	/* index = 14 */

/* Slimbus Multi channel port id pool  */
#define SLIMBUS_0_RX		0x4000
#define SLIMBUS_0_TX		0x4001
#define SLIMBUS_1_RX		0x4002
#define SLIMBUS_1_TX		0x4003
#define SLIMBUS_2_RX		0x4004
#define SLIMBUS_2_TX		0x4005
#define SLIMBUS_3_RX		0x4006
#define SLIMBUS_3_TX		0x4007
#define SLIMBUS_4_RX		0x4008
#define SLIMBUS_4_TX		0x4009
#define SLIMBUS_5_RX		0x400a
#define SLIMBUS_5_TX		0x400b
#define SLIMBUS_6_RX		0x400c
#define SLIMBUS_6_TX		0x400d
#define SLIMBUS_PORT_LAST	SLIMBUS_6_TX


#define INT_BT_SCO_RX 0x3000		/* index = 25 */
#define INT_BT_SCO_TX 0x3001		/* index = 26 */
#define INT_BT_A2DP_RX 0x3002		/* index = 27 */
#define INT_FM_RX 0x3004		/* index = 28 */
#define INT_FM_TX 0x3005		/* index = 29 */
#define RT_PROXY_PORT_001_RX	0x2000    /* index = 30 */
#define RT_PROXY_PORT_001_TX	0x2001    /* index = 31 */

#endif
