#ifndef __COMMON_H__
#define __COMMON_H__
extern struct device *apq8016_dev;
extern int smmu_exists;
extern int sid;

#define PCM_FORMAT_MAX_NUM_CHANNEL  8
#define PCM_CHANNEL_NULL 0

/* Front left channel. */
#define PCM_CHANNEL_FL    1

/* Front right channel. */
#define PCM_CHANNEL_FR    2

/* Front center channel. */
#define PCM_CHANNEL_FC    3

/* Left surround channel.*/
#define PCM_CHANNEL_LS   4

/* Right surround channel.*/
#define PCM_CHANNEL_RS   5

/* Low frequency effect channel. */
#define PCM_CHANNEL_LFE  6

/* Center surround channel; Rear center channel. */
#define PCM_CHANNEL_CS   7

/* Left back channel; Rear left channel. */
#define PCM_CHANNEL_LB   8

/* Right back channel; Rear right channel. */
#define PCM_CHANNEL_RB   9

/* Top surround channel. */
#define PCM_CHANNELS   10

/* Center vertical height channel.*/
#define PCM_CHANNEL_CVH  11

/* Mono surround channel.*/
#define PCM_CHANNEL_MS   12

/* Front left of center. */
#define PCM_CHANNEL_FLC  13

/* Front right of center. */
#define PCM_CHANNEL_FRC  14

/* Rear left of center. */
#define PCM_CHANNEL_RLC  15

/* Rear right of center. */
#define PCM_CHANNEL_RRC  16


enum {
	LEGACY_PCM_MODE = 0,
	LOW_LATENCY_PCM_MODE,
	ULTRA_LOW_LATENCY_PCM_MODE,
	ULL_POST_PROCESSING_PCM_MODE,
};


#endif /* __COMMON_H__*/
