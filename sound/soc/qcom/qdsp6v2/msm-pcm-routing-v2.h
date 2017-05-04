#ifndef _MSM_PCM_ROUTING_H
#define _MSM_PCM_ROUTING_H

enum msm_pcm_routing_event {
	MSM_PCM_RT_EVT_BUF_RECFG,
	MSM_PCM_RT_EVT_DEVSWITCH,
	MSM_PCM_RT_EVT_MAX,
};
struct msm_pcm_routing_evt {
	void (*event_func)(enum msm_pcm_routing_event, void *);
	void *priv_data;
};

int msm_pcm_routing_reg_phy_stream(int fedai_id, int perf_mode, int dspst_id,
				   int stream_type);
int msm_pcm_routing_reg_phy_stream_v2(int fedai_id, int perf_mode,
				      int dspst_id, int stream_type,
				      struct msm_pcm_routing_evt event_info);
void msm_pcm_routing_dereg_phy_stream(int fedai_id, int stream_type);

#endif /*_MSM_PCM_H*/
