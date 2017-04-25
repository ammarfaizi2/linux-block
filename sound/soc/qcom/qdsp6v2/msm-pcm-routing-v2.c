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

#include <linux/init.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include <linux/slab.h>
#include <sound/core.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/pcm.h>
#include <sound/control.h>
#include <sound/asound.h>
#include <sound/pcm_params.h>
//#include <sound/q6core.h>
#include <dt-bindings/sound/qcom,afe.h>
#include <dt-bindings/sound/qcom,asm.h>
#include "q6afe-v2.h"
#include "q6adm-v2.h"
#include "msm-pcm-routing-v2.h"

struct msm_routing_session_data {
	int state;
	//[session-id] = { afe-port id, path-type, app_type, acdb, sample rate, bits per sample, perf mode, numcopps, copps.},
	int port_id;
	int path_type;
	int app_type;
	int acdb_id;
	int sample_rate;
	int bits_per_sample;
	int channels;
	int format;
	int perf_mode;
	int numcopps;
	int fedai_id;
	unsigned long copp_map;

};

#define MAX_SESSIONS	16

struct msm_routing_data {
	struct msm_routing_session_data sessions[MAX_SESSIONS];
	struct mutex lock;
};
struct msm_routing_data routing_data;

int msm_pcm_routing_reg_phy_stream(int fedai_id, int perf_mode, int dspst_id, int stream_type)
{
	int j, topology, num_copps = 0;
	struct route_payload payload;
	int copp_idx;
	struct msm_routing_session_data *session = &routing_data.sessions[dspst_id - 1];

	mutex_lock(&routing_data.lock);
	session->fedai_id = fedai_id;
	payload.num_copps = 0; /* only RX needs to use payload */
	topology = NULL_COPP_TOPOLOGY;
			
	copp_idx = adm_open(session->port_id, session->path_type, session->sample_rate, session->channels, topology, perf_mode, session->bits_per_sample, 0, 0);
	if ((copp_idx < 0) || (copp_idx >= MAX_COPPS_PER_PORT)) {
		pr_err("%s: adm open failed copp_idx:%d\n", __func__, copp_idx);
		mutex_unlock(&routing_data.lock);
		return -EINVAL;
	}

	set_bit(copp_idx, &session->copp_map);
	for (j = 0; j < MAX_COPPS_PER_PORT; j++) {
		unsigned long copp = session->copp_map;
		if (test_bit(j, &copp)) {
			payload.port_id[num_copps] = session->port_id;
			payload.copp_idx[num_copps] = j;
			num_copps++;
		}
	}

	if (num_copps) {
		payload.num_copps = num_copps;
		payload.session_id = dspst_id;//fe_dai_map[fedai_id][session_type].strm_id;
		payload.app_type = 0;//fe_dai_app_type_cfg[fedai_id].app_type;
		payload.acdb_dev_id = 0;// fe_dai_app_type_cfg[fedai_id].acdb_dev_id;
		payload.sample_rate = session->sample_rate;
		adm_matrix_map(session->path_type, payload, perf_mode);
		//msm_pcm_routng_cfg_matrix_map_pp(payload, path_type, perf_mode);
	}
	mutex_unlock(&routing_data.lock);

	return 0;
}

int msm_pcm_routing_reg_phy_stream_v2(int fedai_id, int perf_mode,
				      int dspst_id, int stream_type,
				      struct msm_pcm_routing_evt event_info)
{
	if (msm_pcm_routing_reg_phy_stream(fedai_id, perf_mode, dspst_id,
				       stream_type)) {
		pr_err("%s: failed to reg phy stream\n", __func__);
		return -EINVAL;
	}

	return 0;
}

struct msm_routing_session_data *msm_pcm_routing_get_session_data(struct msm_routing_data *data, int port_id, int port_type)
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		if (port_id == data->sessions[i].port_id) {
			return &data->sessions[i];
		}
	}
	
			//&& (port_type == data->sessions[i].port_type))
	return NULL;
}

struct msm_routing_session_data *get_session_from_fedai_id(struct msm_routing_data *data, int fedai_id)
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		if (fedai_id == data->sessions[i].fedai_id) {
			return &data->sessions[i];
		}
	}
	
			//&& (port_type == data->sessions[i].port_type))
	return NULL;
}

void msm_pcm_routing_dereg_phy_stream(int fedai_id, int stream_type)
{
	struct msm_routing_session_data *session = get_session_from_fedai_id(&routing_data, fedai_id);
	int idx;

	if (!session)
		return;

	for_each_set_bit(idx, &session->copp_map, MAX_COPPS_PER_PORT)
		adm_close(session->port_id, session->perf_mode, idx);

//	session->port_id = -1;
	session->fedai_id = -1;
	session->copp_map = 0;

	return;
}

static int msm_routing_get_audio_mixer(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_context *dapm = snd_soc_dapm_kcontrol_dapm(kcontrol);
	struct soc_mixer_control *mc =
	(struct soc_mixer_control *)kcontrol->private_value;
	int session_id  = mc->shift;
	struct snd_soc_platform *platform = snd_soc_dapm_to_platform(dapm);
	struct msm_routing_data *priv = snd_soc_platform_get_drvdata(platform);
	struct msm_routing_session_data *session = &priv->sessions[session_id];

	if (session->port_id != -1)
		ucontrol->value.integer.value[0] = 1;
	else
		ucontrol->value.integer.value[0] = 0;

	pr_debug("%s: reg %x shift %x val %ld\n", __func__, mc->reg, mc->shift,
	ucontrol->value.integer.value[0]);

	return 0;
}

static int msm_routing_put_audio_mixer(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_context *dapm = snd_soc_dapm_kcontrol_dapm(kcontrol);
	struct snd_soc_platform *platform = snd_soc_dapm_to_platform(dapm);
	struct msm_routing_data *data = snd_soc_platform_get_drvdata(platform);
	struct soc_mixer_control *mc =
		(struct soc_mixer_control *)kcontrol->private_value;
	struct snd_soc_dapm_update *update = NULL;
	int be_id = mc->reg;
	int session_id  = mc->shift;
	struct msm_routing_session_data *session = &data->sessions[session_id];

	if (ucontrol->value.integer.value[0]) {
		session->port_id = be_id;//q6afe_get_port_id(be_id);

	//	msm_pcm_routing_process_audio(mc->reg, mc->shift, 1);
	//	FIXME
		snd_soc_dapm_mixer_update_power(dapm, kcontrol, 1, update);
	} else {
		session->port_id = -1;
//		msm_pcm_routing_process_audio(mc->reg, mc->shift, 0);
		snd_soc_dapm_mixer_update_power(dapm, kcontrol, 0, update);
	}

	return 1;
}

//FIXME ..
static const struct snd_kcontrol_new hdmi_mixer_controls[] = {
	SOC_SINGLE_EXT("MultiMedia1", AFE_PORT_HDMI_RX,
	MSM_FRONTEND_DAI_MULTIMEDIA1, 1, 0, msm_routing_get_audio_mixer,
	msm_routing_put_audio_mixer),
	SOC_SINGLE_EXT("MultiMedia2", AFE_PORT_HDMI_RX,
	MSM_FRONTEND_DAI_MULTIMEDIA2, 1, 0, msm_routing_get_audio_mixer,
	msm_routing_put_audio_mixer),
	SOC_SINGLE_EXT("MultiMedia3", AFE_PORT_HDMI_RX,
	MSM_FRONTEND_DAI_MULTIMEDIA3, 1, 0, msm_routing_get_audio_mixer,
	msm_routing_put_audio_mixer),
	SOC_SINGLE_EXT("MultiMedia4", AFE_PORT_HDMI_RX,
	MSM_FRONTEND_DAI_MULTIMEDIA4, 1, 0, msm_routing_get_audio_mixer,
	msm_routing_put_audio_mixer),
	SOC_SINGLE_EXT("MultiMedia5", AFE_PORT_HDMI_RX,
	MSM_FRONTEND_DAI_MULTIMEDIA5, 1, 0, msm_routing_get_audio_mixer,
	msm_routing_put_audio_mixer),
	SOC_SINGLE_EXT("MultiMedia6", AFE_PORT_HDMI_RX,
	MSM_FRONTEND_DAI_MULTIMEDIA6, 1, 0, msm_routing_get_audio_mixer,
	msm_routing_put_audio_mixer),
	SOC_SINGLE_EXT("MultiMedia7", AFE_PORT_HDMI_RX,
	MSM_FRONTEND_DAI_MULTIMEDIA7, 1, 0, msm_routing_get_audio_mixer,
	msm_routing_put_audio_mixer),
	SOC_SINGLE_EXT("MultiMedia8", AFE_PORT_HDMI_RX,
	MSM_FRONTEND_DAI_MULTIMEDIA8, 1, 0, msm_routing_get_audio_mixer,
	msm_routing_put_audio_mixer),
};

static const struct snd_soc_dapm_widget msm_qdsp6_widgets[] = {
	/* Frontend AIF */
	/* Widget name equals to Front-End DAI name<Need confirmation>,
	 * Stream name must contains substring of front-end dai name
	 */
	SND_SOC_DAPM_AIF_IN("MM_DL1", "MultiMedia1 Playback", 0, 0, 0, 0),

	SND_SOC_DAPM_AIF_IN("MM_DL2", "MultiMedia2 Playback", 0, 0, 0, 0),
	SND_SOC_DAPM_AIF_IN("MM_DL3", "MultiMedia3 Playback", 0, 0, 0, 0),
	SND_SOC_DAPM_AIF_IN("MM_DL4", "MultiMedia4 Playback", 0, 0, 0, 0),
	SND_SOC_DAPM_AIF_IN("MM_DL5", "MultiMedia5 Playback", 0, 0, 0, 0),
	SND_SOC_DAPM_AIF_IN("MM_DL6", "MultiMedia6 Playback", 0, 0, 0, 0),
	SND_SOC_DAPM_AIF_IN("MM_DL7", "MultiMedia7 Playback", 0, 0, 0, 0),
	SND_SOC_DAPM_AIF_IN("MM_DL8", "MultiMedia8 Playback", 0, 0, 0, 0),

	/* Mixer definitions */
	SND_SOC_DAPM_MIXER("HDMI Mixer", SND_SOC_NOPM, 0, 0, hdmi_mixer_controls, ARRAY_SIZE(hdmi_mixer_controls)),
	/* Virtual Pins to force backends ON atm */
//	SND_SOC_DAPM_OUTPUT("BE_OUT"),
};

static const struct snd_soc_dapm_route intercon[] = {
	{"HDMI Mixer", "MultiMedia1", "MM_DL1"},
	{"HDMI Mixer", "MultiMedia2", "MM_DL2"},
	{"HDMI Mixer", "MultiMedia3", "MM_DL3"},
	{"HDMI Mixer", "MultiMedia4", "MM_DL4"},
	{"HDMI Mixer", "MultiMedia5", "MM_DL5"},
	{"HDMI Mixer", "MultiMedia6", "MM_DL6"},
	{"HDMI Mixer", "MultiMedia7", "MM_DL7"},
	{"HDMI Mixer", "MultiMedia8", "MM_DL8"},
	{"HDMI", NULL, "HDMI Mixer"},
	/* Backend Enablement */
//	{"BE_OUT", NULL, "HDMI"},
	//FIXME should go to machine driver
	{"HDMI-RX", NULL, "HDMI"},
};

static int msm_pcm_routing_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	//unsigned int be_id = rtd->dai_link->be_id;
	unsigned int be_id = rtd->dai_link->id;
	struct snd_soc_platform *platform = rtd->platform;
	struct msm_routing_data *data = snd_soc_platform_get_drvdata(platform);
	struct msm_routing_session_data *session;
	int port_id, port_type, path_type, bits_per_sample;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
//		session_type = SESSION_TYPE_RX;
		path_type = ADM_PATH_PLAYBACK;
		port_type = MSM_AFE_PORT_TYPE_RX;
	} else {
		//session_type = SESSION_TYPE_TX;
		path_type = ADM_PATH_LIVE_REC;
		port_type = MSM_AFE_PORT_TYPE_TX;
	}

	port_id = be_id;//q6afe_get_port_id(be_id);

	session = msm_pcm_routing_get_session_data(data, port_id, port_type);

	if (!session) {
		pr_err("No session matrix setup yet.. \n");
		return -EINVAL;
	}

	mutex_lock(&data->lock);

	session->path_type = path_type;
	session->sample_rate = params_rate(params);	
	session->channels = params_channels(params);
	session->format = params_format(params);

	if (session->format == SNDRV_PCM_FORMAT_S16_LE)
		session->bits_per_sample = 16;
	else if (session->format == SNDRV_PCM_FORMAT_S24_LE)
		bits_per_sample = 24;

	pr_debug("%s: port id %d session  BE Sample Rate (%d) format (%d) be_id %d\n",
		__func__, session->port_id, session->sample_rate,
		session->format, be_id);
	mutex_unlock(&data->lock);
	return 0;
}

static int msm_pcm_routing_close(struct snd_pcm_substream *substream)
{
	return 0;
}

static int msm_pcm_routing_prepare(struct snd_pcm_substream *substream)
{
	return 0;
}

static struct snd_pcm_ops msm_routing_pcm_ops = {
	.hw_params	= msm_pcm_routing_hw_params,
	.close          = msm_pcm_routing_close,
	.prepare        = msm_pcm_routing_prepare,
};

/* Not used but frame seems to require it */
static int msm_routing_probe(struct snd_soc_platform *platform)
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		routing_data.sessions[i].port_id = -1;
	}
	snd_soc_platform_set_drvdata(platform, &routing_data);
	return 0;
}
static struct snd_soc_platform_driver msm_soc_routing_platform = {
	.ops		= &msm_routing_pcm_ops,
	.probe		= msm_routing_probe,
	.component_driver = {
		.dapm_widgets = msm_qdsp6_widgets,
		.num_dapm_widgets = ARRAY_SIZE(msm_qdsp6_widgets),
		.dapm_routes = intercon,
		.num_dapm_routes = ARRAY_SIZE(intercon),
	},
};

static int msm_routing_pcm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	mutex_init(&routing_data.lock);

	return snd_soc_register_platform(dev, &msm_soc_routing_platform);
}

static int msm_routing_pcm_remove(struct platform_device *pdev)
{
	snd_soc_unregister_platform(&pdev->dev);
	return 0;
}

static const struct of_device_id msm_pcm_routing_dt_match[] = {
	{.compatible = "qcom,msm-pcm-routing"},
	{}
};
MODULE_DEVICE_TABLE(of, msm_pcm_routing_dt_match);

static struct platform_driver msm_routing_pcm_driver = {
	.driver = {
		.name = "msm-pcm-routing",
		.owner = THIS_MODULE,
		.of_match_table = msm_pcm_routing_dt_match,
	},
	.probe = msm_routing_pcm_probe,
	.remove = msm_routing_pcm_remove,
};
module_platform_driver(msm_routing_pcm_driver);

MODULE_DESCRIPTION("MSM routing platform driver");
MODULE_LICENSE("GPL v2");
