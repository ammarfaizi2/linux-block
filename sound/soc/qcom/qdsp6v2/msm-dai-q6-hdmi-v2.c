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
/**
 * TODO:
 * Add HDMI CA support
 *
 */
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/of_device.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/soc.h>
//#include <sound/msm-dai-q6-v2.h>
#include <sound/pcm_params.h>
#include <dt-bindings/sound/qcom,afe.h>
#include "q6afe-v2.h"


struct msm_hdmi_ca {
	bool set_ca;
	u32 ca;
};

static struct msm_hdmi_ca hdmi_ca = { false, 0x0 };

struct msm_dai_q6_hdmi_dai_data {
	struct q6afe_port *port;
	struct q6afe_hdmi_cfg port_config;
};

static int msm_dai_q6_hdmi_format_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct msm_dai_q6_hdmi_dai_data *dai_data = kcontrol->private_data;
	int value = ucontrol->value.integer.value[0];
	
	dai_data->port_config.datatype = value;

	return 0;
}

static int msm_dai_q6_hdmi_format_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{

	struct msm_dai_q6_hdmi_dai_data *dai_data = kcontrol->private_data;

	ucontrol->value.integer.value[0] =
		dai_data->port_config.datatype;

	return 0;
}

static int msm_dai_q6_hdmi_ca_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	hdmi_ca.ca = ucontrol->value.integer.value[0];
	hdmi_ca.set_ca = true;
	return 0;
}

static int msm_dai_q6_hdmi_ca_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	ucontrol->value.integer.value[0] = hdmi_ca.ca;
	return 0;
}

/* HDMI format field for AFE_PORT_MULTI_CHAN_HDMI_AUDIO_IF_CONFIG command
 *  0: linear PCM
 *  1: non-linear PCM
 */
static const char * const hdmi_format[] = {
	"LPCM",
	"Compr"
};

static const struct soc_enum hdmi_config_enum[] = {
	SOC_ENUM_SINGLE_EXT(2, hdmi_format),
};

static const struct snd_kcontrol_new hdmi_config_controls[] = {
	SOC_ENUM_EXT("HDMI RX Format", hdmi_config_enum[0],
				 msm_dai_q6_hdmi_format_get,
				 msm_dai_q6_hdmi_format_put),
//	SOC_SINGLE_MULTI_EXT("HDMI RX CA", SND_SOC_NOPM, 0,
//				 HDMI_RX_CA_MAX, 0, 1,
//				 msm_dai_q6_hdmi_ca_get,
//				 msm_dai_q6_hdmi_ca_put),
};

/* Current implementation assumes hw_param is called once
 * This may not be the case but what to do when ADM and AFE
 * port are already opened and parameter changes
 */
static int msm_dai_q6_hdmi_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params,
				struct snd_soc_dai *dai)
{
	struct msm_dai_q6_hdmi_dai_data *dai_data = dev_get_drvdata(dai->dev);
	int channels = params_channels(params);

	dai_data->port_config.sample_rate = params_rate(params);
	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S16_LE:
		dai_data->port_config.bit_width = 16;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		dai_data->port_config.bit_width = 24;
		break;
	}

	/*refer to HDMI spec CEA-861-E: Table 28 Audio InfoFrame Data Byte 4*/
	switch (channels) {
	case 2:
		dai_data->port_config.channel_allocation = 0;
		break;
	case 3:
		dai_data->port_config.channel_allocation = 0x02;
		break;
	case 4:
		dai_data->port_config.channel_allocation = 0x06;
		break;
	case 5:
		dai_data->port_config.channel_allocation = 0x0A;
		break;
	case 6:
		dai_data->port_config.channel_allocation = 0x0B;
		break;
	case 7:
		dai_data->port_config.channel_allocation = 0x12;
		break;
	case 8:
		dai_data->port_config.channel_allocation = 0x13;
		break;
	default:
		dev_err(dai->dev, "invalid Channels = %u\n", channels);
		return -EINVAL;
	}

	return 0;
}

static void msm_dai_q6_hdmi_shutdown(struct snd_pcm_substream *substream,
				struct snd_soc_dai *dai)
{
	struct msm_dai_q6_hdmi_dai_data *dai_data = dev_get_drvdata(dai->dev);
	int rc = 0;

	rc = q6afe_port_stop(dai_data->port); /* can block */
	if (rc < 0)
		dev_err(dai->dev, "fail to close AFE port\n");

}

static int msm_dai_q6_hdmi_prepare(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct msm_dai_q6_hdmi_dai_data *dai_data = dev_get_drvdata(dai->dev);
	int rc = 0;

	rc = q6afe_hdmi_port_start(dai_data->port, &dai_data->port_config);
	if (rc <0)
		dev_err(dai->dev, "fail to open AFE port %x\n",	dai->id);

	return rc;
}

static inline void msm_dai_q6_hdmi_set_dai_id(struct snd_soc_dai *dai)
{
	if (!dai->driver->id) {
		dev_warn(dai->dev, "DAI driver id is not set\n");
		return;
	}
	dai->id = dai->driver->id;

	return;
}

static int msm_dai_q6_hdmi_dai_probe(struct snd_soc_dai *dai)
{
	struct msm_dai_q6_hdmi_dai_data *dai_data;
	const struct snd_kcontrol_new *kcontrol;
	int rc = 0;
	struct snd_soc_dapm_route intercon;
	struct q6afe_port *port;
	struct snd_soc_dapm_context *dapm = snd_soc_component_get_dapm(dai->component);

	if (!dai) {
		pr_err("%s: dai not found\n", __func__);
		return -EINVAL;
	}
	dai_data = kzalloc(sizeof(struct msm_dai_q6_hdmi_dai_data),
		GFP_KERNEL);

	if (!dai_data) {
		dev_err(dai->dev, "DAI-%d: fail to allocate dai data\n",
		dai->id);
		rc = -ENOMEM;
	}

	port = q6afe_port_get(dai->dev, "qcom,afe-port");

	if (IS_ERR(port)) {
		dev_err(dai->dev, "Unable to get afe port\n");
		return -EINVAL;
	}
	dai_data->port = port;	
	dev_set_drvdata(dai->dev, dai_data);
	msm_dai_q6_hdmi_set_dai_id(dai);

	kcontrol = &hdmi_config_controls[0];
	rc = snd_ctl_add(dai->component->card->snd_card,
					 snd_ctl_new1(kcontrol, dai_data));
	memset(&intercon, 0 , sizeof(intercon));
	if (!rc && dai && dai->driver) {
		if (dai->driver->playback.stream_name &&
			dai->driver->name) {
			dev_dbg(dai->dev, "%s add route for widget %s",
				   __func__, dai->driver->playback.stream_name);
			intercon.source = dai->driver->name;
			intercon.sink = dai->driver->playback.stream_name;
			dev_dbg(dai->dev, "%s src %s sink %s\n",
				   __func__, intercon.source, intercon.sink);
			snd_soc_dapm_add_routes(dapm, &intercon, 1);
		}
		if (dai->driver->capture.stream_name &&
		   dai->driver->name) {
			dev_dbg(dai->dev, "%s add route for widget %s",
				   __func__, dai->driver->capture.stream_name);
			intercon.sink = dai->driver->name;
			intercon.source = dai->driver->capture.stream_name;
			dev_dbg(dai->dev, "%s src %s sink %s\n",
				   __func__, intercon.source, intercon.sink);
			snd_soc_dapm_add_routes(dapm, &intercon, 1);
		}
	}

	return rc;
}

static int msm_dai_q6_hdmi_dai_remove(struct snd_soc_dai *dai)
{
	struct msm_dai_q6_hdmi_dai_data *dai_data;

	dai_data = dev_get_drvdata(dai->dev);
	kfree(dai_data);

	return 0;
}

static struct snd_soc_dai_ops msm_dai_q6_hdmi_ops = {
	.prepare	= msm_dai_q6_hdmi_prepare,
	.hw_params	= msm_dai_q6_hdmi_hw_params,
	.shutdown	= msm_dai_q6_hdmi_shutdown,
};

static struct snd_soc_dai_driver msm_dai_q6_hdmi_hdmi_rx_dai = {
	.playback = {
		.stream_name = "HDMI Playback",
		.rates = SNDRV_PCM_RATE_48000 | SNDRV_PCM_RATE_96000 |
		 SNDRV_PCM_RATE_192000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE,
		.channels_min = 2,
		.channels_max = 8,
		.rate_max =     192000,
		.rate_min =	48000,
	},
	.ops = &msm_dai_q6_hdmi_ops,
	.id = HDMI_RX,
	.probe = msm_dai_q6_hdmi_dai_probe,
	.remove = msm_dai_q6_hdmi_dai_remove,
	.name = "HDMI",
};

static const struct snd_soc_dapm_widget hdmi_dapm_widgets[] = {
	SND_SOC_DAPM_AIF_OUT("HDMI", "HDMI Playback", 0, 0, 0 , 0),	
	SND_SOC_DAPM_OUTPUT("HDMI-RX"),
};

static const struct snd_soc_component_driver msm_dai_hdmi_q6_component = {
	.name		= "msm-dai-q6-hdmi",
	.dapm_widgets = hdmi_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(hdmi_dapm_widgets),
};

static int msm_dai_q6_hdmi_dev_probe(struct platform_device *pdev)
{
	return snd_soc_register_component(&pdev->dev,
					  &msm_dai_hdmi_q6_component,
					  &msm_dai_q6_hdmi_hdmi_rx_dai, 1);
}

static int msm_dai_q6_hdmi_dev_remove(struct platform_device *pdev)
{
	snd_soc_unregister_component(&pdev->dev);
	return 0;
}

static const struct of_device_id msm_dai_q6_hdmi_dt_match[] = {
	{.compatible = "qcom,msm-dai-q6-hdmi"},
	{}
};
MODULE_DEVICE_TABLE(of, msm_dai_q6_hdmi_dt_match);

static struct platform_driver msm_dai_q6_hdmi_driver = {
	.probe  = msm_dai_q6_hdmi_dev_probe,
	.remove = msm_dai_q6_hdmi_dev_remove,
	.driver = {
		.name = "msm-dai-q6-hdmi",
		.owner = THIS_MODULE,
		.of_match_table = msm_dai_q6_hdmi_dt_match,
	},
};

module_platform_driver(msm_dai_q6_hdmi_driver);
