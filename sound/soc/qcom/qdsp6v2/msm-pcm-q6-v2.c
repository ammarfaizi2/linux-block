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
 * 	- move get iova address to this file and make specific to soc.
 */
#include <linux/init.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/pcm.h>
#include <asm/dma.h>
#include <linux/dma-mapping.h>
#include <dt-bindings/sound/qcom,asm.h>
#include <linux/of_device.h>
#include <sound/pcm_params.h>
//FIXME remove this dependency..
#include "q6asm-v2.h"
#include "msm-pcm-routing-v2.h"
#include "common.h"

#define PLAYBACK_MIN_NUM_PERIODS    2
#define PLAYBACK_MAX_NUM_PERIODS   8
#define PLAYBACK_MAX_PERIOD_SIZE    4096
#define PLAYBACK_MIN_PERIOD_SIZE    128

struct msm_audio {
	struct snd_pcm_substream *substream;
	void *data;
	dma_addr_t phys;
	unsigned int pcm_size;
	unsigned int pcm_count;
	unsigned int pcm_irq_pos;       /* IRQ position */
	uint16_t source; /* Encoding source bit mask */

	struct audio_client *audio_client;
	uint16_t session_id;

	int enabled;
	bool set_channel_map;
	char channel_map[8];
};

struct msm_plat_data {
	int perf_mode;
	u64 sid;
};

static struct snd_pcm_hardware msm_pcm_hardware_playback = {
	.info =                 (SNDRV_PCM_INFO_MMAP |
				SNDRV_PCM_INFO_BLOCK_TRANSFER |
				SNDRV_PCM_INFO_MMAP_VALID |
				SNDRV_PCM_INFO_INTERLEAVED |
				SNDRV_PCM_INFO_PAUSE | SNDRV_PCM_INFO_RESUME),
	.formats =              (SNDRV_PCM_FMTBIT_S16_LE |
				SNDRV_PCM_FMTBIT_S24_LE),
	.rates =                SNDRV_PCM_RATE_8000_192000,
	.rate_min =             8000,
	.rate_max =             192000,
	.channels_min =         1,
	.channels_max =         8,
	.buffer_bytes_max =     PLAYBACK_MAX_NUM_PERIODS *
				PLAYBACK_MAX_PERIOD_SIZE,
	.period_bytes_min =	PLAYBACK_MIN_PERIOD_SIZE,
	.period_bytes_max =     PLAYBACK_MAX_PERIOD_SIZE,
	.periods_min =          PLAYBACK_MIN_NUM_PERIODS,
	.periods_max =          PLAYBACK_MAX_NUM_PERIODS,
	.fifo_size =            0,
};

/* Conventional and unconventional sample rate supported */
static unsigned int supported_sample_rates[] = {
	8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000,
	88200, 96000, 176400, 192000
};

static struct snd_pcm_hw_constraint_list constraints_sample_rates = {
	.count = ARRAY_SIZE(supported_sample_rates),
	.list = supported_sample_rates,
	.mask = 0,
};

phys_addr_t set_iova_address(u64 sid, phys_addr_t addr)
{
	if (sid < 0)
		return addr;

	return (addr | (sid << 32));
}

static void event_handler(uint32_t opcode, uint32_t token,
			  uint32_t *payload, void *priv)
{
	struct msm_audio *prtd = priv;
	struct snd_pcm_substream *substream = prtd->substream;

	switch (opcode) {
	case ASM_DATA_EVENT_WRITE_DONE_V2: {
		prtd->pcm_irq_pos += prtd->pcm_count;
		snd_pcm_period_elapsed_irq(substream);
		//FIXME check if we are over feeding... here.
		q6asm_write_nolock(prtd->audio_client, prtd->pcm_count, 0, 0, NO_TIMESTAMP);

		break;
	}
	default:
		pr_err("Not Supported Event opcode[0x%x]\n", opcode);
		break;
	}
}

static int msm_pcm_prepare(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *soc_prtd = substream->private_data;
	struct msm_audio *prtd = runtime->private_data;
	struct snd_pcm_hw_params *params;
	struct msm_plat_data *pdata;
	uint16_t bits_per_sample = 16;
	int ret;

	pdata = dev_get_drvdata(soc_prtd->platform->dev);
	if (!pdata) {
		pr_err("%s: platform data not populated\n", __func__);
		return -EINVAL;
	}
	if (!prtd || !prtd->audio_client) {
		pr_err("%s: private data null or audio client freed\n",
			__func__);
		return -EINVAL;
	}
	params = &soc_prtd->dpcm[substream->stream].hw_params;

	prtd->pcm_size = snd_pcm_lib_buffer_bytes(substream);
	prtd->pcm_count = snd_pcm_lib_period_bytes(substream);
	prtd->pcm_irq_pos = 0;
	/* rate and channels are sent to audio driver */
	if (prtd->enabled)
		return 0;

	prtd->audio_client->perf_mode = pdata->perf_mode;

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S16_LE:
		bits_per_sample = 16;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		bits_per_sample = 24;
		break;
	}

	ret = q6asm_open_write_v2(prtd->audio_client, FORMAT_LINEAR_PCM, bits_per_sample);
	if (ret < 0) {
		pr_err("%s: q6asm_open_write_v2 failed\n", __func__);
		q6asm_audio_client_free(prtd->audio_client);
		prtd->audio_client = NULL;
		return -ENOMEM;
	}

	prtd->session_id = prtd->audio_client->session;
	ret = msm_pcm_routing_reg_phy_stream(soc_prtd->dai_link->id,
			prtd->audio_client->perf_mode,
			prtd->session_id, substream->stream);
	if (ret) {
		pr_err("%s: stream reg failed ret:%d\n", __func__, ret);
		return ret;
	}

	ret = q6asm_media_format_block_multi_ch_pcm_v2(
			prtd->audio_client, runtime->rate,
			runtime->channels, !prtd->set_channel_map,
			prtd->channel_map, bits_per_sample);
	if (ret < 0)
		pr_info("%s: CMD Format block failed\n", __func__);

	prtd->enabled = 1;

	return 0;
}

static int msm_pcm_trigger(struct snd_pcm_substream *substream, int cmd)
{
	int ret = 0;
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct msm_audio *prtd = runtime->private_data;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		pr_err("%s: Trigger start\n", __func__);
		ret = q6asm_run(prtd->audio_client, 0, 0, 0);
		q6asm_write_nolock(prtd->audio_client, prtd->pcm_count,	0, 0, NO_TIMESTAMP);
		break;
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		ret = q6asm_run(prtd->audio_client, 0, 0, 0);
		break;
	case SNDRV_PCM_TRIGGER_STOP:
		pr_err("SNDRV_PCM_TRIGGER_STOP\n");
		ret = q6asm_cmd(prtd->audio_client, CMD_EOS);
		break;
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		pr_err("SNDRV_PCM_TRIGGER_PAUSE\n");
		ret = q6asm_cmd(prtd->audio_client, CMD_PAUSE);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int msm_pcm_open(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *soc_prtd = substream->private_data;
	struct msm_audio *prtd;
	struct device *dev = soc_prtd->platform->dev;
	int ret = 0;

	prtd = kzalloc(sizeof(struct msm_audio), GFP_KERNEL);
	if (prtd == NULL) {
		pr_err("Failed to allocate memory for msm_audio\n");
		return -ENOMEM;
	}
	prtd->substream = substream;
	prtd->audio_client = q6asm_audio_client_alloc(dev,
				(app_cb)event_handler, prtd);
	if (!prtd->audio_client) {
		pr_info("%s: Could not allocate memory\n", __func__);
		kfree(prtd);
		return -ENOMEM;
	}

	prtd->audio_client->dev = dev;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		runtime->hw = msm_pcm_hardware_playback;

	ret = snd_pcm_hw_constraint_list(runtime, 0,
				SNDRV_PCM_HW_PARAM_RATE,
				&constraints_sample_rates);
	if (ret < 0)
		pr_info("snd_pcm_hw_constraint_list failed\n");
	/* Ensure that buffer size is a multiple of period size */
	ret = snd_pcm_hw_constraint_integer(runtime,
					    SNDRV_PCM_HW_PARAM_PERIODS);
	if (ret < 0)
		pr_info("snd_pcm_hw_constraint_integer failed\n");

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		ret = snd_pcm_hw_constraint_minmax(runtime,
			SNDRV_PCM_HW_PARAM_BUFFER_BYTES,
			PLAYBACK_MIN_NUM_PERIODS * PLAYBACK_MIN_PERIOD_SIZE,
			PLAYBACK_MAX_NUM_PERIODS * PLAYBACK_MAX_PERIOD_SIZE);
		if (ret < 0) {
			pr_err("constraint for buffer bytes min max ret = %d\n",
									ret);
		}
	}

	ret = snd_pcm_hw_constraint_step(runtime, 0,
		SNDRV_PCM_HW_PARAM_PERIOD_BYTES, 32);
	if (ret < 0) {
		pr_err("constraint for period bytes step ret = %d\n",
								ret);
	}
	ret = snd_pcm_hw_constraint_step(runtime, 0,
		SNDRV_PCM_HW_PARAM_BUFFER_BYTES, 32);
	if (ret < 0) {
		pr_err("constraint for buffer bytes step ret = %d\n",
								ret);
	}

	prtd->set_channel_map = false;
	runtime->private_data = prtd;

	return 0;
}

static int msm_pcm_close(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *soc_prtd = substream->private_data;
	struct msm_audio *prtd = runtime->private_data;
	int dir = 0;

	if (prtd->audio_client) {
		dir = IN;
		q6asm_cmd(prtd->audio_client, CMD_CLOSE);
		snd_dma_free_pages(&substream->dma_buffer);
		q6asm_audio_client_unmap_memory_regions(dir, prtd->audio_client);
		q6asm_audio_client_free(prtd->audio_client);
	}
	msm_pcm_routing_dereg_phy_stream(soc_prtd->dai_link->id,
						SNDRV_PCM_STREAM_PLAYBACK);
	kfree(prtd);
	return 0;
}

static snd_pcm_uframes_t msm_pcm_pointer(struct snd_pcm_substream *substream)
{

	struct snd_pcm_runtime *runtime = substream->runtime;
	struct msm_audio *prtd = runtime->private_data;

	if (prtd->pcm_irq_pos >= prtd->pcm_size)
		prtd->pcm_irq_pos = 0;

	return bytes_to_frames(runtime, (prtd->pcm_irq_pos));
}

static int msm_pcm_mmap(struct snd_pcm_substream *substream,
				struct vm_area_struct *vma)
{

	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *soc_prtd = substream->private_data;

	return dma_mmap_coherent(soc_prtd->platform->dev, vma,
			runtime->dma_area, runtime->dma_addr,
			runtime->dma_bytes);
}

static int msm_pcm_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct msm_audio *prtd = runtime->private_data;
	struct snd_soc_pcm_runtime *soc_prtd = substream->private_data;
	struct device *dev = soc_prtd->platform->dev;
	struct msm_plat_data *pdata;
	int dir, ret;

	pdata = dev_get_drvdata(dev);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		dir = IN;
	else
		dir = OUT;
	prtd->pcm_size = params_buffer_bytes(params);

	ret = snd_dma_alloc_pages(SNDRV_DMA_TYPE_DEV, dev, prtd->pcm_size,
				  &substream->dma_buffer);
	if (ret) {
		dev_err(dev, "Cannot allocate buffer(s)\n");
		return ret;
	}

	prtd->data = substream->dma_buffer.area; 
	prtd->phys = set_iova_address(pdata->sid, substream->dma_buffer.addr); 
	ret = q6asm_audio_client_map_memory_regions(dir,
			prtd->audio_client,
			prtd->data, prtd->phys,
			(params_buffer_bytes(params) / params_periods(params)),
			 params_periods(params));

	if (ret < 0) {
		pr_err("Audio Start: Buffer Allocation failed rc = %d\n",
							ret);
		return -ENOMEM;
	}

	snd_pcm_set_runtime_buffer(substream, &substream->dma_buffer);
	return 0;
}

static struct snd_pcm_ops msm_pcm_ops = {
	.open           = msm_pcm_open,
	.hw_params	= msm_pcm_hw_params,
	.close          = msm_pcm_close,
	.ioctl          = snd_pcm_lib_ioctl,
	.prepare        = msm_pcm_prepare,
	.trigger        = msm_pcm_trigger,
	.pointer        = msm_pcm_pointer,
	.mmap		= msm_pcm_mmap,
};
static int msm_asoc_pcm_new(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_card *card = rtd->card->snd_card;
	int ret = 0;

	if (!card->dev->coherent_dma_mask)
		card->dev->coherent_dma_mask = DMA_BIT_MASK(32);

	return ret;
}

static struct snd_soc_platform_driver msm_soc_platform = {
	.ops		= &msm_pcm_ops,
	.pcm_new	= msm_asoc_pcm_new,
};

static const struct snd_soc_dapm_route afe_pcm_routes[] = {
	{"MM_DL1",  NULL, "MultiMedia1 Playback" },
	{"MM_DL2",  NULL, "MultiMedia2 Playback" },

};

static int fe_dai_probe(struct snd_soc_dai *dai)
{
	struct snd_soc_dapm_context *dapm = snd_soc_component_get_dapm(dai->component);
	
	snd_soc_dapm_add_routes(dapm, afe_pcm_routes, ARRAY_SIZE(afe_pcm_routes));

	return 0;
}

static const struct snd_soc_component_driver msm_fe_dai_component = {
	.name		= "msm-dai-fe",
};

//FIXME for now its just 2 FE's for testing purpose.
static struct snd_soc_dai_driver msm_fe_dais[] = {
	{
		.playback = {
			.stream_name = "MultiMedia1 Playback",
			.rates = (SNDRV_PCM_RATE_8000_192000|
					SNDRV_PCM_RATE_KNOT),
			.formats = (SNDRV_PCM_FMTBIT_S16_LE |
						SNDRV_PCM_FMTBIT_S24_LE),
			.channels_min = 1,
			.channels_max = 8,
			.rate_min =     8000,
			.rate_max =	192000,
		},
		.name = "MM_DL1",
		.probe = fe_dai_probe,
		.id = MSM_FRONTEND_DAI_MULTIMEDIA1,
	},
	{
		.playback = {
			.stream_name = "MultiMedia2 Playback",
			.rates = (SNDRV_PCM_RATE_8000_192000|
					SNDRV_PCM_RATE_KNOT),
			.formats = (SNDRV_PCM_FMTBIT_S16_LE |
						SNDRV_PCM_FMTBIT_S24_LE),
			.channels_min = 1,
			.channels_max = 8,
			.rate_min =     8000,
			.rate_max =	192000,
		},
		.name = "MM_DL2",
		.probe = fe_dai_probe,
		.id = MSM_FRONTEND_DAI_MULTIMEDIA2,
	},
};

static int msm_pcm_probe(struct platform_device *pdev)
{
	struct msm_plat_data *pdata;
	const char *latency_level;
	struct device *dev = &pdev->dev;
	struct of_phandle_args args;
	struct device_node *node = dev->of_node;
	int rc;

	pdata = devm_kzalloc(dev, sizeof(struct msm_plat_data), GFP_KERNEL);
	if (!pdata) {
		dev_err(&pdev->dev, "Failed to allocate memory for platform data\n");
		return -ENOMEM;
	}

	if (of_property_read_bool(node,	"qcom,msm-pcm-low-latency")) {
		pdata->perf_mode = LOW_LATENCY_PCM_MODE;
		rc = of_property_read_string(node, "qcom,latency-level", &latency_level);
		if (!rc) {
			if (!strcmp(latency_level, "ultra"))
				pdata->perf_mode = ULTRA_LOW_LATENCY_PCM_MODE;
			else if (!strcmp(latency_level, "ull-pp"))
				pdata->perf_mode = ULL_POST_PROCESSING_PCM_MODE;
		}
	}
	else
		pdata->perf_mode = LEGACY_PCM_MODE;


	rc = of_parse_phandle_with_fixed_args(node, "iommus", 1, 0, &args);
	if (rc < 0) {
		pdata->sid = -1;
	} else {
		pdata->sid = args.args[0];
	}

	dev_set_drvdata(dev, pdata);

	rc = snd_soc_register_platform(dev,  &msm_soc_platform);
	if (rc) {
		dev_err(&pdev->dev, "err_dai_platform\n");
		return rc;
	}

	rc = snd_soc_register_component(dev, &msm_fe_dai_component, msm_fe_dais, ARRAY_SIZE(msm_fe_dais));
	if (rc)
		dev_err(dev, "err_dai_component\n");

	return rc;

}

static int msm_pcm_remove(struct platform_device *pdev)
{
	snd_soc_unregister_platform(&pdev->dev);

	return 0;
}
static const struct of_device_id msm_pcm_dt_match[] = {
	{.compatible = "qcom,msm8996-pcm-dsp"},
	{.compatible = "qcom,msm-pcm-dsp"},
	{}
};
MODULE_DEVICE_TABLE(of, msm_pcm_dt_match);

static struct platform_driver msm_pcm_driver = {
	.driver = {
		.name = "msm-pcm-dsp",
		.owner = THIS_MODULE,
		.of_match_table = msm_pcm_dt_match,
	},
	.probe = msm_pcm_probe,
	.remove = msm_pcm_remove,
};

module_platform_driver(msm_pcm_driver);

MODULE_DESCRIPTION("PCM module platform driver");
MODULE_LICENSE("GPL v2");
