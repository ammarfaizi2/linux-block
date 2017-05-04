
#include <linux/clk.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/pcm.h>
#include <linux/dma-mapping.h>
#include <dt-bindings/sound/qcom,afe.h>
#include <dt-bindings/sound/qcom,asm.h>
//#include "qdsp6v2/common.h"

static int msm_hdmi_rx_ch = 2;
static int hdmi_rate_variable;

static const char *hdmi_rx_ch_text[] = {"Two", "Three", "Four", "Five",
	"Six", "Seven", "Eight"};
static const char * const hdmi_rate[] = {"Default", "Variable"};

static const struct soc_enum msm_enum[] = {
	SOC_ENUM_SINGLE_EXT(7, hdmi_rx_ch_text),
	SOC_ENUM_SINGLE_EXT(2, hdmi_rate),
};

static int msm_hdmi_rx_ch_get(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	ucontrol->value.integer.value[0] = msm_hdmi_rx_ch - 2;
	return 0;
}

static int msm_hdmi_rx_ch_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	msm_hdmi_rx_ch = ucontrol->value.integer.value[0] + 2;
	return 1;
}
	
static int msm_hdmi_rate_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	hdmi_rate_variable = ucontrol->value.integer.value[0];
	return 0;
}

static int msm_hdmi_rate_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	ucontrol->value.integer.value[0] = hdmi_rate_variable;
	return 0;
}

static const struct snd_kcontrol_new tabla_msm_controls[] = {
	SOC_ENUM_EXT("HDMI_RX Channels", msm_enum[0],
		msm_hdmi_rx_ch_get, msm_hdmi_rx_ch_put),
	SOC_ENUM_EXT("HDMI RX Rate", msm_enum[1],
					msm_hdmi_rate_get,
					msm_hdmi_rate_put),
};

int hdmi_rx_bit_format = SNDRV_PCM_FORMAT_S16_LE;

#define SAMPLING_RATE_48KHZ     48000
int hdmi_rx_sample_rate = SAMPLING_RATE_48KHZ;

inline int param_is_mask(int p)
{
	return (p >= SNDRV_PCM_HW_PARAM_FIRST_MASK) &&
			(p <= SNDRV_PCM_HW_PARAM_LAST_MASK);
}

inline struct snd_mask *param_to_mask(struct snd_pcm_hw_params *p,
					     int n)
{
	return &(p->masks[n - SNDRV_PCM_HW_PARAM_FIRST_MASK]);
}

void param_set_mask(struct snd_pcm_hw_params *p, int n, unsigned bit)
{
	if (bit >= SNDRV_MASK_MAX)
		return;
	if (param_is_mask(n)) {
		struct snd_mask *m = param_to_mask(p, n);
		m->bits[0] = 0;
		m->bits[1] = 0;
		m->bits[bit >> 5] |= (1 << (bit & 31));
	}
}

int msm8996_hdmi_be_hw_params_fixup(struct snd_soc_pcm_runtime *rtd,
					      struct snd_pcm_hw_params *params)
{
	struct snd_interval *rate = hw_param_interval(params,
					SNDRV_PCM_HW_PARAM_RATE);
	struct snd_interval *channels = hw_param_interval(params,
					SNDRV_PCM_HW_PARAM_CHANNELS);

	param_set_mask(params, SNDRV_PCM_HW_PARAM_FORMAT,
				hdmi_rx_bit_format);
	if (channels->max < 2)
		channels->min = channels->max = 2;
	rate->min = rate->max = hdmi_rx_sample_rate;
	channels->min = channels->max = msm_hdmi_rx_ch;

	return 0;
}

static int apq8096_sbc_parse_of(struct snd_soc_card *card)
{
	struct device *dev = card->dev;
	struct snd_soc_dai_link *link;
	struct device_node *np, *codec, *platform, *cpu, *node  = dev->of_node;
//	struct apq8096_sbc_data *data;
	int ret, num_links;
	bool is_fe;

	ret = snd_soc_of_parse_card_name(card, "qcom,model");
	if (ret) {
		dev_err(dev, "Error parsing card name: %d\n", ret);
		return ret;
	}
#if 0
	/* DAPM routes */
	if (of_property_read_bool(node, "qcom,audio-routing")) {
		ret = snd_soc_of_parse_audio_routing(card,
					"qcom,audio-routing");
		if (ret)
			return ERR_PTR(ret);
	}

#endif
	/* Populate links */
	num_links = of_get_child_count(node);

	/* Allocate the private data and the DAI link array */
	card->dai_link = devm_kzalloc(dev, sizeof(*link) * num_links,   GFP_KERNEL);
	if (!card->dai_link)
		return -ENOMEM;

	card->num_links	= num_links;

	link = &card->dai_link[0];

	for_each_child_of_node(node, np) {
		is_fe = false;
		if (of_property_read_bool(np, "is-fe"))
			is_fe = true;

		if (is_fe) {
			/* BE is dummy */
			link->codec_of_node	= NULL;
			link->codec_dai_name	= "snd-soc-dummy-dai";
			link->codec_name	= "snd-soc-dummy";

			/* FE settings */
			link->dynamic		= 1;
			link->nonatomic		= 1;
			link->dpcm_playback = 1;

		}else {
			link->no_pcm = 1;
			link->dpcm_playback = 1;
			link->be_hw_params_fixup = msm8996_hdmi_be_hw_params_fixup;
		}

		of_property_read_u32(np, "id", &link->id);
		cpu = of_get_child_by_name(np, "cpu");
		platform = of_get_child_by_name(np, "platform");
		codec = of_get_child_by_name(np, "codec");

		if (!cpu) {
			dev_err(dev, "Can't find cpu DT node\n");
			return -EINVAL;
		}

		link->cpu_of_node = of_parse_phandle(cpu, "sound-dai", 0);
		if (!link->cpu_of_node) {
			dev_err(card->dev, "error getting cpu phandle\n");
			return -EINVAL;
		}
		
		link->platform_of_node = of_parse_phandle(platform, "sound-dai", 0);
		if (!link->platform_of_node) {
			dev_err(card->dev, "error getting platform phandle\n");
			return -EINVAL;
		}

		ret = snd_soc_of_get_dai_name(cpu, &link->cpu_dai_name);
		if (ret) {
			dev_err(card->dev, "error getting cpu dai name\n");
			return ret;
		}

		if (codec) {
			ret = snd_soc_of_get_dai_link_codecs(dev, codec, link);

			if (ret < 0) {
				dev_err(card->dev, "error getting codec dai name\n");
				return ret;
			}
		}

		ret = of_property_read_string(np, "link-name", &link->name);
		if (ret) {
			dev_err(card->dev, "error getting codec dai_link name\n");
			return ret;
		}

		link->stream_name = link->name;
		link++;
	}

	return 0;
}
static struct snd_soc_card snd_soc_card_msm = {
	.name		= "apq8096-tabla-snd-card",
	.owner 		= THIS_MODULE,
	.controls = tabla_msm_controls,
	.num_controls = ARRAY_SIZE(tabla_msm_controls),
};

static int msm_snd_apq8096_probe(struct platform_device *pdev)
{
	int ret;
	snd_soc_card_msm.dev = &pdev->dev;
	
	apq8096_sbc_parse_of(&snd_soc_card_msm);

	ret = snd_soc_register_card(&snd_soc_card_msm);
	if (ret)
		dev_err(&pdev->dev, "Error: snd_soc_register_card failed (%d)!\n", ret);

	return ret;
}

static  int msm_snd_apq8096_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id msm_snd_apq8096_dt_match[] = {
	{.compatible = "qcom,snd-apq8096"},
	{}
};

static struct platform_driver msm_snd_apq8096_driver = {
	.probe  = msm_snd_apq8096_probe,
	.remove = msm_snd_apq8096_remove,
	.driver = {
		.name = "msm-snd-apq8096",
		.owner = THIS_MODULE,
		.of_match_table = msm_snd_apq8096_dt_match,
	},
};
module_platform_driver(msm_snd_apq8096_driver);
/* Module information */

MODULE_DESCRIPTION("ALSA SoC msm");
MODULE_LICENSE("GPL v2");
