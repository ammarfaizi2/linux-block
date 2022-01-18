#define DEBUG

#include <linux/clk.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_clk.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/of_dma.h>
#include <linux/reset.h>
#include <linux/dma-mapping.h>

#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/dmaengine_pcm.h>


/* relative to cluster base */
#define REG_STATUS		0x0
#define STATUS_MCLK_EN		BIT(0)
#define REG_MCLK_CONF		0x4
#define MCLK_CONF_DIV		GENMASK(11, 8)

#define REG_SYNCGEN_STATUS	0x100
#define SYNCGEN_STATUS_EN	BIT(0)
#define REG_SYNCGEN_MCLK_SEL	0x104
#define SYNCGEN_MCLK_SEL	GENMASK(3, 0)
#define REG_SYNCGEN_HI_PERIOD	0x108
#define REG_SYNCGEN_LO_PERIOD	0x10c

#define REG_PORT_ENABLES	0x600
#define PORT_ENABLES_CLOCKS	GENMASK(2, 1)
#define PORT_ENABLES_TX_DATA	BIT(3)
#define REG_PORT_CLOCK_SEL	0x604
#define PORT_CLOCK_SEL		GENMASK(11, 8)
#define REG_PORT_DATA_SEL	0x608
#define PORT_DATA_SEL_TXA(cl)	(1 << ((cl)*2))
#define PORT_DATA_SEL_TXB(cl)	(2 << ((cl)*2))

/* bases of serdes units (relative to cluster) */
#define CLUSTER_RXA_OFF	0x200
#define CLUSTER_TXA_OFF	0x300
#define CLUSTER_RXB_OFF	0x400
#define CLUSTER_TXB_OFF	0x500

/* relative to serdes unit base */
#define REG_SERDES_STATUS	0x00
#define SERDES_STATUS_EN	BIT(0)
#define SERDES_STATUS_RST	BIT(1)
#define REG_SERDES_CONF		0x04
#define SERDES_CONF_NCHANS	GENMASK(3, 0)
#define SERDES_CONF_WIDTH_MASK	GENMASK(8, 4)
#define SERDES_CONF_WIDTH_16BIT 0x40
#define SERDES_CONF_WIDTH_20BIT 0x80
#define SERDES_CONF_WIDTH_24BIT 0xc0
#define SERDES_CONF_WIDTH_32BIT 0x100
#define SERDES_CONF_BCLK_POL	0x400
#define SERDES_CONF_LSB_FIRST	0x800
#define SERDES_CONF_UNK1	BIT(12)
#define SERDES_CONF_UNK2	BIT(13)
#define SERDES_CONF_UNK3	BIT(14)
#define SERDES_CONF_SYNC_SEL	GENMASK(18, 16)
#define REG_SERDES_BITSTART	0x08	
#define REG_SERDES_CHANMASK	0x10

/* relative to switch base */
#define REG_DMA_ADAPTER(cl)	(0x8000 * (cl))
#define DMA_ADAPTER_LSB_PAD	GENMASK(4, 0)
#define DMA_ADAPTER_UNK1	GENMASK(6, 5)
#define DMA_ADAPTER_NCHANS	GENMASK(22, 20)


#define SWITCH_STRIDE 0x8000
#define CLUSTER_STRIDE 0x4000

#define MAX_NCLUSTERS 6


struct mca_data {
	struct device *dev;
	struct snd_soc_dai_driver dai_driver;
	struct clk *clk_parents[MAX_NCLUSTERS];

	u32 mclk_range[2];

	int nclusters;

	__iomem void *regs;
	__iomem void *switch_regs;

	struct list_head routes;
};

struct mca_route {
	struct list_head list;
	struct dma_chan *chan[SNDRV_PCM_STREAM_LAST + 1];
	struct device_node *of_node;

	struct clk *clk_parent;
	bool clk_parent_enabled;

	unsigned int tdm_slots;
	unsigned int tdm_slot_width;
	unsigned int tdm_tx_mask;
	unsigned long set_sysclk;

	int clock;
	int syncgen;
	int serdes;

	int nports;
	int ports[];
};

struct mca_route *mca_find_route_for_dai(struct mca_data *mca,
				struct snd_soc_dai *dai);

inline static void mca_poke(struct mca_data *mca, int cluster,
				int regoffset, u32 val)
{
	int offset = (CLUSTER_STRIDE * cluster) + regoffset;
	dev_dbg(mca->dev, "regs: %x <- %x\n", offset, val);
	writel_relaxed(val, mca->regs + offset);
}

inline static void mca_modify(struct mca_data *mca, int cluster,
				int regoffset, u32 mask, u32 val)
{
	int offset = (CLUSTER_STRIDE * cluster) + regoffset;
	__iomem void *p = mca->regs + offset;
	u32 newval = (val & mask) | (readl_relaxed(p) & ~mask);
	dev_dbg(mca->dev, "regs: %x <- %x\n", offset, newval);
	writel_relaxed(newval, p);
}

static int mca_dai_trigger(struct snd_pcm_substream *substream, int cmd,
	struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);
	int ret;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		if (!route->clk_parent_enabled) {
			ret = clk_enable(route->clk_parent);
			if (ret) {
				dev_err(mca->dev, "%s: unable to enable parent clock: %d\n",
					dai->name, ret);
				return ret;
			}
			route->clk_parent_enabled = true;
		}

		mca_modify(mca, route->serdes,
			CLUSTER_TXA_OFF + REG_SERDES_STATUS,
			SERDES_STATUS_EN | SERDES_STATUS_RST,
			SERDES_STATUS_RST);
		mca_modify(mca, route->serdes,
			CLUSTER_TXA_OFF + REG_SERDES_STATUS,
			SERDES_STATUS_EN | SERDES_STATUS_RST,
			SERDES_STATUS_EN);
		mca_modify(mca, route->syncgen,
			REG_SYNCGEN_STATUS, 
			SYNCGEN_STATUS_EN, SYNCGEN_STATUS_EN);

		dev_dbg(mca->dev, "trigger start\n");
		break;
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		mca_modify(mca, route->syncgen,
			REG_SYNCGEN_STATUS,
			SYNCGEN_STATUS_EN, 0);
		mca_modify(mca, route->serdes,
			CLUSTER_TXA_OFF + REG_SERDES_STATUS,
			SERDES_STATUS_EN, 0);

		if (route->clk_parent_enabled) {
			clk_disable(route->clk_parent);
			route->clk_parent_enabled = false;
		}

		dev_dbg(mca->dev, "trigger stop\n");
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int mca_dai_set_tdm_slot(struct snd_soc_dai *dai, unsigned int tx_mask,
			unsigned int rx_mask, int slots, int slot_width);


#define div_ceil(A, B) ((A)/(B) + ((A)%(B) ? 1 : 0))

static int mca_configure_serdes(struct mca_data *mca, int cluster, int serdes_unit,
				unsigned int mask, int slots, int slot_width)
{
	u32 serdes_conf;

	serdes_conf = FIELD_PREP(SERDES_CONF_NCHANS, max(slots, 1) - 1);

	switch (slot_width) {
	case 16:
		serdes_conf |= SERDES_CONF_WIDTH_16BIT;
		break;
	case 20:
		serdes_conf |= SERDES_CONF_WIDTH_20BIT;
		break;
	case 24:
		serdes_conf |= SERDES_CONF_WIDTH_24BIT;
		break;
	case 32:
		serdes_conf |= SERDES_CONF_WIDTH_32BIT;
		break;
	default:
		goto err;
	}

	mca_modify(mca, cluster,
		serdes_unit + REG_SERDES_CONF,
		SERDES_CONF_WIDTH_MASK | SERDES_CONF_NCHANS, serdes_conf);
	mca_poke(mca, cluster,
		serdes_unit + REG_SERDES_CHANMASK,
		~((u32) mask));

	return 0;

err:
	dev_err(mca->dev, "unsupported SERDES configuration requested (mask=0x%x slots=%d slot_width=%d)\n",
			mask, slots, slot_width);
	return -EINVAL;
}

static int mca_dai_hw_params(struct snd_pcm_substream *substream,
		struct snd_pcm_hw_params *params, struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);

	unsigned int samp_rate = params_rate(params);
	unsigned int tdm_slots, tdm_slot_width, tdm_tx_mask;
	unsigned long bclk_ratio;
	u32 regval, pad;
	int ret;

	dev_info(mca->dev, "sample rate: %d\n", samp_rate);

	tdm_slot_width = 0;

	if (route->tdm_slots) {
		/* we were given a slot width from above */
		tdm_slot_width = route->tdm_slot_width;
		tdm_slots = route->tdm_slots;
		tdm_tx_mask = route->tdm_tx_mask;
	} else {
		/* set initial guesses of tdm values (will be refined based on sysclk) */
		tdm_slot_width = params_width(params);
		tdm_slots = params_channels(params);
	}

	if (route->set_sysclk)
		bclk_ratio = route->set_sysclk / samp_rate;
	else
		bclk_ratio = tdm_slot_width * tdm_slots;

	if (!route->tdm_slots) {
		/* refine tdm */

		int nchannels = params_channels(params);

		if (nchannels > 2) {
			dev_err(mca->dev, "nchannels > 2 and no TDM\n");
			return -EINVAL;
		}

		if ((bclk_ratio % nchannels) != 0) {
			dev_err(mca->dev, "bclk ratio not divisible bclk_ratio=%ld nchannels=%d\n",
					bclk_ratio, nchannels);
			return -EINVAL;
		}

		tdm_slot_width = bclk_ratio / nchannels;

		if (tdm_slot_width > 32 && nchannels == 1)
			tdm_slot_width = 32;

		if (tdm_slot_width < params_width(params)) {
			dev_err(mca->dev, "TDM slots too narrow tdm=%d params=%d\n",
					tdm_slot_width, params_width(params));
			return -EINVAL;
		}

		tdm_tx_mask = (1 << tdm_slots) - 1;
	}

	ret = mca_configure_serdes(mca, route->serdes, CLUSTER_TXA_OFF, tdm_tx_mask,
					tdm_slots, tdm_slot_width);
	if (ret)
		return ret;

	/*
	 * Set up FSYNC duty cycle to be as even as possible.
	 */
	mca_poke(mca, route->syncgen,
		REG_SYNCGEN_HI_PERIOD,
		(bclk_ratio / 2) - 1);
	mca_poke(mca, route->syncgen,
		REG_SYNCGEN_LO_PERIOD,
		((bclk_ratio + 1) / 2) - 1);

	//pad = params_physical_width(params) - params_width(params);
	
	pad = tdm_slot_width - params_width(params);
	regval = FIELD_PREP(DMA_ADAPTER_NCHANS, params_channels(params))
			| FIELD_PREP(DMA_ADAPTER_UNK1, 0x2)
			| FIELD_PREP(DMA_ADAPTER_LSB_PAD, pad);

	dev_info(mca->dev, "adapter: pad: %d regval: %x\n", pad, regval);

	writel_relaxed(regval,
			mca->switch_regs + REG_DMA_ADAPTER(route->serdes));

	mca_modify(mca, route->clock,
		REG_STATUS,
		STATUS_MCLK_EN, 0);
	mca_poke(mca, route->clock,
		REG_MCLK_CONF,
		FIELD_PREP(MCLK_CONF_DIV, 0x1));
	mca_modify(mca, route->clock,
		REG_STATUS,
		STATUS_MCLK_EN, STATUS_MCLK_EN);

	ret = clk_set_rate(route->clk_parent, bclk_ratio * samp_rate);
	if (ret) {
		dev_err(mca->dev, "%s: unable to set parent clock rate: %d\n", dai->name, ret);
		return ret;
	}

	return 0;
}

static int mca_dai_startup(struct snd_pcm_substream *substream,
				struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);

	mca_poke(mca, route->syncgen, REG_SYNCGEN_MCLK_SEL,
			1 + route->clock); //FIELD_PREP(SYNCGEN_MCLK_SEL, 1 << (route->clock)));

	mca_poke(mca, route->ports[0], REG_PORT_ENABLES,
			PORT_ENABLES_CLOCKS | PORT_ENABLES_TX_DATA);
	mca_poke(mca, route->ports[0], REG_PORT_CLOCK_SEL,
			FIELD_PREP(PORT_CLOCK_SEL, route->syncgen + 1));
	mca_poke(mca, route->ports[0], REG_PORT_DATA_SEL,
			PORT_DATA_SEL_TXA(route->serdes));

	mca_modify(mca, route->serdes, CLUSTER_TXA_OFF + REG_SERDES_CONF,
			SERDES_CONF_UNK1 | SERDES_CONF_UNK2 | SERDES_CONF_UNK3,
			SERDES_CONF_UNK1 | SERDES_CONF_UNK2 /* | SERDES_CONF_UNK3 */);


	mca_modify(mca, route->serdes, CLUSTER_TXA_OFF + REG_SERDES_CONF,
			SERDES_CONF_SYNC_SEL, FIELD_PREP(SERDES_CONF_SYNC_SEL,
						route->syncgen + 1));

	if (route->clk_parent) {
		dev_dbg(mca->dev, "%s: clk prepare\n", dai->name);
		clk_prepare(route->clk_parent);
	}

	return 0;
}

static void mca_dai_shutdown(struct snd_pcm_substream *substream,
					struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);

	if (route->clk_parent) {
		dev_dbg(mca->dev, "%s: clk unprepare\n", dai->name);
		clk_unprepare(route->clk_parent);
	}
}

static int mca_dai_probe(struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);

	if (!route) {
		dev_dbg(mca->dev, "probe on DAI %d with no route\n", dai->id);
		return -EINVAL;
	}

	return 0;
}

static int mca_dai_set_tdm_slot(struct snd_soc_dai *dai, unsigned int tx_mask,
				unsigned int rx_mask, int slots, int slot_width)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);

	if (rx_mask) {
		dev_err(mca->dev, "refusing TDM with non-zero RX mask (no RX support)\n");
		return -EINVAL;
	}

	route->tdm_slots = slots;
	route->tdm_slot_width = slot_width;
	route->tdm_tx_mask = tx_mask;

	return 0;
}

static int mca_dai_set_fmt(struct snd_soc_dai *dai,
				unsigned int fmt)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);
	u32 serdes_conf = 0;
	u32 bitstart;
	u32 fpol_inv = 0;

	if ((fmt & SND_SOC_DAIFMT_CLOCK_PROVIDER_MASK) !=
			SND_SOC_DAIFMT_CBC_CFC)
		goto err;

	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		fpol_inv = 0;
		bitstart = 1;
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		fpol_inv = 1;
		bitstart = 0;
		break;
	default:
		goto err;
	}

	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_IF:
	case SND_SOC_DAIFMT_IB_IF:
		fpol_inv ^= 1;
		break;
	}

	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:
	case SND_SOC_DAIFMT_NB_IF:
		serdes_conf |= SERDES_CONF_BCLK_POL;
	}

	/*
	if (!fpol_inv)
		goto err;
	*/

	mca_modify(mca, route->serdes, CLUSTER_TXA_OFF + REG_SERDES_CONF,
					SERDES_CONF_BCLK_POL, serdes_conf);
	mca_poke(mca, route->serdes, CLUSTER_TXA_OFF + REG_SERDES_BITSTART,
						bitstart);

	return 0;

err:
	dev_err(mca->dev, "unsupported DAI format (0x%x) requested\n", fmt);
	return -EINVAL;
}

static int mca_dai_set_sysclk(struct snd_soc_dai *dai, int clk_id,
				unsigned int freq, int dir)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);
	int ret;

	ret = clk_set_rate(route->clk_parent, freq);
	if (!ret)
		route->set_sysclk = freq;
	return ret;
}

static const struct snd_soc_dai_ops mca_dai_ops = {
	.startup = mca_dai_startup,
	.shutdown = mca_dai_shutdown,
	.trigger = mca_dai_trigger,
	.hw_params = mca_dai_hw_params,
	.set_fmt = mca_dai_set_fmt,
	.set_sysclk = mca_dai_set_sysclk,
	.set_tdm_slot = mca_dai_set_tdm_slot,
};

struct mca_route *mca_find_route_for_dai(struct mca_data *mca, struct snd_soc_dai *dai)
{
	struct mca_route *route;

	list_for_each_entry(route, &mca->routes, list)
		if (route->ports[0] == dai->id)
			return route;

	return NULL;
}

static struct mca_route *mca_route_for_rtd(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_soc_dai *dai = asoc_rtd_to_cpu(rtd, 0);
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	return mca_find_route_for_dai(mca, dai);
}

static int mca_set_runtime_hwparams(struct snd_soc_component *component,
				struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = asoc_substream_to_rtd(substream);
	struct mca_route *route = mca_route_for_rtd(asoc_substream_to_rtd(substream));
	struct dma_chan *chan = route->chan[substream->stream];
	struct device *dma_dev = chan->device->dev;
	struct snd_dmaengine_dai_dma_data dma_data = {};
	int ret;

	struct snd_pcm_hardware hw;

	memset(&hw, 0, sizeof(hw));

	hw.info = SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_MMAP_VALID |
			SNDRV_PCM_INFO_INTERLEAVED;
	hw.periods_min = 2;
	hw.periods_max = UINT_MAX;
	hw.period_bytes_min = 256;
	hw.period_bytes_max = dma_get_max_seg_size(dma_dev);
	hw.buffer_bytes_max = SIZE_MAX;
	hw.fifo_size = 16;

	ret = snd_dmaengine_pcm_refine_runtime_hwparams(substream,
						&dma_data, &hw, chan);

	if (ret)
		return ret;

	return snd_soc_set_runtime_hwparams(substream, &hw);
}

static int mca_open(struct snd_soc_component *component,
		struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = asoc_substream_to_rtd(substream);
	struct mca_route *route = mca_route_for_rtd(rtd);
	struct dma_chan *chan = route->chan[substream->stream];
	int ret;

	ret = mca_set_runtime_hwparams(component, substream);
	if (ret)
		return ret;

	return snd_dmaengine_pcm_open(substream, chan);
}

static int mca_hw_params(struct snd_soc_component *component,
			struct snd_pcm_substream *substream,
			struct snd_pcm_hw_params *params)
{
	struct dma_chan *chan = snd_dmaengine_pcm_get_chan(substream);
	struct dma_slave_config slave_config;
	int ret;

	memset(&slave_config, 0, sizeof(slave_config));
	ret = snd_hwparams_to_dma_slave_config(substream, params, &slave_config);
	if (ret)
		return ret;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		slave_config.dst_port_window_size = params_channels(params);
	else
		slave_config.src_port_window_size = params_channels(params);

	ret = dmaengine_slave_config(chan, &slave_config);
	if (ret)
		return ret;

	return 0;
}

static int mca_close(struct snd_soc_component *component,
		struct snd_pcm_substream *substream)
{
	return snd_dmaengine_pcm_close(substream);
}

static int mca_trigger(struct snd_soc_component *component,
		struct snd_pcm_substream *substream, int cmd)
{
	return snd_dmaengine_pcm_trigger(substream, cmd);
}

static snd_pcm_uframes_t mca_pointer(struct snd_soc_component *component,
				struct snd_pcm_substream *substream)
{
	return snd_dmaengine_pcm_pointer(substream);
}

static int mca_pcm_new(struct snd_soc_component *component,
			struct snd_soc_pcm_runtime *rtd)
{
	struct mca_route *route = mca_route_for_rtd(rtd);
	unsigned int i;

	for_each_pcm_streams(i) {
		struct snd_pcm_substream *substream = rtd->pcm->streams[i].substream;
		if (!substream)
			continue;

		if (!route->chan[i]) {
			dev_err(component->dev, "missing DMA channel for stream %d\n", i);
			return -EINVAL;
		}

		snd_pcm_set_managed_buffer(substream, SNDRV_DMA_TYPE_DEV_IRAM,
					route->chan[i]->device->dev, 512*1024,
					SIZE_MAX);
	}

	return 0;
}

static const struct snd_soc_component_driver mca_component = {
	.name = "apple-mca",
	.open		= mca_open,
	.close		= mca_close,
	.hw_params	= mca_hw_params,
	.trigger	= mca_trigger,
	.pointer	= mca_pointer,
	.pcm_construct	= mca_pcm_new,
};

void apple_mca_release_dma_chans(struct mca_data *mca)
{
	int i;
	struct mca_route *route;

	list_for_each_entry(route, &mca->routes, list) {
		for_each_pcm_streams(i) {
			if (!route->chan[i])
				continue;
			dma_release_channel(route->chan[i]);
			route->chan[i] = NULL;
		}
	}
}

void apple_mca_put_clks(struct mca_data *mca)
{
	struct mca_route *route;
	int i;

	list_for_each_entry(route, &mca->routes, list) {
		if (!route->clk_parent)
			continue;
		//clk_rate_exclusive_put(route->clk_parent);
		route->clk_parent = NULL;
	}

	for (i = 0; i < mca->nclusters; i++) {
		if (!mca->clk_parents[i])
			continue;
		clk_put(mca->clk_parents[i]);
		mca->clk_parents[i] = NULL;
	}
}

static int apple_mca_probe(struct platform_device *pdev)
{
	struct mca_data *mca;
	struct snd_soc_dai_driver *dai_drivers;
	struct device_node *np;
	struct mca_route *route;
	const char *name;
	int nclusters;
	int i, ret;

	mca = devm_kzalloc(&pdev->dev, sizeof(*mca), GFP_KERNEL);
	if (!mca)
		return -ENOMEM;

	nclusters = 6; /* TODO */
	mca->nclusters = nclusters;
	mca->dev = &pdev->dev;
	INIT_LIST_HEAD(&mca->routes);

	platform_set_drvdata(pdev, mca);

	mca->regs = devm_platform_ioremap_resource_byname(pdev, "clusters");
	if (IS_ERR(mca->regs)) {
		dev_err(&pdev->dev, "unable to obtain clusters MMIO resource: %ld\n",
					PTR_ERR(mca->regs));
		return PTR_ERR(mca->regs);
	}

	mca->switch_regs = devm_platform_ioremap_resource_byname(pdev, "switch");
	if (IS_ERR(mca->switch_regs)) {
		dev_err(&pdev->dev, "unable to obtain switch MMIO resource: %ld\n",
					PTR_ERR(mca->switch_regs));
		return PTR_ERR(mca->switch_regs);
	}

	{
		struct reset_control *rst;
		rst = of_reset_control_array_get(pdev->dev.of_node, true, true, false);
		if (IS_ERR(rst)) {
			dev_err(&pdev->dev, "unable to obtain reset control: %ld\n",
					PTR_ERR(rst));
		} else if (rst) {
			reset_control_reset(rst);
			reset_control_put(rst);
		}
	}

	ret = of_property_read_u32_array(pdev->dev.of_node, "apple,mclk-range",
						mca->mclk_range, 2);
	if (ret) {
		dev_err(&pdev->dev, "bad or missing apple,mclk-range property\n");
		return ret;
	}

	dai_drivers = devm_kzalloc(&pdev->dev, sizeof(*dai_drivers) * nclusters,
					GFP_KERNEL);
	if (!dai_drivers)
		return -ENOMEM;

	for (i = 0; i < nclusters; i++) {
		struct snd_soc_dai_driver *drv = &dai_drivers[i];

		drv->id = i;
		drv->name = devm_kasprintf(&pdev->dev, GFP_KERNEL,
						"mca-i2s-%d", i);
		if (!drv->name)
			return -ENOMEM;
		drv->probe = mca_dai_probe;
		drv->ops = &mca_dai_ops;
	}

	for_each_child_of_node(pdev->dev.of_node, np) {
		struct snd_soc_dai_driver *drv;
		struct mca_route *route;
		struct of_phandle_args args;
		u32 clock;
		u32 serdes;
		u32 port;
		int nports;

		/* TODO: support for serdes units other than TXA */
		ret = of_property_read_u32(np, "apple,serdes", &serdes);
		if (ret || serdes >= nclusters) {
			dev_err(&pdev->dev, "bad apple,serdes at %pOF\n", np);
			return -EINVAL;
		}

		nports = 1; // TODO
		ret = of_parse_phandle_with_args(np, "sound-dai", "#sound-dai-cells", 0, &args);
		if (!ret && (args.args_count != 1 || args.np != pdev->dev.of_node ||
							args.args[0] >= nclusters)) {
			dev_err(&pdev->dev, "bad sound-dai at %pOF\n", np);
			return -EINVAL;
		}
		if (!ret) {
			port = args.args[0];
		} else {
			port = serdes;
		}

		ret = of_property_read_u32(np, "apple,clock", &clock);
		if (!ret && clock >= nclusters) {
			dev_err(&pdev->dev, "bad apple,clock at %pOF\n", np);
			return -EINVAL;
		} else {
			clock = serdes;
		}

		route = devm_kzalloc(&pdev->dev, struct_size(route, ports, nports), GFP_KERNEL);
		if (!route)
			return -ENOMEM;

		route->serdes = serdes;
		route->syncgen = serdes;
		route->nports = nports;
		route->ports[0] = port;
		route->clock = clock;
		route->of_node = np;

		dev_dbg(&pdev->dev, "adding route: serdes=%d port=%d clock=%d\n", serdes, port, clock);

		list_add(&route->list, &mca->routes);

		drv = &dai_drivers[route->ports[0]];
		drv->playback.channels_min = 1;
		drv->playback.channels_max = 2;
		drv->playback.rates = SNDRV_PCM_RATE_8000_192000;

		// 16 bit is broken for the time being
		drv->playback.formats = SNDRV_PCM_FMTBIT_S16_LE |
					SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE;
	}

	for (i = 0; i < of_count_phandle_with_args(pdev->dev.of_node,
						"clocks", "#clock-cells"); i++) {
		struct clk *clk;

		if (i > nclusters) {
			dev_err(&pdev->dev, "superfluous clock parent specified\n");
			break;
		}

		clk = of_clk_get(pdev->dev.of_node, i);

		if (IS_ERR(clk)) {
			dev_err(&pdev->dev, "unable to obtain clock parent %s: %ld\n",
				name, PTR_ERR(clk));
			goto err_release_chans_clocks;
		}
		mca->clk_parents[i] = clk;
	}

	/*
	 * In this last pass over routes we obtain DMA chans
	 * and clock rate exclusivities.
	 */
	list_for_each_entry(route, &mca->routes, list) {
		struct clk *clk;

		for_each_pcm_streams(i) {
			struct dma_chan *chan = NULL;
			char *name = (i == SNDRV_PCM_STREAM_PLAYBACK) \
					? "tx" : "rx";

			chan = of_dma_request_slave_channel(route->of_node, name);
			if (IS_ERR(chan) && PTR_ERR(chan) == -EPROBE_DEFER) {
				ret = PTR_ERR(chan);
				goto err_release_chans_clocks;
			} else if (IS_ERR(chan)) {
				dev_dbg(&pdev->dev, "no %s DMA channel at %pOF (lookup returned %ld)\n",
					name, route->of_node, PTR_ERR(chan));
				chan = NULL;
			}

			route->chan[i] = chan;
		}

		clk = mca->clk_parents[route->clock];
		if (!clk) {
			dev_err(&pdev->dev, "missing clock parent for route %pOF\n",
				route->of_node);
			goto err_release_chans_clocks;
		}

/*
		ret = clk_rate_exclusive_get(clk);
		if (ret) {
			dev_err(&pdev->dev, "unable to get clock rate exclusivity for %pOF\n",
				route->of_node);
			goto err_release_chans_clocks;
		}
*/
		route->clk_parent = clk;
	}

	ret = devm_snd_soc_register_component(&pdev->dev, &mca_component,
						dai_drivers, nclusters);
	if (ret) {
		dev_err(&pdev->dev, "unable to register ASoC component: %d\n", ret);
		goto err_release_chans_clocks;
	}

	dev_dbg(&pdev->dev, "all good, ready to go!\n");
	return 0;

err_release_chans_clocks:
	apple_mca_put_clks(mca);
	apple_mca_release_dma_chans(mca);
	return ret;
}

static int apple_mca_remove(struct platform_device *pdev)
{
	struct mca_data *mca = platform_get_drvdata(pdev);

	apple_mca_put_clks(mca);
	apple_mca_release_dma_chans(mca);

	return 0;
}

static const struct of_device_id apple_mca_of_match[] = {
	{ .compatible = "apple,mca", },
	{ .compatible = "apple,mca-t8103", },
	{},
};
MODULE_DEVICE_TABLE(of, apple_mca_of_match);

static struct platform_driver apple_mca_driver = {
	.driver = {
		.name = "apple-mca",
		.of_match_table = apple_mca_of_match,
	},
	.probe = apple_mca_probe,
	.remove = apple_mca_remove,
};
module_platform_driver(apple_mca_driver);

MODULE_AUTHOR("Martin Povišer <povik@protonmail.com>");
MODULE_DESCRIPTION("Driver for MCA blocks on Apple Silicon SoCs");
MODULE_LICENSE("GPL");
