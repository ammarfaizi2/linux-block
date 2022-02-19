#define USE_RXB_FOR_CAPTURE

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

#define REG_INTSTATE		0x700
#define REG_INTMASK		0x704

/* bases of serdes units (relative to cluster) */
#define CLUSTER_RXA_OFF	0x200
#define CLUSTER_TXA_OFF	0x300
#define CLUSTER_RXB_OFF	0x400
#define CLUSTER_TXB_OFF	0x500

#define CLUSTER_TX_OFF	CLUSTER_TXA_OFF

#ifndef USE_RXB_FOR_CAPTURE
#define CLUSTER_RX_OFF	CLUSTER_RXA_OFF
#else
#define CLUSTER_RX_OFF	CLUSTER_RXB_OFF
#endif

/* relative to serdes unit base */
#define REG_SERDES_STATUS	0x00
#define SERDES_STATUS_EN	BIT(0)
#define SERDES_STATUS_RST	BIT(1)
#define REG_TX_SERDES_CONF	0x04
#define REG_RX_SERDES_CONF	0x08
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
#define REG_TX_SERDES_BITSTART	0x08
#define REG_RX_SERDES_BITSTART	0x0c
#define REG_TX_SERDES_CHANMASK	0x10
#define REG_RX_SERDES_CHANMASK	0x14
#define REG_RX_SERDES_PORT	0x04

/* relative to switch base */
#define REG_DMA_ADAPTER_A(cl)	(0x8000 * (cl))
#define REG_DMA_ADAPTER_B(cl)	(0x8000 * (cl) + 0x4000)
#define DMA_ADAPTER_TX_LSB_PAD	GENMASK(4, 0)
#define DMA_ADAPTER_UNK1	GENMASK(6, 5)
#define DMA_ADAPTER_RX_MSB_PAD	GENMASK(12, 8)
#define DMA_ADAPTER_NCHANS	GENMASK(22, 20)

#define SWITCH_STRIDE 0x8000
#define CLUSTER_STRIDE 0x4000

#define MAX_NCLUSTERS 6


struct mca_data {
	struct device *dev;
	struct clk *clk_parents[MAX_NCLUSTERS];

	int nclusters;

	__iomem void *base;
	__iomem void *switch_base;

	struct list_head routes;
};

struct mca_cluster {
	struct mca_data *host;
	int no;
};

struct mca_route {
	struct list_head list;
	struct dma_chan *chan[SNDRV_PCM_STREAM_LAST + 1];
	struct device_node *of_node;

	struct clk *clk_parent;

	bool clocks_in_use[SNDRV_PCM_STREAM_LAST];

	unsigned int tdm_slots;
	unsigned int tdm_slot_width;
	unsigned int tdm_tx_mask;
	unsigned int tdm_rx_mask;
	unsigned long set_sysclk;

	int clock;
	int syncgen;
	int serdes;

	int nports;
	int ports[];
};

struct mca_route *mca_find_route_for_dai(struct mca_data *mca,
				struct snd_soc_dai *dai);

#if 0
static u32 mca_peek(struct mca_data *mca, int cluster, int regoffset)
{
	int offset = (CLUSTER_STRIDE * cluster) + regoffset;

	return readl_relaxed(mca->base + offset);
}
#endif

static void mca_poke(struct mca_data *mca, int cluster,
				int regoffset, u32 val)
{
	int offset = (CLUSTER_STRIDE * cluster) + regoffset;
	dev_dbg(mca->dev, "regs: %x <- %x\n", offset, val);
	writel_relaxed(val, mca->base + offset);
}

static void mca_modify(struct mca_data *mca, int cluster,
				int regoffset, u32 mask, u32 val)
{
	int offset = (CLUSTER_STRIDE * cluster) + regoffset;
	__iomem void *p = mca->base + offset;
	u32 newval = (val & mask) | (readl_relaxed(p) & ~mask);
	dev_dbg(mca->dev, "regs: %x <- %x\n", offset, newval);
	writel_relaxed(newval, p);
}

#if 0
static void mca_rearm_irqs(struct mca_data *mca, int cluster)
{
	dev_dbg(mca->dev, "cl%d: rearming interrupts\n", cluster);
	mca_poke(mca, cluster, REG_INTSTATE, 0xffffffff);
	mca_poke(mca, cluster, REG_INTMASK, ~mca_peek(mca, cluster, REG_INTSTATE));
}
#endif

static int mca_dai_trigger(struct snd_pcm_substream *substream, int cmd,
	struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);

	int serdes_unit = (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ?
				CLUSTER_TX_OFF : CLUSTER_RX_OFF;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		mca_modify(mca, route->serdes,
			serdes_unit + REG_SERDES_STATUS,
			SERDES_STATUS_EN | SERDES_STATUS_RST,
			SERDES_STATUS_RST);
		mca_modify(mca, route->serdes,
			serdes_unit + REG_SERDES_STATUS,
			SERDES_STATUS_EN | SERDES_STATUS_RST,
			SERDES_STATUS_EN);

		dev_dbg(mca->dev, "trigger start\n");
		break;
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		mca_modify(mca, route->serdes,
			serdes_unit + REG_SERDES_STATUS,
			SERDES_STATUS_EN, 0);

		dev_dbg(mca->dev, "trigger stop\n");
		break;
	default:
		return -EINVAL;
	}
	return 0;
}


static bool mca_clocks_in_use(struct mca_route *route)
{
	int stream;

	for_each_pcm_streams(stream)
		if (route->clocks_in_use[stream])
			return true;
	return false;
}

static int mca_dai_prepare(struct snd_pcm_substream *substream,
				struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);
	int ret;

	if (!mca_clocks_in_use(route)) {
		ret = clk_prepare_enable(route->clk_parent);
		if (ret) {
			dev_err(mca->dev, "%s: unable to enable parent clock: %d\n",
				dai->name, ret);
			return ret;
		}

		mca_poke(mca, route->syncgen, REG_SYNCGEN_MCLK_SEL,
			route->clock + 1);
		mca_modify(mca, route->syncgen,
			REG_SYNCGEN_STATUS, 
			SYNCGEN_STATUS_EN, SYNCGEN_STATUS_EN);
		mca_modify(mca, route->clock,
			REG_STATUS,
			STATUS_MCLK_EN, STATUS_MCLK_EN);
	}

	route->clocks_in_use[substream->stream] = true;

	return 0;
}

static int mca_dai_hw_free(struct snd_pcm_substream *substream,
				struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);

	if (!mca_clocks_in_use(route))
		return 0; /* Nothing to do */

	route->clocks_in_use[substream->stream] = false;

	if (!mca_clocks_in_use(route)) {
		mca_modify(mca, route->syncgen,
			REG_SYNCGEN_STATUS,
			SYNCGEN_STATUS_EN, 0);
		mca_modify(mca, route->clock,
			REG_STATUS,
			STATUS_MCLK_EN, 0);

		clk_disable_unprepare(route->clk_parent);
	}

	return 0;
}

static int mca_dai_set_tdm_slot(struct snd_soc_dai *dai, unsigned int tx_mask,
			unsigned int rx_mask, int slots, int slot_width);


#define div_ceil(A, B) ((A)/(B) + ((A)%(B) ? 1 : 0))

static int mca_configure_serdes(struct mca_data *mca, int cluster, int serdes_unit,
				unsigned int mask, int slots, int slot_width, bool is_tx, int port)
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
		serdes_unit + (is_tx ? REG_TX_SERDES_CONF : REG_RX_SERDES_CONF),
		SERDES_CONF_WIDTH_MASK | SERDES_CONF_NCHANS, serdes_conf);
	mca_poke(mca, cluster,
		serdes_unit + (is_tx ? REG_TX_SERDES_CHANMASK : REG_RX_SERDES_CHANMASK),
		~((u32) mask));
	mca_poke(mca, cluster,
		serdes_unit + (is_tx ? REG_TX_SERDES_CHANMASK : REG_RX_SERDES_CHANMASK) + 0x4,
		~((u32) mask));

	if (!is_tx)
		mca_poke(mca, cluster,
			serdes_unit + REG_RX_SERDES_PORT,
			1 << port);

	return 0;

err:
	dev_err(mca->dev, "unsupported SERDES configuration requested (mask=0x%x slots=%d slot_width=%d)\n",
			mask, slots, slot_width);
	return -EINVAL;
}

static int mca_dai_hw_params(struct snd_pcm_substream *substream,
		struct snd_pcm_hw_params *params, struct snd_soc_dai *dai)
{
	bool is_tx = substream->stream == SNDRV_PCM_STREAM_PLAYBACK;
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

	ret = mca_configure_serdes(mca, route->serdes, is_tx ? CLUSTER_TX_OFF : CLUSTER_RX_OFF,
				tdm_tx_mask, tdm_slots, tdm_slot_width, is_tx, route->ports[0]);
	if (ret)
		return ret;
	
	pad = tdm_slot_width - params_width(params);
	regval = FIELD_PREP(DMA_ADAPTER_NCHANS, params_channels(params))
			| FIELD_PREP(DMA_ADAPTER_UNK1, 0x2)
			| FIELD_PREP(DMA_ADAPTER_TX_LSB_PAD, pad)
			| FIELD_PREP(DMA_ADAPTER_RX_MSB_PAD, pad);

	dev_info(mca->dev, "adapter: pad: %d regval: %x\n", pad, regval);

#ifndef USE_RXB_FOR_CAPTURE
	writel_relaxed(regval, mca->switch_base + REG_DMA_ADAPTER_A(route->serdes));
#else
	if (is_tx)
		writel_relaxed(regval, mca->switch_base + REG_DMA_ADAPTER_A(route->serdes));
	else
		writel_relaxed(regval, mca->switch_base + REG_DMA_ADAPTER_B(route->serdes));
#endif

	if (!mca_clocks_in_use(route)) {
		/*
		 * Set up FSYNC duty cycle to be as even as possible.
		 */
		mca_poke(mca, route->syncgen,
			REG_SYNCGEN_HI_PERIOD,
			(bclk_ratio / 2) - 1);
		mca_poke(mca, route->syncgen,
			REG_SYNCGEN_LO_PERIOD,
			((bclk_ratio + 1) / 2) - 1);

		mca_poke(mca, route->clock,
			REG_MCLK_CONF,
			FIELD_PREP(MCLK_CONF_DIV, 0x1));

		ret = clk_set_rate(route->clk_parent, bclk_ratio * samp_rate);
		if (ret) {
			dev_err(mca->dev, "%s: unable to set parent clock rate: %d\n", dai->name, ret);
			return ret;
		}
	}

	return 0;
}

static int mca_dai_startup(struct snd_pcm_substream *substream,
				struct snd_soc_dai *dai)
{
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);

	mca_poke(mca, route->ports[0], REG_PORT_ENABLES,
			PORT_ENABLES_CLOCKS | PORT_ENABLES_TX_DATA);
	mca_poke(mca, route->ports[0], REG_PORT_CLOCK_SEL,
			FIELD_PREP(PORT_CLOCK_SEL, route->syncgen + 1));
	mca_poke(mca, route->ports[0], REG_PORT_DATA_SEL,
			PORT_DATA_SEL_TXA(route->serdes));

	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		mca_modify(mca, route->serdes, CLUSTER_TX_OFF + REG_TX_SERDES_CONF,
				SERDES_CONF_UNK1 | SERDES_CONF_UNK2 | SERDES_CONF_UNK3,
				SERDES_CONF_UNK1 | SERDES_CONF_UNK2 | SERDES_CONF_UNK3);
		mca_modify(mca, route->serdes, CLUSTER_TX_OFF + REG_TX_SERDES_CONF,
				SERDES_CONF_SYNC_SEL, FIELD_PREP(SERDES_CONF_SYNC_SEL,
							route->syncgen + 1));
		break;

	case SNDRV_PCM_STREAM_CAPTURE:
		mca_modify(mca, route->serdes, CLUSTER_RX_OFF + REG_RX_SERDES_CONF,
				SERDES_CONF_UNK1 | SERDES_CONF_UNK2,
				SERDES_CONF_UNK1 | SERDES_CONF_UNK2);
		mca_modify(mca, route->serdes, CLUSTER_RX_OFF + REG_RX_SERDES_CONF,
			SERDES_CONF_SYNC_SEL, FIELD_PREP(SERDES_CONF_SYNC_SEL,
						route->syncgen + 1));
		break;

	default:
		break;
	}	

	return 0;
}

static void mca_dai_shutdown(struct snd_pcm_substream *substream,
					struct snd_soc_dai *dai)
{
#if 0
	struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_find_route_for_dai(mca, dai);
#endif
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

	route->tdm_slots = slots;
	route->tdm_slot_width = slot_width;
	route->tdm_tx_mask = tx_mask;
	route->tdm_rx_mask = rx_mask;

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

	if (!fpol_inv)
		goto err;

	mca_modify(mca, route->serdes, CLUSTER_TX_OFF + REG_TX_SERDES_CONF,
					SERDES_CONF_BCLK_POL, serdes_conf);
	mca_poke(mca, route->serdes, CLUSTER_TX_OFF + REG_TX_SERDES_BITSTART,
						bitstart);
	mca_modify(mca, route->serdes, CLUSTER_RX_OFF + REG_RX_SERDES_CONF,
					SERDES_CONF_BCLK_POL, serdes_conf);
	mca_poke(mca, route->serdes, CLUSTER_RX_OFF + REG_RX_SERDES_BITSTART,
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

	if (freq == route->set_sysclk)
		return 0;

	if (mca_clocks_in_use(route))
		return -EBUSY;

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
	.prepare = mca_dai_prepare,
	.hw_free = mca_dai_hw_free,
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
	//struct snd_soc_pcm_runtime *rtd = asoc_substream_to_rtd(substream);
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
	//struct snd_soc_dai *dai = asoc_rtd_to_cpu(rtd, 0);
	//struct mca_data *mca = snd_soc_dai_get_drvdata(dai);
	struct mca_route *route = mca_route_for_rtd(rtd);
	struct dma_chan *chan = route->chan[substream->stream];
	int ret;

	//mca_rearm_irqs(mca, route->serdes);

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

#if 0
static irqreturn_t mca_interrupt(int irq, void *devid)
{
	struct mca_cluster *cl = devid;
	struct mca_data *mca = cl->host;
	u32 mask = mca_peek(mca, cl->no, REG_INTMASK);
	u32 state = mca_peek(mca, cl->no, REG_INTSTATE);
	u32 cleared;

	mca_poke(mca, cl->no, REG_INTSTATE, state & mask);
	cleared = state & ~mca_peek(mca, cl->no, REG_INTSTATE);

	dev_dbg(mca->dev, "cl%d: took an interrupt. state=%x mask=%x unmasked=%x cleared=%x\n",
			cl->no, state, mask, state & mask, cleared);

	mca_poke(mca, cl->no, REG_INTMASK, mask & (~state | cleared));

	return true ? IRQ_HANDLED : IRQ_NONE;
}
#endif

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
	struct mca_cluster *clusters;
	struct snd_soc_dai_driver *dai_drivers;
	struct mca_route *route;
	const char *name;
	int nclusters;
	int irq, ret, i;

	mca = devm_kzalloc(&pdev->dev, sizeof(*mca), GFP_KERNEL);
	if (!mca)
		return -ENOMEM;

	nclusters = 6; /* TODO */
	mca->nclusters = nclusters;
	mca->dev = &pdev->dev;
	INIT_LIST_HEAD(&mca->routes);

	platform_set_drvdata(pdev, mca);

	mca->base = devm_platform_ioremap_resource_byname(pdev, "clusters");
	if (IS_ERR(mca->base)) {
		dev_err(&pdev->dev, "unable to obtain clusters MMIO resource: %ld\n",
					PTR_ERR(mca->base));
		return PTR_ERR(mca->base);
	}

	mca->switch_base = devm_platform_ioremap_resource_byname(pdev, "switch");
	if (IS_ERR(mca->switch_base)) {
		dev_err(&pdev->dev, "unable to obtain switch MMIO resource: %ld\n",
					PTR_ERR(mca->switch_base));
		return PTR_ERR(mca->switch_base);
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

	dai_drivers = devm_kzalloc(&pdev->dev, sizeof(*dai_drivers) * nclusters,
					GFP_KERNEL);
	if (!dai_drivers)
		return -ENOMEM;

	clusters = devm_kzalloc(&pdev->dev, sizeof(*clusters) * nclusters,
					GFP_KERNEL);
	if (!clusters)
		return -ENOMEM;

	for (i = 0; i < nclusters; i++) {
		struct mca_cluster *cluster = &clusters[i];
		struct snd_soc_dai_driver *drv = &dai_drivers[i];
		struct mca_route *route;
		struct clk *clk;
		int stream;

		cluster->host = mca;
		cluster->no = i;

		drv->id = i;
		drv->name = devm_kasprintf(&pdev->dev, GFP_KERNEL,
						"mca-i2s-%d", i);
		if (!drv->name) {
			ret = -ENOMEM;
			goto err_release_chans_clocks;
		}
		drv->probe = mca_dai_probe;
		drv->ops = &mca_dai_ops;
		drv->playback.channels_min = 1;
		drv->playback.channels_max = 2;
		drv->playback.rates = SNDRV_PCM_RATE_8000_192000;
		drv->playback.formats = SNDRV_PCM_FMTBIT_S16_LE |
					SNDRV_PCM_FMTBIT_S24_LE |
					SNDRV_PCM_FMTBIT_S32_LE;
		drv->capture.channels_min = 1;
		drv->capture.channels_max = 2;
		drv->capture.rates = SNDRV_PCM_RATE_8000_192000;
		drv->capture.formats = SNDRV_PCM_FMTBIT_S16_LE |
					SNDRV_PCM_FMTBIT_S24_LE |
					SNDRV_PCM_FMTBIT_S32_LE;
		drv->symmetric_rate = 1;

		route = devm_kzalloc(&pdev->dev, struct_size(route, ports, 1), GFP_KERNEL);
		if (!route) {
			ret = -ENOMEM;
			goto err_release_chans_clocks;
		}
		route->serdes = i;
		route->syncgen = i;
		route->nports = 1;
		route->ports[0] = i;
		route->clock = i;
		list_add(&route->list, &mca->routes);

		clk = of_clk_get(pdev->dev.of_node, i);
		mca->clk_parents[i] = clk;

		if (IS_ERR(clk)) {
			dev_err(&pdev->dev, "unable to obtain clock %s: %d\n",
				name, PTR_ERR(clk));
			ret = PTR_ERR(clk);
			goto err_release_chans_clocks;
		}

		irq = platform_get_irq_optional(pdev, i);
		if (irq >= 0) {
			dev_dbg(&pdev->dev, "have IRQs for cluster %d\n", i);
#if 0
			ret = devm_request_irq(&pdev->dev, irq, mca_interrupt,
						0, dev_name(&pdev->dev), cluster);
 			if (ret) {
	 			dev_err(&pdev->dev, "unable to register interrupt: %d\n", ret);
 				goto err_release_chans_clocks;
 			}
 			mca_poke(mca, i, REG_INTMASK, 0xffffffff);
#endif
		}

		for_each_pcm_streams(stream) {
			struct dma_chan *chan;
			bool is_tx = (stream == SNDRV_PCM_STREAM_PLAYBACK);
#ifndef USE_RXB_FOR_CAPTURE
			char *name = devm_kasprintf(&pdev->dev, GFP_KERNEL,
					is_tx ? "tx%da" : "rx%da", route->serdes);
#else
			char *name = devm_kasprintf(&pdev->dev, GFP_KERNEL,
					is_tx ? "tx%da" : "rx%db", route->serdes);
#endif

			chan = of_dma_request_slave_channel(pdev->dev.of_node, name);
			if (IS_ERR(chan)) {
				if (PTR_ERR(chan) != -EPROBE_DEFER)
					dev_err(&pdev->dev, "no %s DMA channel: %d\n",
						name, route->of_node, PTR_ERR(chan));

				ret = PTR_ERR(chan);
				goto err_release_chans_clocks;
			}

			route->chan[stream] = chan;
		}
	}

	list_for_each_entry(route, &mca->routes, list) {
		struct clk *clk;

		clk = mca->clk_parents[route->clock];
		if (!clk) {
			ret = -EINVAL;
			dev_err(&pdev->dev, "missing clock parent for route %pOF\n",
				route->of_node);
			goto err_release_chans_clocks;
		}

#if 0
		ret = clk_rate_exclusive_get(clk);
		if (ret) {
			dev_err(&pdev->dev, "unable to get clock rate exclusivity for %pOF\n",
				route->of_node);
			goto err_release_chans_clocks;
		}
#endif
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
	{}
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

MODULE_AUTHOR("Martin Povišer <povik+lin@cutebit.org>");
MODULE_DESCRIPTION("ASoC platform driver Apple Silicon SoCs");
MODULE_LICENSE("GPL");
