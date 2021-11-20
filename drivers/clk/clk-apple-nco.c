// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple NCO (Numerically Controlled Oscillator) clock driver
 *
 * Driver for an SoC block found on t8103 (M1) and other Apple chips
 *
 * Copyright (C) The Asahi Linux Contributors
 */

#include <linux/bits.h>
#include <linux/clk-provider.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_clk.h>
#include <linux/platform_device.h>
#include <linux/io.h>

#define NCO_CHANNEL_STRIDE	0x4000

#define REG_CTRL	0
#define CTRL_ENABLE	BIT(31)
#define REG_DIV		4
#define DIV_FINE	GENMASK(1, 0)
#define DIV_COARSE	GENMASK(12, 2)
#define REG_INC1	8
#define REG_INC2	12
#define REG_ACCINIT	16

struct nco_tables;

struct nco_channel {
	void __iomem *base;
	struct nco_tables *tbl;
	struct clk_hw hw;
};

#define to_nco_channel(_hw) container_of(_hw, struct nco_channel, hw)

#define LFSR_POLY	0xa01
#define LFSR_INIT	0x7ff
#define LFSR_LEN	11
#define LFSR_PERIOD	((1 << LFSR_LEN) - 1)
#define LFSR_TBLSIZE	(1 << LFSR_LEN)

/* The minimal attainable coarse divisor (first value in table) */
#define COARSE_DIV_OFFSET 2

struct nco_tables {
	u16 fwd[LFSR_TBLSIZE];
	u16 inv[LFSR_TBLSIZE];
};

static int nco_enable(struct clk_hw *hw);
static void nco_disable(struct clk_hw *hw);
static int nco_is_enabled(struct clk_hw *hw);

static void nco_compute_tables(struct nco_tables *tbl)
{
	int i;
	u32 state = LFSR_INIT;

	/*
	 * Go through the states of a galois LFSR and build
	 * a coarse divisor translation table.
	 */
	for (i = LFSR_PERIOD; i > 0; i--) {
		if (state & 1)
			state = (state >> 1) ^ (LFSR_POLY >> 1);
		else
			state = (state >> 1);
		tbl->fwd[i] = state;
		tbl->inv[state] = i;
	}

	/* Zero value is special-cased */
	tbl->fwd[0] = 0;
	tbl->inv[0] = 0;
}

static bool nco_div_check(int div)
{
	int coarse = div / 4;
	return coarse >= COARSE_DIV_OFFSET &&
		coarse < COARSE_DIV_OFFSET + LFSR_TBLSIZE;
}

static u32 nco_div_translate(struct nco_tables *tbl, int div)
{
	int coarse = div / 4;

	if (WARN_ON(!nco_div_check(div)))
		return 0;

	return FIELD_PREP(DIV_COARSE, tbl->fwd[coarse - COARSE_DIV_OFFSET]) |
			FIELD_PREP(DIV_FINE, div % 4);
}

static int nco_div_translate_inv(struct nco_tables *tbl, int regval)
{
	int coarse, fine;

	coarse = tbl->inv[FIELD_GET(DIV_COARSE, regval)] + COARSE_DIV_OFFSET;
	fine = FIELD_GET(DIV_FINE, regval);

	return coarse * 4 + fine;
}

static int nco_set_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long parent_rate)
{
	struct nco_channel *chan = to_nco_channel(hw);
	u32 div;
	s32 inc1, inc2;
	bool was_enabled;

	was_enabled = nco_is_enabled(hw);
	nco_disable(hw);

	div = 2 * parent_rate / rate;
	inc1 = 2 * parent_rate - div * rate;
	inc2 = -((s32) (rate - inc1));

	if (!nco_div_check(div))
		return -EINVAL;

	div = nco_div_translate(chan->tbl, div);

	writel_relaxed(div,  chan->base + REG_DIV);
	writel_relaxed(inc1, chan->base + REG_INC1);
	writel_relaxed(inc2, chan->base + REG_INC2);
	writel_relaxed(1 << 31, chan->base + REG_ACCINIT);

	if (was_enabled)
		nco_enable(hw);

	return 0;
}

static unsigned long nco_recalc_rate(struct clk_hw *hw,
				unsigned long parent_rate)
{
	struct nco_channel *chan = to_nco_channel(hw);
	u32 div;
	s32 inc1, inc2, incbase;

	div = nco_div_translate_inv(chan->tbl,
			readl_relaxed(chan->base + REG_DIV));

	inc1 = readl_relaxed(chan->base + REG_INC1);
	inc2 = readl_relaxed(chan->base + REG_INC2);

	/*
	 * We don't support wraparound of accumulator
	 * nor the edge case of both increments being zero
	 */
	if (inc1 < 0 || inc2 > 0 || (inc1 == 0 && inc2 == 0))
		return 0;

	/* Scale both sides of division by incbase to maintain precision */
	incbase = inc1 - inc2;

	return div_u64(((u64) parent_rate) * 2 * incbase,
			((u64) div) * incbase + inc1);
}

static long nco_round_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long *parent_rate)
{
	unsigned long lo = *parent_rate / (COARSE_DIV_OFFSET + LFSR_TBLSIZE) + 1;
	unsigned long hi = *parent_rate / COARSE_DIV_OFFSET;

	return clamp(rate, lo, hi);
}

static int nco_enable(struct clk_hw *hw)
{
	struct nco_channel *chan = to_nco_channel(hw);
	u32 val;

	val = readl_relaxed(chan->base + REG_CTRL);
	writel_relaxed(val | CTRL_ENABLE, chan->base + REG_CTRL);
	return 0;
}

static void nco_disable(struct clk_hw *hw)
{
	struct nco_channel *chan = to_nco_channel(hw);
	u32 val;

	val = readl_relaxed(chan->base + REG_CTRL);
	writel_relaxed(val & ~CTRL_ENABLE, chan->base + REG_CTRL);
}

static int nco_is_enabled(struct clk_hw *hw)
{
	struct nco_channel *chan = to_nco_channel(hw);

	return (readl_relaxed(chan->base + REG_CTRL) & CTRL_ENABLE) != 0;
}

static const struct clk_ops nco_ops = {
	.set_rate = nco_set_rate,
	.recalc_rate = nco_recalc_rate,
	.round_rate = nco_round_rate,
	.enable = nco_enable,
	.disable = nco_disable,
	.is_enabled = nco_is_enabled,
};

static int apple_nco_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct clk_init_data init;
	struct clk_hw_onecell_data *onecell_data;
	const char *parent_name;
	void __iomem *regs;
	struct nco_tables *tbl;
	int nchannels;
	int ret, i;

	ret = of_property_read_u32(np, "apple,nchannels", &nchannels);
	if (ret) {
		dev_err(&pdev->dev, "missing or invalid apple,nchannels property\n");
		return -EINVAL;
	}

	regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(regs))
		return PTR_ERR(regs);

	if (of_clk_get_parent_count(np) != 1)
		return -EINVAL;
	parent_name = of_clk_get_parent_name(np, 0);
	if (!parent_name)
		return -EINVAL;

	onecell_data = devm_kzalloc(&pdev->dev, struct_size(onecell_data, hws,
							nchannels), GFP_KERNEL);
	if (!onecell_data)
		return -ENOMEM;
	onecell_data->num = nchannels;

	tbl = devm_kzalloc(&pdev->dev, sizeof(*tbl), GFP_KERNEL);
	if (!tbl)
		return -ENOMEM;
	nco_compute_tables(tbl);

	for (i = 0; i < nchannels; i++) {
		struct nco_channel *chan;

		chan = devm_kzalloc(&pdev->dev, sizeof(*chan), GFP_KERNEL);
		if (!chan)
			return -ENOMEM;
		chan->base = regs + NCO_CHANNEL_STRIDE*i;
		chan->tbl = tbl;

		memset(&init, 0, sizeof(init));
		init.name = devm_kasprintf(&pdev->dev, GFP_KERNEL,
						"%s-%d", np->name, i);
		init.ops = &nco_ops;
		init.num_parents = 1;
		init.parent_names = &parent_name;
		init.flags = 0;

		chan->hw.init = &init;
		ret = devm_clk_hw_register(&pdev->dev, &chan->hw);
		if (ret)
			return ret;

		onecell_data->hws[i] = &chan->hw;
	}

	ret = devm_of_clk_add_hw_provider(&pdev->dev, of_clk_hw_onecell_get,
							onecell_data);
	if (ret)
		return ret;

	return 0;
}

static const struct of_device_id apple_nco_ids[] = {
	{ .compatible = "apple,nco" },
	{ },
};
MODULE_DEVICE_TABLE(of, apple_nco_ids)

static struct platform_driver apple_nco_driver = {
	.driver = {
		.name = "apple-nco",
		.of_match_table = apple_nco_ids,
	},
	.probe = apple_nco_probe,
};
module_platform_driver(apple_nco_driver);

MODULE_AUTHOR("Martin Povišer <povik@protonmail.com>");
MODULE_DESCRIPTION("Clock driver for NCO blocks on Apple SoCs");
MODULE_LICENSE("GPL v2");
