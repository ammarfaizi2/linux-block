/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include "clk-regmap.h"
#include "clk-regmap-mux-div.h"

enum {
	P_GPLL0,
	P_A53PLL,
};

static const struct parent_map gpll0_a53cc_map[] = {
	{ P_GPLL0, 4 },
	{ P_A53PLL, 5 },
};

static const char * const gpll0_a53cc[] = {
	"gpll0_vote",
	"a53pll",
};

static const struct regmap_config a53cc_regmap_config = {
	.reg_bits		= 32,
	.reg_stride		= 4,
	.val_bits		= 32,
	.max_register		= 0x1000,
	.fast_io		= true,
	.val_format_endian	= REGMAP_ENDIAN_LITTLE,
};

static const struct of_device_id qcom_a53cc_match_table[] = {
	{ .compatible = "qcom,a53cc" },
	{ }
};
MODULE_DEVICE_TABLE(of, qcom_a53cc_match_table);

static int qcom_a53cc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct clk_regmap_mux_div *a53cc;
	struct resource *res;
	void __iomem *base;
	struct clk *pclk;
	struct regmap *regmap;
	struct clk_init_data init;
	int ret;

	a53cc = devm_kzalloc(dev, sizeof(*a53cc), GFP_KERNEL);
	if (!a53cc)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	base = devm_ioremap_resource(dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	a53cc->reg_offset = 0x50,
	a53cc->hid_width = 5,
	a53cc->hid_shift = 0,
	a53cc->src_width = 3,
	a53cc->src_shift = 8,
	a53cc->safe_src = 4,
	a53cc->safe_div = 3,
	a53cc->parent_map = gpll0_a53cc_map,

	init.name = "a53mux",
	init.parent_names = gpll0_a53cc,
	init.num_parents = 2,
	init.ops = &clk_regmap_mux_div_ops,
	init.flags = CLK_SET_RATE_PARENT;
	a53cc->clkr.hw.init = &init;

	pclk = __clk_lookup(gpll0_a53cc[1]);
	if (!pclk)
		return -EPROBE_DEFER;

	ret = clk_prepare_enable(pclk);
	if (ret) {
		dev_err(dev, "failed to enable %s: %d\n", gpll0_a53cc[1], ret);
		return ret;
	}

	regmap = devm_regmap_init_mmio(dev, base, &a53cc_regmap_config);
	if (IS_ERR(regmap)) {
		ret = PTR_ERR(regmap);
		dev_err(dev, "failed to init regmap mmio: %d\n", ret);
		goto err;
	}

	a53cc->clkr.regmap = regmap;

	ret = devm_clk_register_regmap(dev, &a53cc->clkr);
	if (ret) {
		dev_err(dev, "failed to register regmap clock: %d\n", ret);
		goto err;
	}

	ret = of_clk_add_hw_provider(dev->of_node, of_clk_hw_simple_get, &a53cc->clkr.hw);
	if (ret) {
		dev_err(dev, "failed to add clock provider: %d\n", ret);
		goto err;
	}

	return 0;
err:
	return ret;
}

static struct platform_driver qcom_a53cc_driver = {
	.probe = qcom_a53cc_probe,
	.driver = {
		.name = "qcom-a53cc",
		.of_match_table = qcom_a53cc_match_table,
	},
};

module_platform_driver(qcom_a53cc_driver);
MODULE_DESCRIPTION("Qualcomm A53 Clock Controller Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:qcom-a53cc");
