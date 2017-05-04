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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include "clk-pll.h"
#include "clk-regmap.h"

static struct pll_freq_tbl a53pll_freq[] = {
	{  998400000, 52, 0x0, 0x1, 0 },
	{ 1094400000, 57, 0x0, 0x1, 0 },
	{ 1152000000, 62, 0x0, 0x1, 0 },
	{ 1209600000, 65, 0x0, 0x1, 0 },
	{ 1401600000, 73, 0x0, 0x1, 0 },
};

static const struct regmap_config a53pll_regmap_config = {
	.reg_bits		= 32,
	.reg_stride		= 4,
	.val_bits		= 32,
	.max_register		= 0x40,
	.fast_io		= true,
	.val_format_endian	= REGMAP_ENDIAN_LITTLE,
};

static const struct of_device_id qcom_a53pll_match_table[] = {
	{ .compatible = "qcom,a53-pll" },
	{ }
};
MODULE_DEVICE_TABLE(of, qcom_a53pll_match_table);

static int qcom_a53pll_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct clk_pll *pll;
	struct resource *res;
	void __iomem *base;
	struct regmap *regmap;
	struct clk_init_data init;

	pll = devm_kzalloc(dev, sizeof(*pll), GFP_KERNEL);
	if (!pll)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	base = devm_ioremap_resource(dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	regmap = devm_regmap_init_mmio(dev, base, &a53pll_regmap_config);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);

	pll->l_reg = 0x04,
	pll->m_reg = 0x08,
	pll->n_reg = 0x0c,
	pll->config_reg = 0x14,
	pll->mode_reg = 0x00,
	pll->status_reg = 0x1c,
	pll->status_bit = 16,
	pll->freq_tbl = a53pll_freq,

	init.name = "a53pll",
	init.parent_names = (const char *[]){ "xo" },
	init.num_parents = 1,
	init.ops = &clk_pll_sr2_ops,
	pll->clkr.hw.init = &init;

	return devm_clk_register_regmap(dev, &pll->clkr);
}

static struct platform_driver qcom_a53pll_driver = {
	.probe = qcom_a53pll_probe,
	.driver = {
		.name = "qcom-a53pll",
		.of_match_table = qcom_a53pll_match_table,
	},
};

module_platform_driver(qcom_a53pll_driver);
MODULE_DESCRIPTION("Qualcomm A53 PLL Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:qcom-a53pll");
