// SPDX-License-Identifier: GPL-2.0-only
/*
 * Driver for Apple M1 FPWM
 *
 * Used for the keyboard backlight on at least some MacBook Pros.
 *
 * This driver requires a clock, which should provide the standard 24 MHz
 * reference clock rate on M1 systems.
 *
 * The actual hardware appears to provide interrupt facilities and
 * other unknown features, but those have not been reverse-engineered
 * yet.
 *
 * Hardware documentation:
 *
 *   https://github.com/AsahiLinux/docs/wiki/HW:MacBook-Pro-keyboard-backlight-(FPWM0)
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 *
 * Based on pwm-twl-led.c, which is:
 *
 * Copyright (C) 2012 Texas Instruments
 * Author: Peter Ujfalusi <peter.ujfalusi@ti.com>
 */

#include <linux/clk.h>
#include <linux/io.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>
#include <linux/slab.h>

#define FPWM_CONTROL		0x00
#define   CONTROL_UPDATE	   0x4239
#define   CONTROL_DISABLE	   0
#define FPWM_STATUS		0x08
#define FPWM_COUNT_OFF		0x18
#define FPWM_COUNT_ON		0x1c

struct fpwm_chip {
	struct pwm_chip chip;
	void __iomem *reg;
	struct clk *clk;
	u64 rate;
};

static inline struct fpwm_chip *to_fpwm(struct pwm_chip *chip)
{
	return container_of(chip, struct fpwm_chip, chip);
}

static int fpwm_config(struct pwm_chip *chip, struct pwm_device *pwm,
		       int duty_ns, int period_ns)
{
	struct fpwm_chip *fpwm = to_fpwm(chip);
	long duty_ticks = div_u64(duty_ns * fpwm->rate, 1000000000);
	long period_ticks = div_u64(period_ns * fpwm->rate, 1000000000);
	long off_ticks = period_ticks - duty_ticks;

	writel(duty_ticks, fpwm->reg + FPWM_COUNT_ON);
	writel(off_ticks, fpwm->reg + FPWM_COUNT_OFF);
	writel(CONTROL_UPDATE, fpwm->reg + FPWM_CONTROL);

	return 0;
}

static int fpwm_enable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct fpwm_chip *fpwm = to_fpwm(chip);

	writel(CONTROL_UPDATE, fpwm->reg + FPWM_CONTROL);

	return 0;
}

static void fpwm_disable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct fpwm_chip *fpwm = to_fpwm(chip);

	writel(CONTROL_DISABLE, fpwm->reg + FPWM_CONTROL);
}

static const struct pwm_ops fpwm_ops = {
	.enable = fpwm_enable,
	.disable = fpwm_disable,
	.config = fpwm_config,
	.owner = THIS_MODULE,
};

static int fpwm_probe(struct platform_device *pdev)
{
	struct fpwm_chip *fpwm;
	struct resource *res;
	int ret;

	fpwm = devm_kzalloc(&pdev->dev, sizeof(*fpwm), GFP_KERNEL);
	if (!fpwm)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	fpwm->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(fpwm->clk))
		return PTR_ERR(fpwm->clk);

	ret = clk_prepare_enable(fpwm->clk);
	if (ret)
		return ret;

	fpwm->rate = clk_get_rate(fpwm->clk);

	fpwm->reg = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(fpwm->reg)) {
		clk_disable_unprepare(fpwm->clk);
		return PTR_ERR(fpwm->reg);
	}

	fpwm->chip.ops = &fpwm_ops;
	fpwm->chip.npwm = 1;
	fpwm->chip.dev = &pdev->dev;
	fpwm->chip.base = -1;

	ret = devm_pwmchip_add(&pdev->dev, &fpwm->chip);
	if (ret < 0) {
		clk_disable_unprepare(fpwm->clk);
		return ret;
	}

	platform_set_drvdata(pdev, fpwm);

	return 0;
}

static int fpwm_remove(struct platform_device *pdev)
{
	struct fpwm_chip *fpwm = platform_get_drvdata(pdev);

	clk_disable_unprepare(fpwm->clk);

	return 0;
}

static const struct of_device_id fpwm_of_match[] = {
	{ .compatible = "apple,t8103-fpwm" },
	{ },
};
MODULE_DEVICE_TABLE(of, fpwm_of_match);

static struct platform_driver fpwm_driver = {
	.driver = {
		.name = "apple-m1-fpwm",
		.of_match_table = of_match_ptr(fpwm_of_match),
	},
	.probe = fpwm_probe,
	.remove = fpwm_remove,
};
module_platform_driver(fpwm_driver);

MODULE_AUTHOR("Pip Cet <pipcet@gmail.com>");
MODULE_DESCRIPTION("PWM driver for Apple M1 FPWM");
MODULE_LICENSE("GPL");
