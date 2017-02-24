/*
 * Power button driver for Dollar Cove TI PMIC
 * Copyright (C) 2014 Intel Corp
 * Copyright (c) 2017 Takashi Iwai <tiwai@suse.de>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/input.h>
#include <linux/mfd/intel_soc_pmic.h>

#define DC_TI_SIRQ_REG		0x3
#define SIRQ_PWRBTN_REL		(1 << 0)

#define DRIVER_NAME "dc_ti_pwrbtn"

static irqreturn_t dc_ti_pwrbtn_interrupt(int irq, void *dev_id)
{
	struct input_dev *pwrbtn_input = dev_id;
	struct device *dev = pwrbtn_input->dev.parent;
	struct regmap *regmap = dev_get_drvdata(dev);
	int state;

	if (!regmap_read(regmap, DC_TI_SIRQ_REG, &state)) {
		dev_dbg(dev, "SIRQ_REG=0x%x\n", state);
		state &= SIRQ_PWRBTN_REL;
		input_event(pwrbtn_input, EV_KEY, KEY_POWER, !state);
		input_sync(pwrbtn_input);
	}

	return IRQ_HANDLED;
}

static int dc_ti_pwrbtn_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct intel_soc_pmic *pmic = dev_get_drvdata(dev->parent);
	struct input_dev *pwrbtn_input;
	int irq;
	int ret;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return -EINVAL;
	pwrbtn_input = devm_input_allocate_device(dev);
	if (!pwrbtn_input)
		return -ENOMEM;
	pwrbtn_input->name = pdev->name;
	pwrbtn_input->phys = "dc-ti-power/input0";
	pwrbtn_input->id.bustype = BUS_HOST;
	pwrbtn_input->dev.parent = dev;
	input_set_capability(pwrbtn_input, EV_KEY, KEY_POWER);
	ret = input_register_device(pwrbtn_input);
	if (ret)
		return ret;

	dev_set_drvdata(dev, pmic->regmap);

	ret = devm_request_threaded_irq(dev, irq, NULL, dc_ti_pwrbtn_interrupt,
					0, KBUILD_MODNAME, pwrbtn_input);
	if (ret)
		return ret;

	ret = enable_irq_wake(irq);
	if (ret)
		dev_warn(dev, "Can't enable IRQ as wake source: %d\n", ret);

	return 0;
}

static struct platform_driver dc_ti_pwrbtn_driver = {
	.driver = {
		.name = DRIVER_NAME,
	},
	.probe	= dc_ti_pwrbtn_probe,
};

module_platform_driver(dc_ti_pwrbtn_driver);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRIVER_NAME);
