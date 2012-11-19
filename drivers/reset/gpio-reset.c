/*
 * GPIO Reset Controller driver
 *
 * Copyright 2013 Philipp Zabel, Pengutronix
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/reset-controller.h>

struct gpio_reset {
	unsigned int gpio;
	bool active_low;
};

struct gpio_reset_data {
	struct reset_controller_dev rcdev;
	/* these arrays contain a number of elements equal to rcdev.nr_resets */
	struct gpio_reset *gpios;
	u32 *delays_us;
};

static void __gpio_reset_set(struct reset_controller_dev *rcdev,
		unsigned long gpio_idx, int asserted)
{
	struct gpio_reset_data *drvdata = container_of(rcdev,
			struct gpio_reset_data, rcdev);
	int value = asserted;

	if (drvdata->gpios[gpio_idx].active_low)
		value = !value;

	gpio_set_value(drvdata->gpios[gpio_idx].gpio, value);
}

static int gpio_reset(struct reset_controller_dev *rcdev,
		unsigned long gpio_idx)
{
	struct gpio_reset_data *drvdata = container_of(rcdev,
			struct gpio_reset_data, rcdev);

	if (gpio_idx >= rcdev->nr_resets)
		return -EINVAL;

	if (drvdata->delays_us == NULL)
		return -ENOSYS;

	__gpio_reset_set(rcdev, gpio_idx, 1);
	udelay(drvdata->delays_us[gpio_idx]);
	__gpio_reset_set(rcdev, gpio_idx, 0);

	return 0;
}

static int gpio_reset_assert(struct reset_controller_dev *rcdev,
		unsigned long gpio_idx)
{
	if (gpio_idx >= rcdev->nr_resets)
		return -EINVAL;

	__gpio_reset_set(rcdev, gpio_idx, 1);

	return 0;
}

static int gpio_reset_deassert(struct reset_controller_dev *rcdev,
		unsigned long gpio_idx)
{
	if (gpio_idx >= rcdev->nr_resets)
		return -EINVAL;

	__gpio_reset_set(rcdev, gpio_idx, 0);

	return 0;
}

static struct reset_control_ops gpio_reset_ops = {
	.reset = gpio_reset,
	.assert = gpio_reset_assert,
	.deassert = gpio_reset_deassert,
};

static int gpio_reset_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct gpio_reset_data *drvdata;
	enum of_gpio_flags flags;
	u32 *initially_in_reset;
	int nr_gpios;
	int ret;
	int i;

	drvdata = devm_kzalloc(&pdev->dev, sizeof(*drvdata), GFP_KERNEL);
	if (drvdata == NULL)
		return -ENOMEM;

	nr_gpios = of_gpio_named_count(np, "reset-gpios");
	if (nr_gpios < 1)
		return -EINVAL;

	drvdata->gpios = devm_kzalloc(&pdev->dev, sizeof(struct gpio_reset) *
			nr_gpios, GFP_KERNEL);
	if (drvdata->gpios == NULL)
		return -ENOMEM;

	for (i = 0; i < nr_gpios; i++) {
		drvdata->gpios[i].gpio = of_get_named_gpio_flags(np,
				"reset-gpios", i, &flags);
		if (drvdata->gpios[i].gpio == -EPROBE_DEFER)
			return drvdata->gpios[i].gpio;
		else if (drvdata->gpios[i].gpio < 0) {
			dev_err(&pdev->dev, "invalid gpio for reset %d\n", i);
			return drvdata->gpios[i].gpio;
		}

		drvdata->gpios[i].active_low = flags & OF_GPIO_ACTIVE_LOW;
	}

	if (of_find_property(np, "reset-delays", NULL)) {
		drvdata->delays_us = devm_kzalloc(&pdev->dev, sizeof(u32) *
				nr_gpios, GFP_KERNEL);
		if (drvdata->delays_us == NULL)
			return -ENOMEM;

		ret = of_property_read_u32_array(np, "reset-delays",
				drvdata->delays_us, nr_gpios);
		if (ret < 0)
			return ret;
	}

	initially_in_reset = devm_kzalloc(&pdev->dev, sizeof(u32) *
			nr_gpios, GFP_KERNEL);
	if (initially_in_reset == NULL)
		return -ENOMEM;
	if (of_find_property(np, "initially-in-reset", NULL)) {
		ret = of_property_read_u32_array(np, "initially-in-reset",
				initially_in_reset, nr_gpios);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < nr_gpios; i++) {
		unsigned long gpio_flags = GPIOF_OUT_INIT_LOW;

		if (drvdata->gpios[i].active_low ^ (!!initially_in_reset[i]))
			gpio_flags = GPIOF_OUT_INIT_HIGH;

		ret = devm_gpio_request_one(&pdev->dev, drvdata->gpios[i].gpio,
				gpio_flags, NULL);
		if (ret < 0) {
			dev_err(&pdev->dev, "failed to request gpio %d for reset %d\n",
					drvdata->gpios[i].gpio, i);
			return ret;
		}
	}

	devm_kfree(&pdev->dev, initially_in_reset);

	drvdata->rcdev.of_node = np;
	drvdata->rcdev.owner = THIS_MODULE;
	drvdata->rcdev.nr_resets = nr_gpios;
	drvdata->rcdev.ops = &gpio_reset_ops;
	reset_controller_register(&drvdata->rcdev);

	platform_set_drvdata(pdev, drvdata);

	return 0;
}

static int gpio_reset_remove(struct platform_device *pdev)
{
	struct gpio_reset_data *drvdata = platform_get_drvdata(pdev);

	reset_controller_unregister(&drvdata->rcdev);

	return 0;
}

static struct of_device_id gpio_reset_dt_ids[] = {
	{ .compatible = "gpio-reset" },
	{ }
};

static struct platform_driver gpio_reset_driver = {
	.probe = gpio_reset_probe,
	.remove = gpio_reset_remove,
	.driver = {
		.name = "gpio-reset",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(gpio_reset_dt_ids),
	},
};

module_platform_driver(gpio_reset_driver);

MODULE_AUTHOR("Philipp Zabel <p.zabel@pengutronix.de>");
MODULE_DESCRIPTION("gpio reset controller");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:gpio-reset");
MODULE_DEVICE_TABLE(of, gpio_reset_dt_ids);
