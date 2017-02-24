/*
 * Device access for Dollar Cove TI PMIC
 * Copyright (c) 2014, Intel Corporation.
 *   Author: Ramakrishna Pallala <ramakrishna.pallala@intel.com>
 * Cleanup and forward-ported by Takashi Iwai <tiwai@suse.de>
 */

#include <linux/module.h>
#include <linux/mfd/core.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/gpio/consumer.h>
#include <linux/acpi.h>
#include <linux/regmap.h>
#include <linux/mfd/intel_soc_pmic.h>

#define DC_TI_IRQLVL1		0x01
#define DC_TI_MASK_IRQLVL1	0x02

#define DC_TI_PWRBTN		0
#define DC_TI_DIETMPWARN	1
#define DC_TI_ADCCMPL		2
#define DC_TI_VBATLOW		4
#define DC_TI_VBUSDET		5
#define DC_TI_CCEOCAL		7

static struct resource power_button_resources[] = {
	DEFINE_RES_IRQ_NAMED(DC_TI_PWRBTN, "PWRBTN"),
};

static struct resource thermal_resources[] = {
	DEFINE_RES_IRQ_NAMED(DC_TI_DIETMPWARN, "DIETMPWARN"),
};

static struct resource adc_resources[] = {
	DEFINE_RES_IRQ_NAMED(DC_TI_ADCCMPL, "ADCCMPL"),
};

static struct resource pwrsrc_resources[] = {
	DEFINE_RES_IRQ_NAMED(DC_TI_VBUSDET, "VBUSDET"),
};

static struct resource battery_resources[] = {
	DEFINE_RES_IRQ_NAMED(DC_TI_VBATLOW, "VBATLOW"),
	DEFINE_RES_IRQ_NAMED(DC_TI_CCEOCAL, "CCEOCAL"),
};

static struct mfd_cell dc_ti_dev[] = {
	{
		.name = "dollar_cove_ti_power_button",
		.num_resources = ARRAY_SIZE(power_button_resources),
		.resources = power_button_resources,
	},
	{
		.name = "dollar_cove_ti_adc",
		.num_resources = ARRAY_SIZE(adc_resources),
		.resources = adc_resources,
	},
	{
		.name = "dollar_cove_ti_thermal",
		.num_resources = ARRAY_SIZE(thermal_resources),
		.resources = thermal_resources,
	},
	{
		.name = "dollar_cove_ti_pwrsrc",
		.num_resources = ARRAY_SIZE(pwrsrc_resources),
		.resources = pwrsrc_resources,
	},
	{
		.name = "dollar_cove_ti_cc",
		.num_resources = ARRAY_SIZE(battery_resources),
		.resources = battery_resources,
	},
	{
		.name = "dollar_cove_ti_pmic",
	},
};

static const struct regmap_config dc_ti_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = 128,
	.cache_type = REGCACHE_NONE,
};

static const struct regmap_irq dc_ti_irqs[] = {
	REGMAP_IRQ_REG(DC_TI_PWRBTN, 0, BIT(DC_TI_PWRBTN)),
	REGMAP_IRQ_REG(DC_TI_DIETMPWARN, 0, BIT(DC_TI_DIETMPWARN)),
	REGMAP_IRQ_REG(DC_TI_ADCCMPL, 0, BIT(DC_TI_ADCCMPL)),
	REGMAP_IRQ_REG(DC_TI_VBATLOW, 0, BIT(DC_TI_VBATLOW)),
	REGMAP_IRQ_REG(DC_TI_VBUSDET, 0, BIT(DC_TI_VBUSDET)),
	REGMAP_IRQ_REG(DC_TI_CCEOCAL, 0, BIT(DC_TI_CCEOCAL)),
};

static const struct regmap_irq_chip dc_ti_irq_chip = {
	.name = "Dollar Cove TI",
	.irqs = dc_ti_irqs,
	.num_irqs = ARRAY_SIZE(dc_ti_irqs),
	.num_regs = 1,
	.status_base = DC_TI_IRQLVL1,
	.mask_base = DC_TI_MASK_IRQLVL1,
	.ack_base = DC_TI_IRQLVL1,
};

static int dc_ti_probe(struct i2c_client *i2c,
		       const struct i2c_device_id *i2c_id)
{
	struct device *dev = &i2c->dev;
	struct intel_soc_pmic *pmic;
	struct gpio_desc *desc;
	int ret;

	pmic = devm_kzalloc(dev, sizeof(*pmic), GFP_KERNEL);
	if (!pmic)
		return -ENOMEM;

	dev_set_drvdata(dev, pmic);

	pmic->regmap = devm_regmap_init_i2c(i2c, &dc_ti_regmap_config);
	if (IS_ERR(pmic->regmap))
		return PTR_ERR(pmic->regmap);

	pmic->irq = i2c->irq;
	desc = devm_gpiod_get_index(dev, KBUILD_MODNAME, 0, GPIOD_IN);
	if (!IS_ERR(desc)) {
		int irq = gpiod_to_irq(desc);

		if (irq >= 0)
			pmic->irq = irq;
	}

	ret = regmap_add_irq_chip(pmic->regmap, pmic->irq,
				  IRQF_TRIGGER_HIGH | IRQF_ONESHOT, 0,
				  &dc_ti_irq_chip, &pmic->irq_chip_data);
	if (ret)
		return ret;

	ret = enable_irq_wake(pmic->irq);
	if (ret)
		dev_warn(dev, "Can't enable IRQ as wake source: %d\n", ret);

	ret = mfd_add_devices(dev, -1, dc_ti_dev, ARRAY_SIZE(dc_ti_dev),
			      NULL, 0,
			      regmap_irq_get_domain(pmic->irq_chip_data));
	if (ret)
		goto error;

	return 0;

 error:
	regmap_del_irq_chip(pmic->irq, pmic->irq_chip_data);
	return ret;
}

static int dc_ti_remove(struct i2c_client *i2c)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(&i2c->dev);

	regmap_del_irq_chip(pmic->irq, pmic->irq_chip_data);
	mfd_remove_devices(&i2c->dev);

	return 0;
}

static void dc_ti_shutdown(struct i2c_client *i2c)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(&i2c->dev);

	disable_irq(pmic->irq);
}

#ifdef CONFIG_PM_SLEEP
static int dc_ti_suspend(struct device *dev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(dev);

	disable_irq(pmic->irq);
	return 0;
}

static int dc_ti_resume(struct device *dev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(dev);

	enable_irq(pmic->irq);
	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(dc_ti_pm_ops, dc_ti_suspend, dc_ti_resume);

static const struct i2c_device_id dc_ti_i2c_id[] = {
	{ }
};

static const struct acpi_device_id dc_ti_acpi_ids[] = {
	{ "INT33F5" },
	{ },
};
MODULE_DEVICE_TABLE(acpi, dc_ti_acpi_ids);

static struct i2c_driver dc_ti_i2c_driver = {
	.driver = {
		.name = KBUILD_MODNAME,
		.pm = &dc_ti_pm_ops,
		.acpi_match_table = ACPI_PTR(dc_ti_acpi_ids),
	},
	.probe = dc_ti_probe,
	.remove = dc_ti_remove,
	.id_table = dc_ti_i2c_id,
	.shutdown = dc_ti_shutdown,
};

module_i2c_driver(dc_ti_i2c_driver);

MODULE_DESCRIPTION("I2C driver for Intel SoC Dollar Cove TI PMIC");
MODULE_LICENSE("GPL v2");
