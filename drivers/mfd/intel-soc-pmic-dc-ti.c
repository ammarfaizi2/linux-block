/*
 * Device access for Dollar Cove TI PMIC
 */

#include <linux/module.h>
#include <linux/mfd/core.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/gpio/consumer.h>
#include <linux/acpi.h>
#include <linux/regmap.h>
#include <linux/mfd/intel_soc_pmic.h>
#include <linux/gpio/machine.h>
#include "intel_soc_pmic_core.h"

#define IRQLVL1		0x01
#define MIRQLVL1	0x02

enum {
	PWRBTN = 0,
	DIETMPWARN,
	ADCCMPL,
	VBATLOW = 4,
	VBUSDET,
	CCEOCAL = 7,
};

static struct resource power_button_resources[] = {
	{
		.name	= "PWRBTN",
		.start	= PWRBTN,
		.end	= PWRBTN,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct resource thermal_resources[] = {
	{
		.name  = "DIETMPWARN",
		.start = DIETMPWARN,
		.end   = DIETMPWARN,
		.flags = IORESOURCE_IRQ,
	},
};

static struct resource adc_resources[] = {
	{
		.name  = "ADCCMPL",
		.start = ADCCMPL,
		.end   = ADCCMPL,
		.flags = IORESOURCE_IRQ,
	},
};

static struct resource pwrsrc_resources[] = {
	{
		.name  = "VBUSDET",
		.start = VBUSDET,
		.end   = VBUSDET,
		.flags = IORESOURCE_IRQ,
	},
};

static struct resource battery_resources[] = {
	{
		.name  = "VBATLOW",
		.start = VBATLOW,
		.end   = VBATLOW,
		.flags = IORESOURCE_IRQ,
	},
	{
		.name  = "CCEOCAL",
		.start = CCEOCAL,
		.end   = CCEOCAL,
		.flags = IORESOURCE_IRQ,
	},
};

static struct mfd_cell dollar_cove_ti_dev[] = {
	{
		.name = "dollar_cove_ti_adc",
		.num_resources = ARRAY_SIZE(adc_resources),
		.resources = adc_resources,
	},
	{
		.name = "dollar_cove_ti_power_button",
		.num_resources = ARRAY_SIZE(power_button_resources),
		.resources = power_button_resources,
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
		.name = "intel_fuel_gauge",
	},
	{
		.name = "intel_fg_iface",
	},
	{
		.name = "dollar_cove_ti_pmic",
	},
};

static const struct regmap_config dollar_cove_ti_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = 128, /* FIXME: which value to set? */
	.cache_type = REGCACHE_NONE,
};

static const struct regmap_irq dollar_cove_ti_irqs[] = {
	[PWRBTN] = {
		.mask = BIT(PWRBTN),
	},
	[DIETMPWARN] = {
		.mask = BIT(DIETMPWARN),
	},
	[ADCCMPL] = {
		.mask = BIT(ADCCMPL),
	},
	[VBATLOW] = {
		.mask = BIT(VBATLOW),
	},
	[VBUSDET] = {
		.mask = BIT(VBUSDET),
	},
	[CCEOCAL] = {
		.mask = BIT(CCEOCAL),
	},
};

static const struct regmap_irq_chip dollar_cove_ti_irq_chip = {
	.name = "Dollar Cove TI",
	.irqs = dollar_cove_ti_irqs,
	.num_irqs = ARRAY_SIZE(dollar_cove_ti_irqs),
	.num_regs = 1,
	.status_base = IRQLVL1,
	.mask_base = MIRQLVL1,
	.ack_base = IRQLVL1,
};

static struct intel_soc_pmic_config intel_soc_pmic_config_dc_ti = {
	.irq_flags = IRQF_TRIGGER_RISING,
	.cell_dev = dollar_cove_ti_dev,
	.n_cell_devs = ARRAY_SIZE(dollar_cove_ti_dev),
	.regmap_config = &dollar_cove_ti_regmap_config,
	.irq_chip = &dollar_cove_ti_irq_chip,
};

static int intel_soc_pmic_find_gpio_irq(struct device *dev)
{
	struct gpio_desc *desc;
	int irq;

	desc = devm_gpiod_get_index(dev, "intel_soc_pmic", 0, GPIOD_IN);
	if (IS_ERR(desc))
		return PTR_ERR(desc);

	irq = gpiod_to_irq(desc);
	if (irq < 0)
		dev_warn(dev, "Can't get irq: %d\n", irq);

	return irq;
}

static int intel_soc_pmic_dc_ti_i2c_probe(struct i2c_client *i2c,
					  const struct i2c_device_id *i2c_id)
{
	struct device *dev = &i2c->dev;
	const struct acpi_device_id *id;
	struct intel_soc_pmic_config *config;
	struct intel_soc_pmic *pmic;
	int ret;
	int irq;

	id = acpi_match_device(dev->driver->acpi_match_table, dev);
	if (!id || !id->driver_data)
		return -ENODEV;

	config = (struct intel_soc_pmic_config *)id->driver_data;

	pmic = devm_kzalloc(dev, sizeof(*pmic), GFP_KERNEL);
	if (!pmic)
		return -ENOMEM;

	dev_set_drvdata(dev, pmic);

	pmic->regmap = devm_regmap_init_i2c(i2c, config->regmap_config);

	/*
	 * On some boards the PMIC interrupt may come from a GPIO line. Try to
	 * lookup the ACPI table for a such connection and setup a GPIO
	 * interrupt if it exists. Otherwise use the IRQ provided by I2C
	 */
	irq = intel_soc_pmic_find_gpio_irq(dev);
	pmic->irq = (irq < 0) ? i2c->irq : irq;

	ret = regmap_add_irq_chip(pmic->regmap, pmic->irq,
				  config->irq_flags | IRQF_ONESHOT,
				  0, config->irq_chip,
				  &pmic->irq_chip_data);
	if (ret)
		return ret;

	ret = enable_irq_wake(pmic->irq);
	if (ret)
		dev_warn(dev, "Can't enable IRQ as wake source: %d\n", ret);

	ret = mfd_add_devices(dev, -1, config->cell_dev,
			      config->n_cell_devs, NULL, 0,
			      regmap_irq_get_domain(pmic->irq_chip_data));
	if (ret)
		goto err_del_irq_chip;

	return 0;

err_del_irq_chip:
	regmap_del_irq_chip(pmic->irq, pmic->irq_chip_data);
	return ret;
}

static int intel_soc_pmic_dc_ti_i2c_remove(struct i2c_client *i2c)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(&i2c->dev);

	regmap_del_irq_chip(pmic->irq, pmic->irq_chip_data);

	mfd_remove_devices(&i2c->dev);

	return 0;
}

static void intel_soc_pmic_dc_ti_shutdown(struct i2c_client *i2c)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(&i2c->dev);

	disable_irq(pmic->irq);

	return;
}

#if defined(CONFIG_PM_SLEEP)
static int intel_soc_pmic_dc_ti_suspend(struct device *dev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(dev);

	disable_irq(pmic->irq);

	return 0;
}

static int intel_soc_pmic_dc_ti_resume(struct device *dev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(dev);

	enable_irq(pmic->irq);

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(intel_soc_pmic_dc_ti_pm_ops,
			 intel_soc_pmic_dc_ti_suspend,
			 intel_soc_pmic_dc_ti_resume);

static const struct i2c_device_id intel_soc_pmic_dc_ti_i2c_id[] = {
	{ }
};
MODULE_DEVICE_TABLE(i2c, intel_soc_pmic_dc_ti_i2c_id);

#ifdef CONFIG_ACPI
static const struct acpi_device_id intel_soc_pmic_dc_ti_acpi_match[] = {
	{"INT33F5", (kernel_ulong_t)&intel_soc_pmic_config_dc_ti},
	{ },
};
MODULE_DEVICE_TABLE(acpi, intel_soc_pmic_dc_ti_acpi_match);
#endif

static struct i2c_driver intel_soc_pmic_dc_ti_i2c_driver = {
	.driver = {
		.name = "intel_soc_pmic_dc_ti_i2c",
		.pm = &intel_soc_pmic_dc_ti_pm_ops,
		.acpi_match_table = ACPI_PTR(intel_soc_pmic_dc_ti_acpi_match),
	},
	.probe = intel_soc_pmic_dc_ti_i2c_probe,
	.remove = intel_soc_pmic_dc_ti_i2c_remove,
	.id_table = intel_soc_pmic_dc_ti_i2c_id,
	.shutdown = intel_soc_pmic_dc_ti_shutdown,
};

module_i2c_driver(intel_soc_pmic_dc_ti_i2c_driver);

MODULE_DESCRIPTION("I2C driver for Intel SoC Dollar Cove TI PMIC");
MODULE_LICENSE("GPL v2");
