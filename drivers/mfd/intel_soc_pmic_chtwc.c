/*
 * MFD core driver for Intel Cherrytrail Whiskey Cove PMIC
 * Copyright (C) 2017 Hans de Goede <hdegoede@redhat.com>
 *
 * Based on various non upstream patches to support the CHT Whiskey Cove PMIC:
 * Copyright (C) 2013-2015 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <acpi/acpi_bus.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/mfd/core.h>
#include <linux/mfd/intel_chtwc.h>
#include <linux/mfd/intel_soc_pmic.h>
#include <linux/module.h>
#include <linux/regmap.h>

/* PMIC device registers */
#define REG_ADDR_MASK		0xff00
#define REG_ADDR_SHIFT		8
#define REG_OFFSET_MASK		0xff

/* Whiskey Cove PMIC share same ACPI ID between different platforms */
#define CHT_WC_HRV		3

static struct mfd_cell cht_wc_dev[] = {
	{
		.name = "cht_wcove_region",
	},
};

/*
 * The CHT Whiskey Cove covers multiple i2c addresses, with a 1 byte
 * register address space per i2c address, so we use 16 bit register
 * addresses where the high 8 bits contain the i2c client address.
 */
static int cht_wc_byte_reg_read(void *context, unsigned int reg,
				unsigned int *val)
{
	struct i2c_client *client = context;
	int ret, orig_addr = client->addr;

	if (reg & REG_ADDR_MASK)
		client->addr = (reg & REG_ADDR_MASK) >> REG_ADDR_SHIFT;
	else
		client->addr = CHT_WC_DEVICE1_ADDR;
	ret = i2c_smbus_read_byte_data(client, reg & REG_OFFSET_MASK);
	client->addr = orig_addr;

	if (ret < 0)
		return ret;

	*val = ret;
	return 0;
}

static int cht_wc_byte_reg_write(void *context, unsigned int reg,
				 unsigned int val)
{
	struct i2c_client *client = context;
	int ret, orig_addr = client->addr;

	if (reg & REG_ADDR_MASK)
		client->addr = (reg & REG_ADDR_MASK) >> REG_ADDR_SHIFT;
	else
		client->addr = CHT_WC_DEVICE1_ADDR;
	ret = i2c_smbus_write_byte_data(client, reg & REG_OFFSET_MASK, val);
	client->addr = orig_addr;

	return ret;
}

static const struct regmap_config cht_wc_regmap_cfg = {
	.reg_bits = 16,
	.val_bits = 8,
	.reg_write = cht_wc_byte_reg_write,
	.reg_read = cht_wc_byte_reg_read,
};

static int cht_wc_probe(struct i2c_client *client,
			const struct i2c_device_id *i2c_id)
{
	struct device *dev = &client->dev;
	struct intel_soc_pmic *pmic;
	acpi_handle handle;
	acpi_status status;
	unsigned long long hrv;
	int ret;

	handle = ACPI_HANDLE(dev);
	status = acpi_evaluate_integer(handle, "_HRV", NULL, &hrv);
	if (ACPI_FAILURE(status)) {
		dev_err(dev, "Failed to get PMIC hardware revision\n");
		return -ENODEV;
	}
	if (hrv != CHT_WC_HRV) {
		dev_err(dev, "Invalid PMIC hardware revision: %llu\n", hrv);
		return -ENODEV;
	}
	if (client->irq < 0) {
		dev_err(dev, "Invalid IRQ\n");
		return -ENODEV;
	}

	pmic = devm_kzalloc(dev, sizeof(*pmic), GFP_KERNEL);
	if (!pmic)
		return -ENOMEM;

	pmic->irq = client->irq;
	pmic->dev = dev;
	i2c_set_clientdata(client, pmic);

	pmic->regmap = devm_regmap_init(dev, NULL, client, &cht_wc_regmap_cfg);
	if (IS_ERR(pmic->regmap)) {
		ret = PTR_ERR(pmic->regmap);
		dev_err(dev, "Failed to initialise regmap: %d\n", ret);
		return ret;
	}

	ret = mfd_add_devices(dev, -1, cht_wc_dev, ARRAY_SIZE(cht_wc_dev),
			      NULL, 0, NULL);
	if (ret) {
		dev_err(dev, "Failed to add devices: %d\n", ret);
		return ret;
	}

	return 0;
}

static int cht_wc_remove(struct i2c_client *client)
{
	struct intel_soc_pmic *pmic = i2c_get_clientdata(client);

	mfd_remove_devices(pmic->dev);

	return 0;
}

static void cht_wc_shutdown(struct i2c_client *client)
{
	struct intel_soc_pmic *pmic = i2c_get_clientdata(client);

	disable_irq(pmic->irq);
}

#ifdef CONFIG_PM_SLEEP
static int cht_wc_suspend(struct device *dev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(dev);

	disable_irq(pmic->irq);
	return 0;
}

static int cht_wc_resume(struct device *dev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(dev);

//	enable_irq(pmic->irq);
	return 0;
}
#endif
static SIMPLE_DEV_PM_OPS(cht_wc_pm_ops, cht_wc_suspend, cht_wc_resume);

static const struct i2c_device_id cht_wc_i2c_id[] = {
	{ }
};
MODULE_DEVICE_TABLE(i2c, cht_wc_i2c_id);

static const struct acpi_device_id cht_wc_acpi_ids[] = {
	{ "INT34D3", },
	{ }
};
MODULE_DEVICE_TABLE(acpi, cht_wc_acpi_ids);

static struct i2c_driver cht_wc_driver = {
	.driver	= {
		.name	= "CHT Whiskey Cove PMIC",
		.pm     = &cht_wc_pm_ops,
		.acpi_match_table = ACPI_PTR(cht_wc_acpi_ids),
	},
	.probe = cht_wc_probe,
	.remove	= cht_wc_remove,
	.shutdown = cht_wc_shutdown,
	.id_table = cht_wc_i2c_id,
};

module_i2c_driver(cht_wc_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Hans de Goede <hdegoede@redhat.com>");
