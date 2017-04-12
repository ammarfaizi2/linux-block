/*
 * intel_pmic_dc_ti.c - TI Dollar Cove PMIC operation region drive
 *
 * Copyright (C) 2014 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/platform_device.h>
#include <linux/mfd/intel_soc_pmic.h>
#include "intel_pmic.h"

#define TI_DC_PMICTEMP_LOW	0x57
#define TI_DC_BATTEMP_LOW	0x59
#define TI_DC_GPADC_LOW	0x5b

static struct pmic_table power_table[] = {
	{
		.address = 0x00,
		.reg = 0x41,
		.bit = 0x00,
	},
	{
		.address = 0x04,
		.reg = 0x42,
		.bit = 0x00,
	},
	{
		.address = 0x08,
		.reg = 0x43,
		.bit = 0x00,
	},
	{
		.address = 0x0c,
		.reg = 0x45,
		.bit = 0x00,
	},
	{
		.address = 0x10,
		.reg = 0x46,
		.bit = 0x00,
	},
	{
		.address = 0x14,
		.reg = 0x47,
		.bit = 0x00,
	},
	{
		.address = 0x18,
		.reg = 0x48,
		.bit = 0x00,
	},
	{
		.address = 0x1c,
		.reg = 0x49,
		.bit = 0x00,
	},
	{
		.address = 0x20,
		.reg = 0x4A,
		.bit = 0x00,
	},
	{
		.address = 0x24,
		.reg = 0x4B,
		.bit = 0x00,
	},
	{
		.address = 0x28,
		.reg = 0x4C,
		.bit = 0x00,
	},
	{
		.address = 0x2c,
		.reg = 0x4D,
		.bit = 0x00,
	},
	{
		.address = 0x30,
		.reg = 0x4E,
		.bit = 0x00,
	},
};

static struct pmic_table thermal_table[] = {
	{
		.address = 0x00,
		.reg = TI_DC_GPADC_LOW
	},
	{
		.address = 0x0c,
		.reg = TI_DC_GPADC_LOW
	},
	{
		.address = 0x18,
		.reg = TI_DC_GPADC_LOW
	}, /* TMP2 -> SYSTEMP */
	{
		.address = 0x24,
		.reg = TI_DC_BATTEMP_LOW
	}, /* TMP3 -> BATTEMP */
	{
		.address = 0x30,
		.reg = TI_DC_GPADC_LOW
	},
	{
		.address = 0x3c,
		.reg = TI_DC_PMICTEMP_LOW
	}, /* TMP5 -> PMICTEMP */
};

static int dollar_cove_ti_pmic_get_power(struct regmap *regmap, int reg,
					 int bit, u64 *value)
{
	int data;

	if (regmap_read(regmap, reg, &data))
		return -EIO;

	*value = data && (data & BIT(bit)) ? 1 : 0;
	return 0;
}

static int dollar_cove_ti_pmic_update_power(struct regmap *regmap, int reg,
					    int bit, bool on)
{
	int data;

	if (regmap_read(regmap, reg, &data))
		return -EIO;

	if (on)
		data |= BIT(bit);
	else
		data &= ~BIT(bit);

	if (regmap_write(regmap, reg, data))
		return -EIO;
	return 0;
}

static int dollar_cove_ti_pmic_get_raw_temp(struct regmap *regmap, int reg)
{
	int temp_l, temp_h;

	if (regmap_read(regmap, reg, &temp_l) ||
	    regmap_read(regmap, reg - 1, &temp_h))
		return -EIO;

	return temp_l | (temp_h & 0x3) << 8;
}

static struct intel_pmic_opregion_data dollar_cove_ti_pmic_opregion_data = {
	.get_power = dollar_cove_ti_pmic_get_power,
	.update_power = dollar_cove_ti_pmic_update_power,
	.get_raw_temp = dollar_cove_ti_pmic_get_raw_temp,
	.power_table = power_table,
	.power_table_count = ARRAY_SIZE(power_table),
	.thermal_table = thermal_table,
	.thermal_table_count = ARRAY_SIZE(thermal_table),
};

static int dollar_cove_ti_pmic_opregion_probe(struct platform_device *pdev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(pdev->dev.parent);

	return intel_pmic_install_opregion_handler(&pdev->dev,
			ACPI_HANDLE(pdev->dev.parent), pmic->regmap,
			&dollar_cove_ti_pmic_opregion_data);
}

static struct platform_driver dollar_cove_ti_pmic_opregion_driver = {
	.probe = dollar_cove_ti_pmic_opregion_probe,
	.driver = {
		.name = "dollar_cove_ti_pmic",
	},
};

static int __init dollar_cove_ti_pmic_opregion_driver_init(void)
{
	return platform_driver_register(&dollar_cove_ti_pmic_opregion_driver);
}
device_initcall(dollar_cove_ti_pmic_opregion_driver_init);
