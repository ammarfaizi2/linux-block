/*
 * Dollar Cove TI PMIC operation region driver
 * Copyright (C) 2014 Intel Corporation. All rights reserved.
 *
 * Rewritten and cleaned up
 * Copyright (C) 2017 Takashi Iwai <tiwai@suse.de>
 */

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/mfd/intel_soc_pmic.h>
#include <linux/platform_device.h>
#include "intel_pmic.h"

/* registers stored in 16bit BE (high:low, total 10bit) */
#define DC_TI_VBAT	0x54
#define DC_TI_DIETEMP	0x56
#define DC_TI_BPTHERM	0x58
#define DC_TI_GPADC	0x5a

static struct pmic_table dc_ti_power_table[] = {
	{ .address = 0x00, .reg = 0x41 },
	{ .address = 0x04, .reg = 0x42 },
	{ .address = 0x08, .reg = 0x43 },
	{ .address = 0x0c, .reg = 0x45 },
	{ .address = 0x10, .reg = 0x46 },
	{ .address = 0x14, .reg = 0x47 },
	{ .address = 0x18, .reg = 0x48 },
	{ .address = 0x1c, .reg = 0x49 },
	{ .address = 0x20, .reg = 0x4a },
	{ .address = 0x24, .reg = 0x4b },
	{ .address = 0x28, .reg = 0x4c },
	{ .address = 0x2c, .reg = 0x4d },
	{ .address = 0x30, .reg = 0x4e },
};

static struct pmic_table dc_ti_thermal_table[] = {
	{
		.address = 0x00,
		.reg = DC_TI_GPADC
	},
	{
		.address = 0x0c,
		.reg = DC_TI_GPADC
	},
	/* TMP2 -> SYSTEMP */
	{
		.address = 0x18,
		.reg = DC_TI_GPADC
	},
	/* TMP3 -> BPTHERM */
	{
		.address = 0x24,
		.reg = DC_TI_BPTHERM
	},
	{
		.address = 0x30,
		.reg = DC_TI_GPADC
	},
	/* TMP5 -> DIETEMP */
	{
		.address = 0x3c,
		.reg = DC_TI_DIETEMP
	},
};

static int dc_ti_pmic_get_power(struct regmap *regmap, int reg, int bit,
				u64 *value)
{
	int data;

	if (regmap_read(regmap, reg, &data))
		return -EIO;

	*value = data & 1;
	return 0;
}

static int dc_ti_pmic_update_power(struct regmap *regmap, int reg, int bit,
				   bool on)
{
	return regmap_update_bits(regmap, reg, 1, on);
}

static int dc_ti_pmic_get_raw_temp(struct regmap *regmap, int reg)
{
	u8 buf[2];
	unsigned int val;

	if (regmap_bulk_read(regmap, reg, buf, 2))
		return -EIO;

	/* stored in big-endian */
	val = buf[0] & 0x03;
	return (val << 8) | buf[1];
}

static struct intel_pmic_opregion_data dc_ti_pmic_opregion_data = {
	.get_power = dc_ti_pmic_get_power,
	.update_power = dc_ti_pmic_update_power,
	.get_raw_temp = dc_ti_pmic_get_raw_temp,
	.power_table = dc_ti_power_table,
	.power_table_count = ARRAY_SIZE(dc_ti_power_table),
	.thermal_table = dc_ti_thermal_table,
	.thermal_table_count = ARRAY_SIZE(dc_ti_thermal_table),
};

static int dc_ti_pmic_opregion_probe(struct platform_device *pdev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(pdev->dev.parent);
	int err;

	err = intel_pmic_install_opregion_handler(&pdev->dev,
			ACPI_HANDLE(pdev->dev.parent), pmic->regmap,
			&dc_ti_pmic_opregion_data);
	if (err < 0)
		return err;

	/* Re-enumerate devices depending on PMIC */
	acpi_walk_dep_device_list(ACPI_HANDLE(pdev->dev.parent));
	return 0;
}

static struct platform_device_id dc_ti_pmic_opregion_id_table[] = {
	{ .name = "dc_ti_region" },
	{},
};

static struct platform_driver dc_ti_pmic_opregion_driver = {
	.probe = dc_ti_pmic_opregion_probe,
	.driver = {
		.name = "dollar_cove_ti_pmic",
	},
	.id_table = dc_ti_pmic_opregion_id_table,
};
module_platform_driver(dc_ti_pmic_opregion_driver);

MODULE_DESCRIPTION("Dollar Cove TI PMIC opregion driver");
MODULE_LICENSE("GPL v2");
