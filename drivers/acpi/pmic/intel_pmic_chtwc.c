/*
 * intel_pmic_chtwc.c - Intel CHT Whiskey Cove PMIC operation region driver
 * Copyright (C) 2017 Hans de Goede <hdegoede@redhat.com>
 *
 * Based on various non upstream patches to support the CHT Whiskey Cove PMIC:
 * Copyright (C) 2013-2015 Intel Corporation. All rights reserved.
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

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/mfd/intel_chtwc.h>
#include <linux/mfd/intel_soc_pmic.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include "intel_pmic.h"

/*
 * Regulator support is based on the non upstream patch:
 * "regulator: whiskey_cove: implements Whiskey Cove pmic VRF support"
 * https://github.com/intel-aero/meta-intel-aero/blob/master/recipes-kernel/linux/linux-yocto/0019-regulator-whiskey_cove-implements-WhiskeyCove-pmic-V.patch
 */
static struct pmic_table power_table[] = {
	{
		.address = 0x0,
		.reg = CHT_WC_V1P8A_CTRL,
		.bit = 0x01,
	}, /* V18A */
	{
		.address = 0x04,
		.reg = CHT_WC_V1P8SX_CTRL,
		.bit = 0x07,
	}, /* V18X */
	{
		.address = 0x08,
		.reg = CHT_WC_VDDQ_CTRL,
		.bit = 0x01,
	}, /* VDDQ */
	{
		.address = 0x0c,
		.reg = CHT_WC_V1P2A_CTRL,
		.bit = 0x07,
	}, /* V12A */
	{
		.address = 0x10,
		.reg = CHT_WC_V1P2SX_CTRL,
		.bit = 0x07,
	}, /* V12X */
	{
		.address = 0x14,
		.reg = CHT_WC_V2P8SX_CTRL,
		.bit = 0x07,
	}, /* V28X */
	{
		.address = 0x18,
		.reg = CHT_WC_V3P3A_CTRL,
		.bit = 0x01,
	}, /* V33A */
	{
		.address = 0x1c,
		.reg = CHT_WC_V3P3SD_CTRL,
		.bit = 0x07,
	}, /* V3SD */
	{
		.address = 0x20,
		.reg = CHT_WC_VSDIO_CTRL,
		.bit = 0x07,
	}, /* VSD */
/*	{
		.address = 0x24,
		.reg = ??,
		.bit = ??,
	}, ** VSW2 */
/*	{
		.address = 0x28,
		.reg = ??,
		.bit = ??,
	}, ** VSW1 */
/*	{
		.address = 0x2c,
		.reg = ??,
		.bit = ??,
	}, ** VUPY */
/*	{
		.address = 0x30,
		.reg = ??,
		.bit = ??,
	}, ** VRSO */
	{
		.address = 0x34,
		.reg = CHT_WC_VPROG1A_CTRL,
		.bit = 0x07,
	}, /* VP1A */
	{
		.address = 0x38,
		.reg = CHT_WC_VPROG1B_CTRL,
		.bit = 0x07,
	}, /* VP1B */
	{
		.address = 0x3c,
		.reg = CHT_WC_VPROG1F_CTRL,
		.bit = 0x07,
	}, /* VP1F */
	{
		.address = 0x40,
		.reg = CHT_WC_VPROG2D_CTRL,
		.bit = 0x07,
	}, /* VP2D */
	{
		.address = 0x44,
		.reg = CHT_WC_VPROG3A_CTRL,
		.bit = 0x07,
	}, /* VP3A */
	{
		.address = 0x48,
		.reg = CHT_WC_VPROG3B_CTRL,
		.bit = 0x07,
	}, /* VP3B */
	{
		.address = 0x4c,
		.reg = CHT_WC_VPROG4A_CTRL,
		.bit = 0x07,
	}, /* VP4A */
	{
		.address = 0x50,
		.reg = CHT_WC_VPROG4B_CTRL,
		.bit = 0x07,
	}, /* VP4B */
	{
		.address = 0x54,
		.reg = CHT_WC_VPROG4C_CTRL,
		.bit = 0x07,
	}, /* VP4C */
	{
		.address = 0x58,
		.reg = CHT_WC_VPROG4D_CTRL,
		.bit = 0x07,
	}, /* VP4D */
	{
		.address = 0x5c,
		.reg = CHT_WC_VPROG5A_CTRL,
		.bit = 0x07,
	}, /* VP5A */
	{
		.address = 0x60,
		.reg = CHT_WC_VPROG5B_CTRL,
		.bit = 0x07,
	}, /* VP5B */
	{
		.address = 0x64,
		.reg = CHT_WC_VPROG6A_CTRL,
		.bit = 0x07,
	}, /* VP6A */
	{
		.address = 0x68,
		.reg = CHT_WC_VPROG6B_CTRL,
		.bit = 0x07,
	}, /* VP6B */
/*	{
		.address = 0x6c,
		.reg = ??,
		.bit = ??,
	}  ** VP7A */
};

static int intel_cht_wc_pmic_get_power(struct regmap *regmap, int reg,
		int bit, u64 *value)
{
	int data;

	if (regmap_read(regmap, reg, &data))
		return -EIO;

	*value = (data & bit) ? 1 : 0;
	return 0;
}

static int intel_cht_wc_pmic_update_power(struct regmap *regmap, int reg,
		int bit, bool on)
{
	u8 mask = bit;

	return regmap_update_bits(regmap, reg, mask, on ? 1 : 0);
}

/*
 * The thermal table and ops are empty, we do not support the Thermal opregion
 * (DPTF) due to lacking documentation.
 */
static struct intel_pmic_opregion_data intel_cht_wc_pmic_opregion_data = {
	.get_power		= intel_cht_wc_pmic_get_power,
	.update_power		= intel_cht_wc_pmic_update_power,
	.power_table		= power_table,
	.power_table_count	= ARRAY_SIZE(power_table),
};

static int intel_cht_wc_pmic_opregion_probe(struct platform_device *pdev)
{
	struct intel_soc_pmic *pmic = dev_get_drvdata(pdev->dev.parent);

	return intel_pmic_install_opregion_handler(&pdev->dev,
			ACPI_HANDLE(pdev->dev.parent),
			pmic->regmap,
			&intel_cht_wc_pmic_opregion_data);
}

static struct platform_device_id cht_wc_opregion_id_table[] = {
	{ .name = "cht_wcove_region" },
	{},
};
MODULE_DEVICE_TABLE(platform, cht_wc_opregion_id_table);

static struct platform_driver intel_cht_wc_pmic_opregion_driver = {
	.probe = intel_cht_wc_pmic_opregion_probe,
	.driver = {
		.name = "cht_whiskey_cove_pmic",
	},
	.id_table = cht_wc_opregion_id_table,
};
module_platform_driver(intel_cht_wc_pmic_opregion_driver);

MODULE_DESCRIPTION("Intel CHT Whiskey Cove PMIC operation region driver");
MODULE_AUTHOR("Hans de Goede <hdegoede@redhat.com>");
MODULE_LICENSE("GPL");
