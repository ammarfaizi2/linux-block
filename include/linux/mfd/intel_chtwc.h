/*
 * intel_chtwc.h - Header file for Intel Cherrytrail Whiskey Cove PMIC
 *
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

#ifndef __INTEL_CHTWC_H__
#define __INTEL_CHTWC_H__

#define CHT_WC_DEVICE1_ADDR		0x6e

#define CHT_WC_V1P05A_CTRL		0x6e3b
#define CHT_WC_V1P15_CTRL		0x6e3c
#define CHT_WC_V1P05A_VSEL		0x6e3d
#define CHT_WC_V1P15_VSEL		0x6e3e
#define CHT_WC_V1P8A_CTRL		0x6e56
#define CHT_WC_V1P8SX_CTRL		0x6e57
#define CHT_WC_VDDQ_CTRL		0x6e58
#define CHT_WC_V1P2A_CTRL		0x6e59
#define CHT_WC_V1P2SX_CTRL		0x6e5a
#define CHT_WC_V1P8A_VSEL		0x6e5b
#define CHT_WC_VDDQ_VSEL		0x6e5c
#define CHT_WC_V2P8SX_CTRL		0x6e5d
#define CHT_WC_V3P3A_CTRL		0x6e5e
#define CHT_WC_V3P3SD_CTRL		0x6e5f
#define CHT_WC_VSDIO_CTRL		0x6e67
#define CHT_WC_V3P3A_VSEL		0x6e68
#define CHT_WC_VPROG1A_CTRL		0x6e90
#define CHT_WC_VPROG1B_CTRL		0x6e91
#define CHT_WC_VPROG1F_CTRL		0x6e95
#define CHT_WC_VPROG2D_CTRL		0x6e99
#define CHT_WC_VPROG3A_CTRL		0x6e9a
#define CHT_WC_VPROG3B_CTRL		0x6e9b
#define CHT_WC_VPROG4A_CTRL		0x6e9c
#define CHT_WC_VPROG4B_CTRL		0x6e9d
#define CHT_WC_VPROG4C_CTRL		0x6e9e
#define CHT_WC_VPROG4D_CTRL		0x6e9f
#define CHT_WC_VPROG5A_CTRL		0x6ea0
#define CHT_WC_VPROG5B_CTRL		0x6ea1
#define CHT_WC_VPROG6A_CTRL		0x6ea2
#define CHT_WC_VPROG6B_CTRL		0x6ea3
#define CHT_WC_VPROG1A_VSEL		0x6ec0
#define CHT_WC_VPROG1B_VSEL		0x6ec1
#define CHT_WC_V1P8SX_VSEL		0x6ec2
#define CHT_WC_V1P2SX_VSEL		0x6ec3
#define CHT_WC_V1P2A_VSEL		0x6ec4
#define CHT_WC_VPROG1F_VSEL		0x6ec5
#define CHT_WC_VSDIO_VSEL		0x6ec6
#define CHT_WC_V2P8SX_VSEL		0x6ec7
#define CHT_WC_V3P3SD_VSEL		0x6ec8
#define CHT_WC_VPROG2D_VSEL		0x6ec9
#define CHT_WC_VPROG3A_VSEL		0x6eca
#define CHT_WC_VPROG3B_VSEL		0x6ecb
#define CHT_WC_VPROG4A_VSEL		0x6ecc
#define CHT_WC_VPROG4B_VSEL		0x6ecd
#define CHT_WC_VPROG4C_VSEL		0x6ece
#define CHT_WC_VPROG4D_VSEL		0x6ecf
#define CHT_WC_VPROG5A_VSEL		0x6ed0
#define CHT_WC_VPROG5B_VSEL		0x6ed1
#define CHT_WC_VPROG6A_VSEL		0x6ed2
#define CHT_WC_VPROG6B_VSEL		0x6ed3

#endif
