/*
 * Copyright (c) 2013-2016 Andrew Lutomirski <luto@amacapital.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _I2C_DIMM_BUS
#define _I2C_DIMM_BUS

struct i2c_adapter;
void i2c_scan_dimm_bus(struct i2c_adapter *adapter);

#endif /* _I2C_DIMM_BUS */
