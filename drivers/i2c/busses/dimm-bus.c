/*
 * Copyright (c) 2013 Andrew Lutomirski <luto@amacapital.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/i2c.h>
#include <linux/bug.h>
#include <linux/module.h>
#include <linux/i2c/dimm-bus.h>

static bool probe_addr(struct i2c_adapter *adapter, int addr)
{
	/*
	 * So far, all known devices that live on DIMMs can be safely
	 * and reliably detected by trying to read a byte at address
	 * zero.  (The exception is the SPD write protection control,
	 * which can't be probed and requires special hardware and/or
	 * quick writes to access, and has no driver.)
	 */
	union i2c_smbus_data dummy;
	return i2c_smbus_xfer(adapter, addr, 0, I2C_SMBUS_READ, 0,
			      I2C_SMBUS_BYTE_DATA, &dummy) >= 0;
}

/**
 * i2c_scan_dimm_bus() - Scans an SMBUS segment known to contain DIMMs
 * @adapter: The SMBUS adapter to scan
 *
 * This function tells the DIMM-bus code that the adapter is known to
 * contain DIMMs.  i2c_scan_dimm_bus will probe for devices known to
 * live on DIMMs.
 *
 * Do NOT call this function on general-purpose system SMBUS segments
 * unless you know that the only things on the bus are DIMMs.
 * Otherwise is it very likely to mis-identify other things on the
 * bus.
 *
 * Callers are advised not to set adapter->class = I2C_CLASS_SPD.
 */
void i2c_scan_dimm_bus(struct i2c_adapter *adapter)
{
	struct i2c_board_info info = {};
	int slot;

	/*
	 * We probe with "read byte data".  If any DIMM SMBUS driver can't
	 * support that access type, this function should be updated.
	 */
	if (WARN_ON(!i2c_check_functionality(adapter,
					  I2C_FUNC_SMBUS_READ_BYTE_DATA)))
		return;

	/*
	 * Addresses on DIMMs use the three low bits to identify the slot
	 * and the four high bits to identify the device type.  Known
	 * devices are:
	 *
	 *  - 0x50 - 0x57: SPD (Serial Presence Detect) EEPROM
	 *  - 0x30 - 0x37: SPD WP control -- not worth trying to probe
	 *  - 0x18 - 0x1f: TSOD (Temperature Sensor on DIMM)
	 *
	 * There may be more some day.
	 */
	for (slot = 0; slot < 8; slot++) {
		/* If there's no SPD, then assume there's no DIMM here. */
		if (!probe_addr(adapter, 0x50 | slot))
			continue;

		strcpy(info.type, "spd");
		info.addr = 0x50 | slot;
		i2c_new_device(adapter, &info);

		if (probe_addr(adapter, 0x18 | slot)) {
			/* This is a temperature sensor. */
			strcpy(info.type, "jc42");
			info.addr = 0x18 | slot;
			i2c_new_device(adapter, &info);
		}
	}
}
EXPORT_SYMBOL(i2c_scan_dimm_bus);

MODULE_AUTHOR("Andrew Lutomirski <luto@amacapital.net>");
MODULE_DESCRIPTION("i2c DIMM bus support");
MODULE_LICENSE("GPL");
