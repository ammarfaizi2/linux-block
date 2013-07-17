/*
 * drivers/hwmon/tsod.c - Temperaure Sensor On DIMM
 *
 * Copyright (C) 2013 Andrew Lutomirski <luto@amacapital.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 * The official reference for these devices is JEDEC Standard No. 21-C,
 * which is available for free from www.jedec.org.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/slab.h>

/* Registers */
#define TSOD_CURRENT_TEMP	5
#define TSOD_VENDOR		6
#define TSOD_DEVICE		7

/*
 * This driver does not program the trip points, etc. -- this is done by
 * firmware, and the memory controller probably wants the defaults preserved.
 */

struct tsod_priv {
	struct i2c_client *client;
	struct device *hwmondev;
};

static ssize_t show_name(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "TSOD\n");
}

static ssize_t show_label(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "DIMM Temperature\n");
}

static ssize_t show_temperature(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct tsod_priv *priv = dev_get_drvdata(dev->parent);
	int temp, raw;

	raw = i2c_smbus_read_word_swapped(priv->client, TSOD_CURRENT_TEMP);
	if (raw < 0)
		return raw;

	/*
	 * The three high bits are undefined and the rest is twos-complement.
	 * Use a sign-extending right shift to propagate the sign bit.
	 */
	temp = ((s16)((s16)raw << 3) >> 3);

	/*
	 * The value is in units of 0.0625 degrees, but we want it in
	 * units of 0.001 degrees.
	 */
	return sprintf(buf, "%d\n", DIV_ROUND_CLOSEST(temp * 625, 10));
}

static DEVICE_ATTR(name, S_IRUGO, show_name, NULL);
static SENSOR_DEVICE_ATTR(temp1_input, S_IRUGO, show_temperature, NULL, 0);
static SENSOR_DEVICE_ATTR(temp1_label, S_IRUGO, show_label, NULL, 0);

static struct attribute *tsod_hwmon_attributes[] = {
	&dev_attr_name.attr,
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp1_label.dev_attr.attr,

	NULL,
};

static const struct attribute_group tsod_hwmon_attr_group = {
	.attrs	= tsod_hwmon_attributes,
};

static int tsod_detect(struct i2c_client *client, struct i2c_board_info *info)
{
	struct i2c_adapter *adapter = client->adapter;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_READ_WORD_DATA))
		return -ENODEV;

	strlcpy(info->type, "tsod", I2C_NAME_SIZE);
	return 0;
}

static int tsod_probe(struct i2c_client *client,
		      const struct i2c_device_id *id)
{
	int ret;
	struct tsod_priv *priv;

	/* Sanity check the address */
	if ((client->addr & 0x78) != 0x18)
		return -ENODEV;

	/* Sanity check: make sure we can read the temperature. */
	ret = i2c_smbus_read_word_swapped(client, TSOD_CURRENT_TEMP);
	if (ret < 0)
		return -ENODEV;

	priv = kzalloc(sizeof(struct tsod_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->client = client;

	priv->hwmondev = hwmon_device_register(&client->dev);
	if (IS_ERR(priv->hwmondev)) {
		ret = PTR_ERR(priv->hwmondev);
		goto err_free;
	}

	i2c_set_clientdata(client, priv);

	ret = sysfs_create_group(&priv->hwmondev->kobj, &tsod_hwmon_attr_group);
	if (ret)
		goto err_unreg;

	return 0;

err_unreg:
	hwmon_device_unregister(&client->dev);

err_free:
	kfree(priv);
	i2c_set_clientdata(client, 0);
	return ret;
}

static int tsod_remove(struct i2c_client *client)
{
	struct tsod_priv *priv = i2c_get_clientdata(client);

	sysfs_remove_group(&priv->hwmondev->kobj, &tsod_hwmon_attr_group);
	hwmon_device_unregister(priv->hwmondev);
	kfree(priv);
	return 0;
}

static const unsigned short tsod_addresses[] = {
	0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, I2C_CLIENT_END
};

static const struct i2c_device_id tsod_id[] = {
	{ "tsod", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, tsod_id);

static struct i2c_driver tsod_driver = {
	.driver = {
		.name	= "tsod",
		.owner	= THIS_MODULE,
	},
	.probe		= tsod_probe,
	.remove		= tsod_remove,
	.id_table	= tsod_id,

	/*
	 * We do not claim I2C_CLASS_SPD -- there are other devices
	 * on, e.g., the i2c_i801 bus that have these addresses.
	 * Instead we let the dimm-bus code instantiate us.
	 */

	.detect		= tsod_detect,
	.address_list	= tsod_addresses,
};

module_i2c_driver(tsod_driver);

MODULE_AUTHOR("Andrew Lutomirski <luto@amacapital.net>");
MODULE_DESCRIPTION("Temperaure Sensor On DIMM");
MODULE_LICENSE("GPL");
