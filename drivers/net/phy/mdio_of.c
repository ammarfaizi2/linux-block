/*
 * OF helpers for the MDIO Bus API
 *
 * Copyright (c) 2009 Secret Lab Technologies, Ltd.
 *
 * This file is released under the GPLv2
 *
 * This file provides helper functions for extracting PHY device information
 * out of the OpenFirmware device tree and using it to populate an mii_bus.
 */

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/err.h>
#include <linux/phy.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/module.h>

#define DEFAULT_GPIO_RESET_DELAY	10	/* in microseconds */

MODULE_AUTHOR("Grant Likely <grant.likely@secretlab.ca>");
MODULE_LICENSE("GPL");

/* Extract the clause 22 phy ID from the compatible string of the form
 * ethernet-phy-idAAAA.BBBB */
static int of_get_phy_id(struct device_node *device, u32 *phy_id)
{
	struct property *prop;
	const char *cp;
	unsigned int upper, lower;

	of_property_for_each_string(device, "compatible", prop, cp) {
		if (sscanf(cp, "ethernet-phy-id%4x.%4x", &upper, &lower) == 2) {
			*phy_id = ((upper & 0xFFFF) << 16) | (lower & 0xFFFF);
			return 0;
		}
	}
	return -EINVAL;
}

static int of_mdiobus_register_phy(struct mii_bus *mdio,
				    struct device_node *child, u32 addr)
{
	struct phy_device *phy;
	bool is_c45;
	int rc;
	u32 phy_id;

	if (!IS_ENABLED(CONFIG_PHYLIB))
		return 0;

	is_c45 = of_device_is_compatible(child,
					 "ethernet-phy-ieee802.3-c45");

	if (!is_c45 && !of_get_phy_id(child, &phy_id))
		phy = phy_device_create(mdio, addr, phy_id, 0, NULL);
	else
		phy = get_phy_device(mdio, addr, is_c45);
	if (IS_ERR(phy))
		return PTR_ERR(phy);

	rc = of_irq_get(child, 0);
	if (rc == -EPROBE_DEFER) {
		phy_device_free(phy);
		return rc;
	}
	if (rc > 0) {
		phy->irq = rc;
		mdio->irq[addr] = rc;
	} else {
		phy->irq = mdio->irq[addr];
	}

	if (of_property_read_bool(child, "broken-turn-around"))
		mdio->phy_ignore_ta_mask |= 1 << addr;

	/* Associate the OF node with the device structure so it
	 * can be looked up later */
	of_node_get(child);
	phy->mdio.dev.of_node = child;

	/* All data is now stored in the phy struct;
	 * register it */
	rc = phy_device_register(phy);
	if (rc) {
		phy_device_free(phy);
		of_node_put(child);
		return rc;
	}

	dev_dbg(&mdio->dev, "registered phy %s at address %i\n",
		child->name, addr);
	return 0;
}

static int of_mdiobus_register_device(struct mii_bus *mdio,
				      struct device_node *child, u32 addr)
{
	struct mdio_device *mdiodev;
	int rc;

	mdiodev = mdio_device_create(mdio, addr);
	if (IS_ERR(mdiodev))
		return PTR_ERR(mdiodev);

	/* Associate the OF node with the device structure so it
	 * can be looked up later.
	 */
	of_node_get(child);
	mdiodev->dev.of_node = child;

	/* All data is now stored in the mdiodev struct; register it. */
	rc = mdio_device_register(mdiodev);
	if (rc) {
		mdio_device_free(mdiodev);
		of_node_put(child);
		return rc;
	}

	dev_dbg(&mdio->dev, "registered mdio device %s at address %i\n",
		child->name, addr);
	return 0;
}

/* The following is a list of PHY compatible strings which appear in
 * some DTBs. The compatible string is never matched against a PHY
 * driver, so is pointless. We only expect devices which are not PHYs
 * to have a compatible string, so they can be matched to an MDIO
 * driver.  Encourage users to upgrade their DT blobs to remove these.
 */
static const struct of_device_id whitelist_phys[] = {
	{ .compatible = "brcm,40nm-ephy" },
	{ .compatible = "broadcom,bcm5241" },
	{ .compatible = "marvell,88E1111", },
	{ .compatible = "marvell,88e1116", },
	{ .compatible = "marvell,88e1118", },
	{ .compatible = "marvell,88e1145", },
	{ .compatible = "marvell,88e1149r", },
	{ .compatible = "marvell,88e1310", },
	{ .compatible = "marvell,88E1510", },
	{ .compatible = "marvell,88E1514", },
	{ .compatible = "moxa,moxart-rtl8201cp", },
	{}
};

/*
 * Return true if the child node is for a phy. It must either:
 * o Compatible string of "ethernet-phy-idX.X"
 * o Compatible string of "ethernet-phy-ieee802.3-c45"
 * o Compatible string of "ethernet-phy-ieee802.3-c22"
 * o In the white list above (and issue a warning)
 * o No compatibility string
 *
 * A device which is not a phy is expected to have a compatible string
 * indicating what sort of device it is.
 */
static bool of_mdiobus_child_is_phy(struct device_node *child)
{
	u32 phy_id;

	if (of_get_phy_id(child, &phy_id) != -EINVAL)
		return true;

	if (of_device_is_compatible(child, "ethernet-phy-ieee802.3-c45"))
		return true;

	if (of_device_is_compatible(child, "ethernet-phy-ieee802.3-c22"))
		return true;

	if (of_match_node(whitelist_phys, child)) {
		pr_warn(FW_WARN
			"%pOF: Whitelisted compatible string. Please remove\n",
			child);
		return true;
	}

	if (!of_find_property(child, "compatible", NULL))
		return true;

	return false;
}

/**
 * of_mdiobus_register - Register mii_bus and create PHYs from the device tree
 * @mdio: pointer to mii_bus structure
 * @np: pointer to device_node of MDIO bus.
 *
 * This function registers the mii_bus structure and registers a phy_device
 * for each child node of @np.
 */
int of_mdiobus_register(struct mii_bus *mdio, struct device_node *np)
{
	struct device_node *child;
	bool scanphys = false;
	int addr, rc;

	/* Do not continue if the node is disabled */
	if (!of_device_is_available(np))
		return -ENODEV;

	/* Mask out all PHYs from auto probing.  Instead the PHYs listed in
	 * the device tree are populated after the bus has been registered */
	mdio->phy_mask = ~0;

	mdio->dev.of_node = np;

	/* Get bus level PHY reset GPIO details */
	mdio->reset_delay_us = DEFAULT_GPIO_RESET_DELAY;
	of_property_read_u32(np, "reset-delay-us", &mdio->reset_delay_us);

	/* Register the MDIO bus */
	rc = mdiobus_register(mdio);
	if (rc)
		return rc;

	/* Loop over the child nodes and register a phy_device for each phy */
	for_each_available_child_of_node(np, child) {
		addr = of_mdio_parse_addr(&mdio->dev, child);
		if (addr < 0) {
			scanphys = true;
			continue;
		}

		if (of_mdiobus_child_is_phy(child))
			rc = of_mdiobus_register_phy(mdio, child, addr);
		else
			rc = of_mdiobus_register_device(mdio, child, addr);
		if (rc)
			goto unregister;
	}

	if (!scanphys)
		return 0;

	/* auto scan for PHYs with empty reg property */
	for_each_available_child_of_node(np, child) {
		/* Skip PHYs with reg property set */
		if (of_find_property(child, "reg", NULL))
			continue;

		for (addr = 0; addr < PHY_MAX_ADDR; addr++) {
			/* skip already registered PHYs */
			if (mdiobus_is_registered_device(mdio, addr))
				continue;

			/* be noisy to encourage people to set reg property */
			dev_info(&mdio->dev, "scan phy %s at address %i\n",
				 child->name, addr);

			if (of_mdiobus_child_is_phy(child)) {
				rc = of_mdiobus_register_phy(mdio, child, addr);
				if (rc)
					goto unregister;
			}
		}
	}

	return 0;

unregister:
	mdiobus_unregister(mdio);
	return rc;
}
EXPORT_SYMBOL(of_mdiobus_register);
