/*
 * Copyright 2010-2011 Calxeda, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/amba/bus.h>
#include <linux/platform_device.h>

#include <asm/hardware/cache-l2x0.h>

#include "core.h"

void __iomem *sregs_base;

static void highbank_l2x0_disable(void)
{
	/* Disable PL310 L2 Cache controller */
	highbank_smc1(0x102, 0x0);
}

static int __init highbank_init_cache(void)
{
	/* Enable PL310 L2 Cache controller */
	if (!IS_ENABLED(CONFIG_CACHE_L2X0))
		return -ENODEV;

	highbank_smc1(0x102, 0x1);
	l2x0_of_init(0, ~0UL);	outer_cache.disable = highbank_l2x0_disable;
	return 0;
}

static const struct of_device_id pl310_match[] __initconst = {
	{ .compatible = "arm,pl310-cache" },
	{},
};
of_initcall_match(highbank_init_cache, arch_initcall, pl310_match);

static int highbank_platform_notifier(struct notifier_block *nb,
				  unsigned long event, void *__dev)
{
	struct resource *res;
	int reg = -1;
	u32 val;
	struct device *dev = __dev;

	if (event != BUS_NOTIFY_ADD_DEVICE)
		return NOTIFY_DONE;

	if (of_device_is_compatible(dev->of_node, "calxeda,hb-ahci"))
		reg = 0xc;
	else if (of_device_is_compatible(dev->of_node, "calxeda,hb-sdhci"))
		reg = 0x18;
	else if (of_device_is_compatible(dev->of_node, "arm,pl330"))
		reg = 0x20;
	else if (of_device_is_compatible(dev->of_node, "calxeda,hb-xgmac")) {
		res = platform_get_resource(to_platform_device(dev),
					    IORESOURCE_MEM, 0);
		if (res) {
			if (res->start == 0xfff50000)
				reg = 0;
			else if (res->start == 0xfff51000)
				reg = 4;
		}
	}

	if (reg < 0)
		return NOTIFY_DONE;

	if (of_property_read_bool(dev->of_node, "dma-coherent")) {
		val = readl(sregs_base + reg);
		writel(val | 0xff01, sregs_base + reg);
		set_dma_ops(dev, &arm_coherent_dma_ops);
	}

	return NOTIFY_OK;
}

static struct notifier_block highbank_amba_nb = {
	.notifier_call = highbank_platform_notifier,
};

static struct notifier_block highbank_platform_nb = {
	.notifier_call = highbank_platform_notifier,
};

static int __init highbank_init(void)
{
	struct device_node *np;

	/* Map system registers */
	np = of_find_compatible_node(NULL, NULL, "calxeda,hb-sregs");
	sregs_base = of_iomap(np, 0);
	WARN_ON(!sregs_base);

	bus_register_notifier(&platform_bus_type, &highbank_platform_nb);
	bus_register_notifier(&amba_bustype, &highbank_amba_nb);

	return 0;
}

static const struct of_device_id highbank_match[] __initconst = {
	{ .compatible = "calxeda,highbank" },
	{ .compatible = "calxeda,ecx-2000" },
	{},
};
of_initcall_match(highbank_init, subsys_initcall, highbank_match);
