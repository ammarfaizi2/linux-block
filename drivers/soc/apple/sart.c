// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple SART device driver
 * Copyright (C) The Asahi Linux Contributors
 *
 * Apple SART is a simple address filter for some DMA transactions.
 * Regions of physical memory must be added to the SART's allow
 * list before before any DMA can target these. Unlike a proper
 * IOMMU no remapping can be done and special support in the
 * consumer driver is required since not all DMA transactions of
 * a single device are subject to SART filtering.
 */

#include <linux/soc/apple/sart.h>
#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/types.h>

#define APPLE_SART_MAX_ENTRIES 16

/* This is probably a bitfield but the exact meaning of each bit is unknown. */
#define APPLE_SART_FLAGS_ALLOW 0xff

/* SARTv2 registers */
#define APPLE_SART2_CONFIG(idx)	      (0x00 + 4 * (idx))
#define APPLE_SART2_CONFIG_FLAGS      GENMASK(31, 24)
#define APPLE_SART2_CONFIG_SIZE	      GENMASK(23, 0)
#define APPLE_SART2_CONFIG_SIZE_SHIFT 12
#define APPLE_SART2_CONFIG_SIZE_MAX   GENMASK(23, 0)

#define APPLE_SART2_PADDR(idx)	(0x40 + 4 * (idx))
#define APPLE_SART2_PADDR_SHIFT 12

/* SARTv3 registers */
#define APPLE_SART3_CONFIG(idx) (0x00 + 4 * (idx))

#define APPLE_SART3_PADDR(idx)	(0x40 + 4 * (idx))
#define APPLE_SART3_PADDR_SHIFT 12

#define APPLE_SART3_SIZE(idx)  (0x80 + 4 * (idx))
#define APPLE_SART3_SIZE_SHIFT 12
#define APPLE_SART3_SIZE_MAX   GENMASK(29, 0)

struct apple_sart_ops {
	void (*get_entry)(struct apple_sart *sart, int index, u8 *flags,
			  phys_addr_t *paddr, size_t *size);
	int (*set_entry)(struct apple_sart *sart, int index, u8 flags,
			 phys_addr_t paddr, size_t size);
};

struct apple_sart {
	struct device *dev;
	void __iomem *regs;

	const struct apple_sart_ops *ops;

	unsigned long protected_entries;
	unsigned long used_entries;
};

static void sart2_get_entry(struct apple_sart *sart, int index, u8 *flags,
			    phys_addr_t *paddr, size_t *size)
{
	u32 cfg = readl_relaxed(sart->regs + APPLE_SART2_CONFIG(index));
	*flags = FIELD_GET(APPLE_SART2_CONFIG_FLAGS, cfg);
	*size = (size_t)FIELD_GET(APPLE_SART2_CONFIG_SIZE, cfg)
		<< APPLE_SART2_CONFIG_SIZE_SHIFT;
	*paddr = (phys_addr_t)readl_relaxed(sart->regs +
					    APPLE_SART2_PADDR(index))
		 << APPLE_SART2_PADDR_SHIFT;
}

static int sart2_set_entry(struct apple_sart *sart, int index, u8 flags,
			   phys_addr_t paddr, size_t size)
{
	u32 cfg;

	if (size & ((1 << APPLE_SART2_CONFIG_SIZE_SHIFT) - 1))
		return -EINVAL;
	if (paddr & ((1 << APPLE_SART2_PADDR_SHIFT) - 1))
		return -EINVAL;

	size >>= APPLE_SART2_CONFIG_SIZE_SHIFT;
	paddr >>= APPLE_SART2_PADDR_SHIFT;

	if (size > APPLE_SART2_CONFIG_SIZE_MAX)
		return -EINVAL;

	cfg = FIELD_PREP(APPLE_SART2_CONFIG_FLAGS, flags);
	cfg |= FIELD_PREP(APPLE_SART2_CONFIG_SIZE, size);

	writel_relaxed(paddr, sart->regs + APPLE_SART2_PADDR(index));
	writel_relaxed(cfg, sart->regs + APPLE_SART2_CONFIG(index));

	return 0;
}

static struct apple_sart_ops sart_ops_v2 = {
	.get_entry = sart2_get_entry,
	.set_entry = sart2_set_entry,
};

static void sart3_get_entry(struct apple_sart *sart, int index, u8 *flags,
			    phys_addr_t *paddr, size_t *size)
{
	*flags = readl_relaxed(sart->regs + APPLE_SART3_CONFIG(index));
	*size = (size_t)readl_relaxed(sart->regs + APPLE_SART3_SIZE(index))
		<< APPLE_SART3_SIZE_SHIFT;
	*paddr = (phys_addr_t)readl_relaxed(sart->regs +
					    APPLE_SART3_PADDR(index))
		 << APPLE_SART3_PADDR_SHIFT;
}

static int sart3_set_entry(struct apple_sart *sart, int index, u8 flags,
			   phys_addr_t paddr, size_t size)
{
	if (size & ((1 << APPLE_SART3_SIZE_SHIFT) - 1))
		return -EINVAL;
	if (paddr & ((1 << APPLE_SART3_PADDR_SHIFT) - 1))
		return -EINVAL;

	paddr >>= APPLE_SART3_PADDR_SHIFT;
	size >>= APPLE_SART3_SIZE_SHIFT;

	if (size > APPLE_SART3_SIZE_MAX)
		return -EINVAL;

	writel_relaxed(paddr, sart->regs + APPLE_SART3_PADDR(index));
	writel_relaxed(size, sart->regs + APPLE_SART3_SIZE(index));
	writel_relaxed(flags, sart->regs + APPLE_SART3_CONFIG(index));

	return 0;
}

static struct apple_sart_ops sart_ops_v3 = {
	.get_entry = sart3_get_entry,
	.set_entry = sart3_set_entry,
};

static int apple_sart_probe(struct platform_device *pdev)
{
	int i;
	struct apple_sart *sart;
	struct device *dev = &pdev->dev;

	sart = devm_kzalloc(dev, sizeof(*sart), GFP_KERNEL);
	if (!sart)
		return -ENOMEM;

	sart->dev = dev;
	sart->ops = of_device_get_match_data(dev);

	sart->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(sart->regs))
		return PTR_ERR(sart->regs);

	for (i = 0; i < APPLE_SART_MAX_ENTRIES; ++i) {
		u8 flags;
		size_t size;
		phys_addr_t paddr;

		sart->ops->get_entry(sart, i, &flags, &paddr, &size);

		if (!flags)
			continue;

		dev_dbg(sart->dev,
			"SART bootloader entry: index %02d; flags: 0x%02x; paddr: 0x%llx; size: 0x%zx\n",
			i, flags, paddr, size);
		set_bit(i, &sart->protected_entries);
	}

	platform_set_drvdata(pdev, sart);
	return 0;
}

struct apple_sart *apple_sart_get(struct device *dev)
{
	struct device_node *sart_node;
	struct platform_device *sart_pdev;
	struct apple_sart *sart;

	sart_node = of_parse_phandle(dev->of_node, "apple,sart", 0);
	if (!sart_node)
		return ERR_PTR(ENODEV);

	sart_pdev = of_find_device_by_node(sart_node);
	of_node_put(sart_node);

	if (!sart_pdev)
		return ERR_PTR(ENODEV);

	sart = dev_get_drvdata(&sart_pdev->dev);
	if (!sart)
		return ERR_PTR(EPROBE_DEFER);

	device_link_add(dev, &sart_pdev->dev,
			DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_SUPPLIER);

	return sart;
}
EXPORT_SYMBOL(apple_sart_get);

int apple_sart_add_allowed_region(struct apple_sart *sart, phys_addr_t paddr,
				  size_t size)
{
	int i, ret;

	for (i = 0; i < APPLE_SART_MAX_ENTRIES; ++i) {
		if (test_bit(i, &sart->protected_entries))
			continue;
		if (test_and_set_bit(i, &sart->used_entries))
			continue;

		ret = sart->ops->set_entry(sart, i, APPLE_SART_FLAGS_ALLOW,
					   paddr, size);
		if (ret) {
			dev_dbg(sart->dev,
				"unable to set entry %d to [0x%llx, 0x%zx]\n",
				i, paddr, size);
			clear_bit(i, &sart->used_entries);
			return ret;
		}

		dev_dbg(sart->dev, "wrote [0x%llx, 0x%zx] to %d\n", paddr, size,
			i);
		return 0;
	}

	dev_warn(sart->dev,
		 "no free entries left to add [paddr: 0x%llx, size: 0x%zx]\n",
		 paddr, size);

	return -EBUSY;
}
EXPORT_SYMBOL(apple_sart_add_allowed_region);

int apple_sart_remove_allowed_region(struct apple_sart *sart, phys_addr_t paddr,
				     size_t size)
{
	int i;

	dev_dbg(sart->dev,
		"will remove [paddr: 0x%llx, size: 0x%zx] from allowed regions\n",
		paddr, size);

	for (i = 0; i < APPLE_SART_MAX_ENTRIES; ++i) {
		u8 eflags;
		size_t esize;
		phys_addr_t epaddr;

		if (test_bit(i, &sart->protected_entries))
			continue;

		sart->ops->get_entry(sart, i, &eflags, &epaddr, &esize);

		if (epaddr != paddr || esize != size)
			continue;

		sart->ops->set_entry(sart, i, 0, 0, 0);

		clear_bit(i, &sart->used_entries);
		dev_dbg(sart->dev, "cleared entry %d\n", i);
		return 0;
	}

	dev_warn(sart->dev, "entry [paddr: 0x%llx, size: 0x%zx] not found\n",
		 paddr, size);

	return -EINVAL;
}
EXPORT_SYMBOL(apple_sart_remove_allowed_region);

static void apple_sart_shutdown(struct platform_device *pdev)
{
	struct apple_sart *sart = dev_get_drvdata(&pdev->dev);
	int i;

	for (i = 0; i < APPLE_SART_MAX_ENTRIES; ++i) {
		if (test_bit(i, &sart->protected_entries))
			continue;

		sart->ops->set_entry(sart, i, 0, 0, 0);
	}
}

static const struct of_device_id apple_sart_of_match[] = {
	{
		.compatible = "apple,sart3",
		.data = &sart_ops_v3,
	},
	{
		.compatible = "apple,sart2",
		.data = &sart_ops_v2,
	},
	{}
};
MODULE_DEVICE_TABLE(of, apple_sart_of_match);

static struct platform_driver apple_sart_driver = {
	.driver = {
		.name = "apple-sart",
		.of_match_table = apple_sart_of_match,
	},
	.probe = apple_sart_probe,
	.shutdown = apple_sart_shutdown,
};
module_platform_driver(apple_sart_driver);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Sven Peter <sven@svenpeter.dev>");
MODULE_DESCRIPTION("Apple SART driver");
