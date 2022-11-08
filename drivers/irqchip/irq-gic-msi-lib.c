// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Linutronix GmbH
// Copyright (C) 2022 Intel

#include <linux/export.h>

#include "irq-gic-msi-lib.h"

/**
 * gic_msi_lib_init_dev_msi_info - Domain info setup for MSI domains
 * @dev:		The device for which the domain is created for
 * @domain:		The domain providing this callback
 * @real_parent:	The real parent domain of the to initialize domain
 *			which might be a domain built on top of @domain
 *			or @domain itself
 * @info:		The domain info for the to initialize domain
 *
 * This function is to be used for all types of MSI domains above the root
 * parent domain and any intermediates. The topmost parent domain specific
 * functionality is determined via @real_parent.
 *
 * All intermediate domains between the root and the device domain must
 * have either msi_parent_ops.init_dev_msi_info = msi_parent_init_dev_msi_info
 * or invoke it down the line.
 */
bool gic_msi_lib_init_dev_msi_info(struct device *dev, struct irq_domain *domain,
				   struct irq_domain *real_parent,
				   struct msi_domain_info *info)
{
	const struct msi_parent_ops *pops = real_parent->msi_parent_ops;

	/*
	 * MSI parent domain specific settings. For now there is only the
	 * root parent domain, e.g. NEXUS, acting as a MSI parent, but it is
	 * possible to stack MSI parents. See x86 vector -> irq remapping
	 */
	if (domain->bus_token == pops->bus_select_token) {
		if (WARN_ON_ONCE(domain != real_parent))
			return false;
	} else {
		WARN_ON_ONCE(1);
		return false;
	}

	/* Parent ops available? */
	if (WARN_ON_ONCE(!pops))
		return false;

	/* Is the target domain bus token supported ? */
	switch(info->bus_token) {
	case DOMAIN_BUS_PCI_DEVICE_MSI:
	case DOMAIN_BUS_PCI_DEVICE_MSIX:
		if (WARN_ON_ONCE(!IS_ENABLED(CONFIG_PCI_MSI)))
			return false;

		pci_device_msi_mask_unmask_parent_enable();
		break;
	case DOMAIN_BUS_DEVICE_IMS:
		/*
		 * Per device IMS should never have any MSI feature bits
		 * set. It's sole purpose is to create a dumb interrupt
		 * chip which has a device specific irq_write_msi_msg()
		 * callback.
		 */
		if (WARN_ON_ONCE(info->flags))
			return false;

		/* Core managed MSI descriptors */
		info->flags = MSI_FLAG_ALLOC_SIMPLE_MSI_DESCS | MSI_FLAG_FREE_MSI_DESCS;

		/*
		 * Per device platform IMS domain creation stores the
		 * irq_write_msi_msg() callback in @info->data.
		 */
		info->chip->irq_write_msi_msg = info->data;
		break;
	case DOMAIN_BUS_WIRED_TO_MSI:
		break;
	default:
		/*
		 * This should never be reached. See
		 * gic_msi_lib_irq_domain_select()
		 */
		WARN_ON_ONCE(1);
		return false;
	}

	/*
	 * Mask out the domain specific MSI feature flags which are not
	 * supported by the real parent.
	 */
	info->flags			&= pops->supported_flags;
	/* Enforce the required flags */
	info->flags			|= pops->required_flags;

	/* Chip updates for all child bus types */
	if (!info->chip->irq_eoi)
		info->chip->irq_eoi	= irq_chip_eoi_parent;
	if (!info->chip->irq_ack)
		info->chip->irq_ack	= irq_chip_ack_parent;

	/*
	 * The device MSI domain can never have a set affinity callback it
	 * always has to rely on the parent domain to handle affinity
	 * settings. The device MSI domain just has to write the resulting
	 * MSI message into the hardware which is the whole purpose of the
	 * device MSI domain aside of mask/unmask which is provided e.g. by
	 * PCI/MSI device domains.
	 */
	info->chip->irq_set_affinity	= msi_domain_set_affinity;
	return true;
}
EXPORT_SYMBOL_GPL(gic_msi_lib_init_dev_msi_info);

/**
 * gic_msi_lib_irq_domain_select - Shared select function for NEXUS domains
 * FIXME: @....
 */
int gic_msi_lib_irq_domain_select(struct irq_domain *d, struct irq_fwspec *fwspec,
				  enum irq_domain_bus_token bus_token)
{
	const struct msi_parent_ops *ops = d->msi_parent_ops;
	u32 busmask = BIT(bus_token);

	if (fwspec->fwnode != d->fwnode || fwspec->param_count != 0)
		return 0;

	/* Handle pure domain searches */
	if (bus_token == ops->bus_select_token)
		return 1;

	return ops && !!(ops->bus_select_mask & busmask);
}
EXPORT_SYMBOL_GPL(gic_msi_lib_irq_domain_select);
