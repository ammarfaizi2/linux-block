// SPDX-License-Identifier: GPL-2.0
/*
 * Interrupt chip and domain for Intel IDXD with hardware array based
 * interrupt message store (IMS).
 */
#include <linux/device.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/pci.h>

#include <linux/irqchip/irq-pci-intel-idxd.h>

MODULE_LICENSE("GPL");

/**
 * struct ims_slot - The hardware layout of a slot in the memory table
 * @address_lo:	Lower 32bit address
 * @address_hi:	Upper 32bit address
 * @data:	Message data
 * @ctrl:	Control word
 */
struct ims_slot {
	u32	address_lo;
	u32	address_hi;
	u32	data;
	u32	ctrl;
} __packed;

/* Bit to mask the interrupt in the control word */
#define CTRL_VECTOR_MASKBIT	BIT(0)
/* Bit to enable PASID in the control word */
#define CTRL_PASID_ENABLE	BIT(3)
/* Position of PASID.LSB in the control word */
#define CTRL_PASID_SHIFT	12

static inline void iowrite32_and_flush(u32 value, void __iomem *addr)
{
	iowrite32(value, addr);
	ioread32(addr);
}

static void idxd_mask(struct irq_data *data)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct ims_slot __iomem *slot = desc->data.iobase;
	u32 cval = desc->data.cookie.value;

	iowrite32_and_flush(cval | CTRL_VECTOR_MASKBIT, &slot->ctrl);
}

static void idxd_unmask(struct irq_data *data)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct ims_slot __iomem *slot = desc->data.iobase;
	u32 cval = desc->data.cookie.value;

	iowrite32_and_flush(cval, &slot->ctrl);
}

static void idxd_write_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct ims_slot __iomem *slot = desc->data.iobase;

	iowrite32(msg->address_lo, &slot->address_lo);
	iowrite32(msg->address_hi, &slot->address_hi);
	iowrite32_and_flush(msg->data, &slot->data);
}

static void idxd_shutdown(struct irq_data *data)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct ims_slot __iomem *slot = desc->data.iobase;

	iowrite32(0, &slot->address_lo);
	iowrite32(0, &slot->address_hi);
	iowrite32(0, &slot->data);
	iowrite32_and_flush(CTRL_VECTOR_MASKBIT, &slot->ctrl);
}

static void idxd_prepare_desc(struct irq_domain *domain, msi_alloc_info_t *arg,
			      struct msi_desc *desc)
{
	struct msi_domain_info *info = domain->host_data;
	struct ims_slot __iomem *slot;

	/* Set up the slot address for the irq_chip callbacks */
	slot = (__force struct ims_slot __iomem *) info->data;
	slot += desc->msi_index;
	desc->data.iobase = slot;

	/* Mask the interrupt for paranoia sake */
	iowrite32_and_flush(CTRL_VECTOR_MASKBIT, &slot->ctrl);

	/*
	 * The caller provided PASID. Shift it to the proper position
	 * and set the PASID enable bit.
	 */
	desc->data.cookie.value <<= CTRL_PASID_SHIFT;
	desc->data.cookie.value |= CTRL_PASID_ENABLE;

	arg->hwirq = desc->msi_index;
}

static const struct msi_domain_template idxd_ims_template = {
	.chip = {
		.name			= "PCI-IDXD",
		.irq_mask		= idxd_mask,
		.irq_unmask		= idxd_unmask,
		.irq_write_msi_msg	= idxd_write_msi_msg,
		.irq_shutdown		= idxd_shutdown,
		.flags			= IRQCHIP_ONESHOT_SAFE,
	},

	.ops = {
		.prepare_desc		= idxd_prepare_desc,
	},

	.info = {
		.flags			= MSI_FLAG_ALLOC_SIMPLE_MSI_DESCS |
					  MSI_FLAG_FREE_MSI_DESCS |
					  MSI_FLAG_PCI_IMS,
		.bus_token		= DOMAIN_BUS_PCI_DEVICE_IMS,
	},
};

/**
 * pci_intel_idxd_create_ims_domain - Create a IDXD IMS domain
 * @pdev:	IDXD PCI device to operate on
 * @slots:	Pointer to the mapped slot memory arrray
 * @nr_slots:	The number of slots in the array
 *
 * Returns: True on success, false otherwise
 *
 * The domain is automatically destroyed when the @pdev is destroyed
 */
bool pci_intel_idxd_create_ims_domain(struct pci_dev *pdev, void __iomem *slots,
				      unsigned int nr_slots)
{
	return pci_create_ims_domain(pdev, &idxd_ims_template, nr_slots, (__force void *)slots);
}
EXPORT_SYMBOL_GPL(pci_intel_idxd_create_ims_domain);
