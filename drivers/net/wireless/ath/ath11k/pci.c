// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/msi.h>
#include <linux/pci.h>

#include "ahb.h"
#include "core.h"
#include "pci.h"
#include "debug.h"

static const struct pci_device_id ath11k_pci_id_table[] = {
	{ QCA6290_VENDOR_ID, QCA6290_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ QCA6390_VENDOR_ID, QCA6390_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ 0 }
};

MODULE_DEVICE_TABLE(pci, ath11k_pci_id_table);

static struct ath11k_msi_config msi_config = {
	.total_vectors = 32,
	.total_users = 4,
	.users = (struct ath11k_msi_user[]) {
		{ .name = "MHI", .num_vectors = 3, .base_vector = 0 },
		{ .name = "CE", .num_vectors = 10, .base_vector = 3 },
		{ .name = "WAKE", .num_vectors = 1, .base_vector = 13 },
		{ .name = "DP", .num_vectors = 18, .base_vector = 14 },
	},
};

static int ath11k_pci_get_msi_assignment(struct ath11k_pci *ar_pci)
{
	ar_pci->msi_config = &msi_config;

	return 0;
}

static inline struct ath11k_pci *ath11k_pci_priv(struct ath11k_base *ab)
{
	return (struct ath11k_pci *)ab->drv_priv;
}

static int ath11k_pci_enable_msi(struct ath11k_pci *ar_pci)
{
	struct ath11k_base *ab = ar_pci->ab;
	struct ath11k_msi_config *msi_config;
	struct msi_desc *msi_desc;
	int num_vectors;
	int ret;

	ret = ath11k_pci_get_msi_assignment(ar_pci);
	if (ret) {
		ath11k_err(ab, "failed to get MSI assignment, err = %d\n", ret);
		goto out;
	}

	msi_config = ar_pci->msi_config;
	if (!msi_config) {
		ath11k_err(ab, "msi_config is NULL!\n");
		ret = -EINVAL;
		goto out;
	}

	num_vectors = pci_alloc_irq_vectors(ar_pci->pdev,
					    msi_config->total_vectors,
					    msi_config->total_vectors,
					    PCI_IRQ_MSI);
	if (num_vectors != msi_config->total_vectors) {
		ath11k_err(ab, "failed to get enough MSI vectors (%d), available vectors = %d",
			   msi_config->total_vectors, num_vectors);
		if (num_vectors >= 0)
			ret = -EINVAL;
		goto reset_msi_config;
	}

	msi_desc = irq_get_msi_desc(ar_pci->pdev->irq);
	if (!msi_desc) {
		ath11k_err(ab, "msi_desc is NULL!\n");
		ret = -EINVAL;
		goto free_msi_vector;
	}

	ar_pci->msi_ep_base_data = msi_desc->msg.data;

	ath11k_dbg(ab, ATH11K_DBG_PCI, "msi base data is %d\n", ar_pci->msi_ep_base_data);

	return 0;

free_msi_vector:
	pci_free_irq_vectors(ar_pci->pdev);
reset_msi_config:
	ar_pci->msi_config = NULL;
out:
	return ret;
}

static void ath11k_pci_disable_msi(struct ath11k_pci *ar_pci)
{
	pci_free_irq_vectors(ar_pci->pdev);
}

static int ath11k_pci_claim(struct ath11k_pci *ar_pci, struct pci_dev *pdev)
{
	u32 pci_dma_mask = PCI_DMA_MASK_32_BIT;
	struct ath11k_base *ab = ar_pci->ab;
	u16 device_id;
	int ret = 0;

	pci_read_config_word(pdev, PCI_DEVICE_ID, &device_id);
	if (device_id != ar_pci->dev_id)  {
		ath11k_err(ab, "pci device id mismatch, config ID: 0x%x, probe ID: 0x%x\n",
			   device_id, ar_pci->dev_id);
		ret = -EIO;
		goto out;
	}

	ret = pci_assign_resource(pdev, PCI_BAR_NUM);
	if (ret) {
		ath11k_err(ab, "failed to assign pci resource, err = %d\n", ret);
		goto out;
	}

	ret = pci_enable_device(pdev);
	if (ret) {
		ath11k_err(ab, "failed to enable pci device, err = %d\n", ret);
		goto out;
	}

	ret = pci_request_region(pdev, PCI_BAR_NUM, "ath11k_pci");
	if (ret) {
		ath11k_err(ab, "failed to request pci region, err = %d\n", ret);
		goto disable_device;
	}

	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(pci_dma_mask));
	if (ret) {
		ath11k_err(ab, "failed to set pci dma mask (%d), err = %d\n",
			   ret, pci_dma_mask);
		goto release_region;
	}

	ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(pci_dma_mask));
	if (ret) {
		ath11k_err(ab, "failed to set pci consistent dma mask (%d), err = %d\n",
			   ret, pci_dma_mask);
		goto release_region;
	}

	pci_set_master(pdev);

	ar_pci->mem_len = pci_resource_len(pdev, PCI_BAR_NUM);
	ar_pci->mem = pci_iomap(pdev, PCI_BAR_NUM, 0);
	if (!ar_pci->mem) {
		ath11k_err(ab, "failed to map pci bar, bar = %d\n", PCI_BAR_NUM);
		ret = -EIO;
		goto clear_master;
	}

	ath11k_dbg(ab, ATH11K_DBG_BOOT, "boot pci_mem 0x%pK\n", ar_pci->mem);
	return 0;

clear_master:
	pci_clear_master(pdev);
release_region:
	pci_release_region(pdev, PCI_BAR_NUM);
disable_device:
	pci_disable_device(pdev);
out:
	return ret;
}

static void ath11k_pci_free_region(struct ath11k_pci *ar_pci)
{
	struct pci_dev *pci_dev = ar_pci->pdev;

	pci_iounmap(pci_dev, ar_pci->mem);
	ar_pci->mem = NULL;
	pci_clear_master(pci_dev);
	pci_release_region(pci_dev, PCI_BAR_NUM);
	if (pci_is_enabled(pci_dev))
		pci_disable_device(pci_dev);
}
static int ath11k_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *pci_dev)
{
	struct ath11k_base *ab;
	struct ath11k_pci *ar_pci;
	enum ath11k_hw_rev hw_rev;
	int ret;

	switch (pci_dev->device) {
	case QCA6290_DEVICE_ID:
		hw_rev = ATH10K_HW_QCA6290;
	case QCA6390_DEVICE_ID:
		hw_rev = ATH10K_HW_QCA6390;
		break;
	default:
		dev_err(&pdev->dev, "Unknown PCI device found: 0x%x\n",
			pci_dev->device);
		WARN_ON(1);
		return -ENOTSUPP;
	}

	ab = ath11k_core_alloc(&pdev->dev, sizeof(*ar_pci), ATH11K_BUS_PCI);
	if (!ab) {
		dev_err(&pdev->dev, "failed to allocate ath11k base\n");
		return -ENOMEM;
	}

	ab->dev = &pdev->dev;
	ab->hw_rev = hw_rev;
	pci_set_drvdata(pdev, ab);
	ar_pci = ath11k_pci_priv(ab);
	ar_pci->dev_id = pci_dev->device;
	ar_pci->ab = ab;
	ar_pci->dev = &pdev->dev;
	ar_pci->pdev = pdev;
	ab->dev = &pdev->dev;
	ab->hw_rev = hw_rev;
	pci_set_drvdata(pdev, ab);

	ret = ath11k_pci_claim(ar_pci, pdev);
	if (ret) {
		ath11k_err(ab, "failed to claim device: %d\n", ret);
		goto err_free_core;
	}

	ret = ath11k_pci_enable_msi(ar_pci);
	if (ret) {
		ath11k_err(ab, "failed to enable  msi: %d\n", ret);
		goto err_pci_free_region;
	}

	return 0;

err_pci_free_region:
	ath11k_pci_free_region(ar_pci);

err_free_core:
	ath11k_core_free(ab);

	return ret;
}

static void ath11k_pci_remove(struct pci_dev *pdev)
{
	struct ath11k_base *ab = pci_get_drvdata(pdev);
	struct ath11k_pci *ar_pci = ath11k_pci_priv(ab);

	set_bit(ATH11K_FLAG_UNREGISTERING, &ab->dev_flags);
	ath11k_pci_disable_msi(ar_pci);
	ath11k_pci_free_region(ar_pci);
	ath11k_core_free(ab);
}

static struct pci_driver ath11k_pci_driver = {
	.name = "ath11k_pci",
	.id_table = ath11k_pci_id_table,
	.probe = ath11k_pci_probe,
	.remove = ath11k_pci_remove,
};

int ath11k_pci_init(void)
{
	int ret;

	ret = pci_register_driver(&ath11k_pci_driver);
	if (ret)
		pr_err("failed to register ath11k pci driver: %d\n",
		       ret);

	return ret;
}
module_init(ath11k_pci_init);

void ath11k_pci_exit(void)
{
	pci_unregister_driver(&ath11k_pci_driver);
}

module_exit(ath11k_pci_exit);

MODULE_DESCRIPTION("Driver support for Qualcomm Atheros 802.11ax WLAN PCIe devices");
MODULE_LICENSE("Dual BSD/GPL");
