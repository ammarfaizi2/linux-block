// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/msi.h>
#include <linux/pci.h>

#include "ahb.h"
#include "core.h"
#include "hif.h"
#include "mhi.h"
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

/* Target firmware's Copy Engine configuration. */
static const struct ce_pipe_config target_ce_config_wlan[] = {
	/* CE0: host->target HTC control and raw streams */
	{
		.pipenum = __cpu_to_le32(0),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE1: target->host HTT + HTC control */
	{
		.pipenum = __cpu_to_le32(1),
		.pipedir = __cpu_to_le32(PIPEDIR_IN),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE2: target->host WMI */
	{
		.pipenum = __cpu_to_le32(2),
		.pipedir = __cpu_to_le32(PIPEDIR_IN),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE3: host->target WMI */
	{
		.pipenum = __cpu_to_le32(3),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE4: host->target HTT */
	{
		.pipenum = __cpu_to_le32(4),
		.pipedir = __cpu_to_le32(PIPEDIR_OUT),
		.nentries = __cpu_to_le32(256),
		.nbytes_max = __cpu_to_le32(256),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR),
		.reserved = __cpu_to_le32(0),
	},

	/* CE5: target->host Pktlog */
	{
		.pipenum = __cpu_to_le32(5),
		.pipedir = __cpu_to_le32(PIPEDIR_IN),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(2048),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE6: Reserved for target autonomous hif_memcpy */
	{
		.pipenum = __cpu_to_le32(6),
		.pipedir = __cpu_to_le32(PIPEDIR_INOUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(16384),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},

	/* CE7 used only by Host */
	{
		.pipenum = __cpu_to_le32(7),
		.pipedir = __cpu_to_le32(PIPEDIR_INOUT_H2H),
		.nentries = __cpu_to_le32(0),
		.nbytes_max = __cpu_to_le32(0),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR),
		.reserved = __cpu_to_le32(0),
	},

	/* CE8 target->host used only by IPA */
	{
		.pipenum = __cpu_to_le32(8),
		.pipedir = __cpu_to_le32(PIPEDIR_INOUT),
		.nentries = __cpu_to_le32(32),
		.nbytes_max = __cpu_to_le32(16384),
		.flags = __cpu_to_le32(CE_ATTR_FLAGS),
		.reserved = __cpu_to_le32(0),
	},
	/* CE 9, 10, 11 are used by MHI driver */
};

/* Map from service/endpoint to Copy Engine.
 * This table is derived from the CE_PCI TABLE, above.
 * It is passed to the Target at startup for use by firmware.
 */
static const struct service_to_pipe target_service_to_ce_map_wlan[] = {
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_DATA_VO),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_DATA_VO),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_DATA_BK),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_DATA_BK),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_DATA_BE),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_DATA_BE),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_DATA_VI),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_DATA_VI),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_CONTROL),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(3),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_WMI_CONTROL),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},

	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_RSVD_CTRL),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(0),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_RSVD_CTRL),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(2),
	},

	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_HTT_DATA_MSG),
		__cpu_to_le32(PIPEDIR_OUT),	/* out = UL = host -> target */
		__cpu_to_le32(4),
	},
	{
		__cpu_to_le32(ATH11K_HTC_SVC_ID_HTT_DATA_MSG),
		__cpu_to_le32(PIPEDIR_IN),	/* in = DL = target -> host */
		__cpu_to_le32(1),
	},

	/* (Additions here) */

	{ /* must be last */
		__cpu_to_le32(0),
		__cpu_to_le32(0),
		__cpu_to_le32(0),
	},
};

static inline struct ath11k_pci *ath11k_pci_priv(struct ath11k_base *ab)
{
	return (struct ath11k_pci *)ab->drv_priv;
}

int ath11k_pci_get_msi_irq(struct device *dev, unsigned int vector)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);

	int irq_num;

	irq_num = pci_irq_vector(pci_dev, vector);

	return irq_num;
}

int ath11k_pci_get_user_msi_assignment(struct ath11k_pci *ar_pci, char *user_name,
				       int *num_vectors, u32 *user_base_data,
				       u32 *base_vector)
{
	struct ath11k_base *ab = ar_pci->ab;
	struct ath11k_msi_config *msi_config;
	int idx;

	msi_config = ar_pci->msi_config;
	if (!msi_config) {
		ath11k_err(ab, "MSI is not supported.\n");
		return -EINVAL;
	}

	for (idx = 0; idx < msi_config->total_users; idx++) {
		if (strcmp(user_name, msi_config->users[idx].name) == 0) {
			*num_vectors = msi_config->users[idx].num_vectors;
			*user_base_data = msi_config->users[idx].base_vector
				+ ar_pci->msi_ep_base_data;
			*base_vector = msi_config->users[idx].base_vector;

			ath11k_dbg(ab, ATH11K_DBG_PCI, "Assign MSI to user: %s, num_vectors: %d, user_base_data: %u, base_vector: %u\n",
				   user_name, *num_vectors, *user_base_data,
				   *base_vector);

			return 0;
		}
	}

	ath11k_err(ab, "Failed to find MSI assignment for %s!\n", user_name);

	return -EINVAL;
}

static void ath11k_pci_free_irq(struct ath11k_base *ab)
{
	int irq_idx;
	int i;

	for (i = 0; i < CE_COUNT; i++) {
		if (ath11k_ce_get_attr_flags(i) & CE_ATTR_DIS_INTR)
			continue;
		irq_idx = ATH11K_IRQ_CE0_OFFSET + i;
		free_irq(ab->irq_num[irq_idx], &ab->ce.ce_pipe[i]);
	}
}

static void ath11k_pci_ce_irq_disable(struct ath11k_base *ab, u16 ce_id)
{
	u32 irq_idx;

	irq_idx = ATH11K_IRQ_CE0_OFFSET + ce_id;
	disable_irq_nosync(ab->irq_num[irq_idx]);
}

static irqreturn_t ath11k_pci_ce_interrupt_handler(int irq, void *arg)
{
	struct ath11k_ce_pipe *ce_pipe = arg;

	ath11k_pci_ce_irq_disable(ce_pipe->ab, ce_pipe->pipe_num);

	return IRQ_HANDLED;
}

static int ath11k_pci_config_irq(struct ath11k_base *ab)
{
	struct ath11k_ce_pipe *ce_pipe;
	u32 msi_data_start;
	u32 msi_data_count;
	u32 msi_irq_start;
	unsigned int msi_data;
	int irq, i, ret, irq_idx;

	ret = ath11k_pci_get_user_msi_assignment(ath11k_pci_priv(ab),
						 "CE", &msi_data_count,
						 &msi_data_start, &msi_irq_start);

	/* Configure CE irqs */
	for (i = 0; i < CE_COUNT; i++) {
		msi_data = (i % msi_data_count) +
				msi_irq_start;
		irq = ath11k_pci_get_msi_irq(ab->dev, msi_data);
		ce_pipe = &ab->ce.ce_pipe[i];

		if (ath11k_ce_get_attr_flags(i) & CE_ATTR_DIS_INTR)
			continue;

		irq_idx = ATH11K_IRQ_CE0_OFFSET + i;

		ret = request_irq(irq, ath11k_pci_ce_interrupt_handler,
				  IRQF_SHARED, irq_name[irq_idx],
				  ce_pipe);
		if (ret)
			return ret;

		ab->irq_num[irq_idx] = irq;
	}

	/* To Do Configure external interrupts */

	return ret;
}

static void ath11k_pci_init_qmi_ce_config(struct ath11k_base *ab)
{
	struct ath11k_qmi_ce_cfg *cfg = &ab->qmi.ce_cfg;

	cfg->tgt_ce = target_ce_config_wlan;
	cfg->tgt_ce_len = sizeof(target_ce_config_wlan);

	cfg->svc_to_ce_map = target_service_to_ce_map_wlan;
	cfg->svc_to_ce_map_len = sizeof(target_service_to_ce_map_wlan);
}

static void ath11k_pci_ce_irq_enable(struct ath11k_base *ab, u16 ce_id)
{
	u32 irq_idx;

	irq_idx = ATH11K_IRQ_CE0_OFFSET + ce_id;
	enable_irq(ab->irq_num[irq_idx]);
}

static void ath11k_pci_ce_irqs_enable(struct ath11k_base *ab)
{
	int i;

	for (i = 0; i < CE_COUNT; i++) {
		if (ath11k_ce_get_attr_flags(i) & CE_ATTR_DIS_INTR)
			continue;
		ath11k_pci_ce_irq_enable(ab, i);
	}
}

int ath11k_pci_qca6x90_powerup(struct ath11k_pci *ar_pci)
{
	return ath11k_pci_start_mhi(ar_pci);
}

void ath11k_pci_qca6x90_powerdown(struct ath11k_pci *ar_pci)
{
	ath11k_pci_stop_mhi(ar_pci);
}

static int ath11k_pci_get_msi_assignment(struct ath11k_pci *ar_pci)
{
	ar_pci->msi_config = &msi_config;

	return 0;
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

static int ath11k_pci_power_up(struct ath11k_base *ab)
{
	struct ath11k_pci *ar_pci;
	int ret;

	ar_pci = ath11k_pci_priv(ab);
	ret = ath11k_pci_qca6x90_powerup(ar_pci);
	if (ret)
		ath11k_err(ab, "failed to power on  mhi: %d\n", ret);

	return ret;
}

static void ath11k_pci_power_down(struct ath11k_base *ab)
{
	struct ath11k_pci *ar_pci;

	ar_pci = ath11k_pci_priv(ab);
	ath11k_pci_qca6x90_powerdown(ar_pci);
}

static void ath11k_pci_stop(struct ath11k_base *ab)
{
	ath11k_ce_cleanup_pipes(ab);
	/* Shutdown other components as appropriate */
}

static int ath11k_pci_start(struct ath11k_base *ab)
{
	ath11k_pci_ce_irqs_enable(ab);
	/* Bring up other components as appropriate */

	return 0;
}

static const struct ath11k_hif_ops ath11k_pci_hif_ops = {
	.start = ath11k_pci_start,
	.stop = ath11k_pci_stop,
	.power_down = ath11k_pci_power_down,
	.power_up = ath11k_pci_power_up,
};

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
	ab->hif.ops = &ath11k_pci_hif_ops;
	pci_set_drvdata(pdev, ab);
	ab->fixed_bdf_addr= false;
	ab->m3_fw_support = true;
	ab->mhi_support = true;
	ab->fixed_mem_region = false;

	ret = ath11k_pci_claim(ar_pci, pdev);
	if (ret) {
		ath11k_err(ab, "failed to claim device: %d\n", ret);
		goto err_free_core;
	}

	ab->mem = ar_pci->mem;
	ab->mem_len = ar_pci->mem_len;
	ret = ath11k_pci_enable_msi(ar_pci);
	if (ret) {
		ath11k_err(ab, "failed to enable  msi: %d\n", ret);
		goto err_pci_free_region;
	}
	ret = ath11k_pci_register_mhi(ar_pci);
	if (ret) {
		ath11k_err(ab, "failed to register  mhi: %d\n", ret);
		goto err_pci_disable_msi;
	}

	ret = ath11k_hal_srng_init(ab);
	if (ret)
		goto err_pci_unregister_mhi;

	ret = ath11k_ce_alloc_pipes(ab);
	if (ret) {
		ath11k_err(ab, "failed to allocate ce pipes: %d\n", ret);
		goto err_hal_srng_deinit;
	}

	ath11k_pci_init_qmi_ce_config(ab);
	ath11k_pci_config_irq(ab);
	if (ret) {
		ath11k_err(ab, "failed to config irq: %d\n", ret);
		goto err_ce_free;
	}
	ret = ath11k_core_init(ab);
	if (ret) {
		ath11k_err(ab, "failed to init core: %d\n", ret);
		goto err_free_irq;
	}
	return 0;

err_free_irq:
	ath11k_pci_free_irq(ab);

err_ce_free:
	ath11k_ce_free_pipes(ab);

err_hal_srng_deinit:
	ath11k_hal_srng_deinit(ab);

err_pci_unregister_mhi:
	ath11k_pci_unregister_mhi(ar_pci);

err_pci_disable_msi:
	ath11k_pci_disable_msi(ar_pci);

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
	ath11k_pci_unregister_mhi(ar_pci);
	ath11k_pci_disable_msi(ar_pci);
	ath11k_pci_free_region(ar_pci);
	ath11k_pci_free_irq(ab);
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
