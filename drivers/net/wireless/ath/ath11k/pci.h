/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
 */
#ifndef _ATH11K_PCI_H
#define _ATH11K_PCI_H

#include <linux/mhi.h>

#define QCA6290_VENDOR_ID		0x17CB
#define QCA6290_DEVICE_ID		0x1100
#define QCA6390_VENDOR_ID		0x17CB
#define QCA6390_DEVICE_ID		0x1101
#define PCI_BAR_NUM			0
#define PCI_DMA_MASK_64_BIT		64
#define PCI_DMA_MASK_32_BIT		32

#define MAX_UNWINDOWED_ADDRESS 0x80000
#define WINDOW_ENABLE_BIT 0x40000000
#define WINDOW_REG_ADDRESS 0x310C
#define WINDOW_SHIFT 19
#define WINDOW_VALUE_MASK 0x3F
#define WINDOW_START MAX_UNWINDOWED_ADDRESS
#define WINDOW_RANGE_MASK 0x7FFFF

#define ATH11K_IRQ_CE0_OFFSET 3

struct ath11k_msi_user {
	char *name;
	int num_vectors;
	u32 base_vector;
};

struct ath11k_msi_config {
	int total_vectors;
	int total_users;
	struct ath11k_msi_user *users;
};

struct ath11k_pci {
	struct pci_dev *pdev;
	struct device *dev;
	struct ath11k_base *ab;
	void __iomem *mem;
	size_t mem_len;
	u16 dev_id;
	u32 chip_id;
	struct ath11k_msi_config *msi_config;
	u32 msi_ep_base_data;
	struct mhi_controller *mhi_ctrl;
	unsigned long mhi_state;
	u32 register_window;
	spinlock_t window_lock;
};

int ath11k_pci_get_user_msi_assignment(struct ath11k_pci *ar_pci, char *user_name,
				       int *num_vectors, u32 *user_base_data,
				       u32 *base_vector);

int ath11k_pci_get_msi_irq(struct device *dev, unsigned int vector);
#endif
