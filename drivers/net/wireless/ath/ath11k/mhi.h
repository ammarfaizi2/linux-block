/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2019 The Linux Foundation. All rights reserved.
 */
#ifndef _ATH11K_MHI_H
#define _ATH11K_MHI_H

#include "pci.h"
#define ATH11K_PCI_FW_FILE_NAME		"amss.bin"

enum ath11k_mhi_state {
	ATH11K_MHI_INIT,
	ATH11K_MHI_DEINIT,
	ATH11K_MHI_POWER_ON,
	ATH11K_MHI_POWER_OFF,
	ATH11K_MHI_FORCE_POWER_OFF,
	ATH11K_MHI_SUSPEND,
	ATH11K_MHI_RESUME,
	ATH11K_MHI_TRIGGER_RDDM,
	ATH11K_MHI_RDDM,
	ATH11K_MHI_RDDM_DONE,
};

int ath11k_pci_start_mhi(struct ath11k_pci *ar_pci);
void ath11k_pci_stop_mhi(struct ath11k_pci *ar_pci);
int ath11k_pci_register_mhi(struct ath11k_pci *ar_pci);
void ath11k_pci_unregister_mhi(struct ath11k_pci *ar_pci);
#endif
