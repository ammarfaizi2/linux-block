// SPDX-License-Identifier: BSD-3-Clause-Clear
/* Copyright (c) 2019 The Linux Foundation. All rights reserved. */

#include <linux/memblock.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/pci.h>

#include "debug.h"
#include "mhi.h"

#define MHI_TIMEOUT_DEFAULT_MS	90000

#ifdef MHI_COMPILE_TEST
int mhi_prepare_for_power_up(struct mhi_controller *mhi_cntrl)
{
	return 0;
}

void mhi_unprepare_after_power_down(struct mhi_controller *mhi_cntrl)
{
}

int mhi_force_rddm_mode(struct mhi_controller *mhi_cntrl)
{
	return 0;
}

void mhi_unregister_mhi_controller(struct mhi_controller *mhi_cntrl)
{
}

void mhi_power_down(struct mhi_controller *mhi_cntrl, bool graceful)
{
}

int mhi_sync_power_up(struct mhi_controller *mhi_cntrl)
{
	return 0;
}
#endif

static int ath11k_pci_get_mhi_msi(struct ath11k_pci *ar_pci)
{
	struct ath11k_base *ab = ar_pci->ab;
	u32 user_base_data, base_vector;
	int ret, num_vectors, i;
	int *irq;

	ret = ath11k_pci_get_user_msi_assignment(ar_pci,
						 "MHI", &num_vectors,
						 &user_base_data, &base_vector);
	if (ret)
		return ret;

	ath11k_dbg(ab, ATH11K_DBG_PCI, "Number of assigned MSI for MHI is %d, base vector is %d\n",
		   num_vectors, base_vector);

	irq = kcalloc(num_vectors, sizeof(int), GFP_KERNEL);
	if (!irq)
		return -ENOMEM;

	for (i = 0; i < num_vectors; i++)
		irq[i] = ath11k_pci_get_msi_irq(ar_pci->dev,
						base_vector + i);

	ar_pci->mhi_ctrl->irq = irq;
	ar_pci->mhi_ctrl->msi_allocated = num_vectors;

	return 0;
}

static int ath11k_mhi_link_status(struct mhi_controller *mhi_ctrl, void *priv)
{
	return 0;
}

static void ath11k_mhi_notify_status(struct mhi_controller *mhi_ctrl, void *priv,
				     enum MHI_CB reason)
{
}

static int ath11k_mhi_pm_runtime_get(struct mhi_controller *mhi_ctrl, void *priv)
{
	return 0;
}

static void ath11k_mhi_pm_runtime_put_noidle(struct mhi_controller *mhi_ctrl,
					     void *priv)
{
}

int ath11k_pci_register_mhi(struct ath11k_pci *ar_pci)
{
	struct pci_dev *pci_dev = ar_pci->pdev;
	struct ath11k_base *ab = ar_pci->ab;
	struct mhi_controller *mhi_ctrl;
	int ret;

	mhi_ctrl = mhi_alloc_controller(0);
	if (!mhi_ctrl) {
		ath11k_err(ab, "invalid mhi controller context\n");
		return -EINVAL;
	}

	ar_pci->mhi_ctrl = mhi_ctrl;

	mhi_ctrl->priv_data = ar_pci;
	mhi_ctrl->dev = &pci_dev->dev;
	mhi_ctrl->of_node = (ar_pci->dev)->of_node;
	mhi_ctrl->dev_id = ar_pci->dev_id;
	mhi_ctrl->domain = pci_domain_nr(pci_dev->bus);
	mhi_ctrl->bus = pci_dev->bus->number;
	mhi_ctrl->slot = PCI_SLOT(pci_dev->devfn);

	mhi_ctrl->fw_image = ATH11K_PCI_FW_FILE_NAME;

	mhi_ctrl->regs = ar_pci->mem;

	ret = ath11k_pci_get_mhi_msi(ar_pci);
	if (ret) {
		ath11k_err(ab, "failed to get msi for mhi\n");
		return ret;
	}

	mhi_ctrl->iova_start = memblock_start_of_DRAM();
	mhi_ctrl->iova_stop = memblock_end_of_DRAM();

	mhi_ctrl->link_status = ath11k_mhi_link_status;
	mhi_ctrl->status_cb = ath11k_mhi_notify_status;
	mhi_ctrl->runtime_get = ath11k_mhi_pm_runtime_get;
	mhi_ctrl->runtime_put = ath11k_mhi_pm_runtime_put_noidle;

	mhi_ctrl->sbl_size = SZ_512K;
	mhi_ctrl->seg_len = SZ_512K;
	mhi_ctrl->fbc_download = true;

	ret = of_register_mhi_controller(mhi_ctrl);
	if (ret) {
		ath11k_err(ab, "failed to register to mhi bus, err = %d\n", ret);
		return ret;
	}

	return 0;
}

void ath11k_pci_unregister_mhi(struct ath11k_pci *ar_pci)
{
	struct mhi_controller *mhi_ctrl = ar_pci->mhi_ctrl;

	mhi_unregister_mhi_controller(mhi_ctrl);
	kfree(mhi_ctrl->irq);
}

static char *ath11k_mhi_state_to_str(enum ath11k_mhi_state mhi_state)
{
	switch (mhi_state) {
	case ATH11K_MHI_INIT:
		return "INIT";
	case ATH11K_MHI_DEINIT:
		return "DEINIT";
	case ATH11K_MHI_POWER_ON:
		return "POWER_ON";
	case ATH11K_MHI_POWER_OFF:
		return "POWER_OFF";
	case ATH11K_MHI_FORCE_POWER_OFF:
		return "FORCE_POWER_OFF";
	case ATH11K_MHI_SUSPEND:
		return "SUSPEND";
	case ATH11K_MHI_RESUME:
		return "RESUME";
	case ATH11K_MHI_TRIGGER_RDDM:
		return "TRIGGER_RDDM";
	case ATH11K_MHI_RDDM_DONE:
		return "RDDM_DONE";
	default:
		return "UNKNOWN";
	}
};

static void ath11k_pci_set_mhi_state_bit(struct ath11k_pci *ar_pci,
					 enum ath11k_mhi_state mhi_state)
{
	struct ath11k_base *ab = ar_pci->ab;

	switch (mhi_state) {
	case ATH11K_MHI_INIT:
		set_bit(ATH11K_MHI_INIT, &ar_pci->mhi_state);
		break;
	case ATH11K_MHI_DEINIT:
		clear_bit(ATH11K_MHI_INIT, &ar_pci->mhi_state);
		break;
	case ATH11K_MHI_POWER_ON:
		set_bit(ATH11K_MHI_POWER_ON, &ar_pci->mhi_state);
		break;
	case ATH11K_MHI_POWER_OFF:
	case ATH11K_MHI_FORCE_POWER_OFF:
		clear_bit(ATH11K_MHI_POWER_ON, &ar_pci->mhi_state);
		clear_bit(ATH11K_MHI_TRIGGER_RDDM, &ar_pci->mhi_state);
		clear_bit(ATH11K_MHI_RDDM_DONE, &ar_pci->mhi_state);
		break;
	case ATH11K_MHI_SUSPEND:
		set_bit(ATH11K_MHI_SUSPEND, &ar_pci->mhi_state);
		break;
	case ATH11K_MHI_RESUME:
		clear_bit(ATH11K_MHI_SUSPEND, &ar_pci->mhi_state);
		break;
	case ATH11K_MHI_TRIGGER_RDDM:
		set_bit(ATH11K_MHI_TRIGGER_RDDM, &ar_pci->mhi_state);
		break;
	case ATH11K_MHI_RDDM_DONE:
		set_bit(ATH11K_MHI_RDDM_DONE, &ar_pci->mhi_state);
		break;
	default:
		ath11k_err(ab, "unhandled mhi state (%d)\n", mhi_state);
	}
}

static int ath11k_pci_check_mhi_state_bit(struct ath11k_pci *ar_pci,
					  enum ath11k_mhi_state mhi_state)
{
	struct ath11k_base *ab = ar_pci->ab;

	switch (mhi_state) {
	case ATH11K_MHI_INIT:
		if (!test_bit(ATH11K_MHI_INIT, &ar_pci->mhi_state))
			return 0;
		break;
	case ATH11K_MHI_DEINIT:
	case ATH11K_MHI_POWER_ON:
		if (test_bit(ATH11K_MHI_INIT, &ar_pci->mhi_state) &&
		    !test_bit(ATH11K_MHI_POWER_ON, &ar_pci->mhi_state))
			return 0;
		break;
	case ATH11K_MHI_FORCE_POWER_OFF:
		if (test_bit(ATH11K_MHI_POWER_ON, &ar_pci->mhi_state))
			return 0;
		break;
	case ATH11K_MHI_POWER_OFF:
	case ATH11K_MHI_SUSPEND:
		if (test_bit(ATH11K_MHI_POWER_ON, &ar_pci->mhi_state) &&
		    !test_bit(ATH11K_MHI_SUSPEND, &ar_pci->mhi_state))
			return 0;
		break;
	case ATH11K_MHI_RESUME:
		if (test_bit(ATH11K_MHI_SUSPEND, &ar_pci->mhi_state))
			return 0;
		break;
	case ATH11K_MHI_TRIGGER_RDDM:
		if (test_bit(ATH11K_MHI_POWER_ON, &ar_pci->mhi_state) &&
		    !test_bit(ATH11K_MHI_TRIGGER_RDDM, &ar_pci->mhi_state))
			return 0;
		break;
	case ATH11K_MHI_RDDM_DONE:
		return 0;
	default:
		ath11k_err(ab, "unhandled mhi state: %s(%d)\n",
			   ath11k_mhi_state_to_str(mhi_state), mhi_state);
	}

	ath11k_err(ab, "failed to set mhi state %s(%d) in current mhi state (0x%lx)\n",
		   ath11k_mhi_state_to_str(mhi_state), mhi_state,
		   ar_pci->mhi_state);

	return -EINVAL;
}

int ath11k_pci_set_mhi_state(struct ath11k_pci *ar_pci,
			     enum ath11k_mhi_state mhi_state)
{
	struct ath11k_base *ab = ar_pci->ab;
	int ret;

	ret = ath11k_pci_check_mhi_state_bit(ar_pci, mhi_state);
	if (ret)
		goto out;

	ath11k_dbg(ab, ATH11K_DBG_PCI, "setting mhi state: %s(%d)\n",
		   ath11k_mhi_state_to_str(mhi_state), mhi_state);

	switch (mhi_state) {
	case ATH11K_MHI_INIT:
		ret = mhi_prepare_for_power_up(ar_pci->mhi_ctrl);
		break;
	case ATH11K_MHI_DEINIT:
		mhi_unprepare_after_power_down(ar_pci->mhi_ctrl);
		ret = 0;
		break;
	case ATH11K_MHI_POWER_ON:
		ret = mhi_sync_power_up(ar_pci->mhi_ctrl);
		break;
	case ATH11K_MHI_POWER_OFF:
		mhi_power_down(ar_pci->mhi_ctrl, true);
		ret = 0;
		break;
	case ATH11K_MHI_FORCE_POWER_OFF:
		mhi_power_down(ar_pci->mhi_ctrl, false);
		ret = 0;
		break;
	case ATH11K_MHI_SUSPEND:
		break;
	case ATH11K_MHI_RESUME:
		break;
	case ATH11K_MHI_TRIGGER_RDDM:
		ret = mhi_force_rddm_mode(ar_pci->mhi_ctrl);
		break;
	case ATH11K_MHI_RDDM_DONE:
		break;
	default:
		ath11k_err(ab, "unhandled MHI state (%d)\n", mhi_state);
		ret = -EINVAL;
	}

	if (ret)
		goto out;

	ath11k_pci_set_mhi_state_bit(ar_pci, mhi_state);

	return 0;

out:
	ath11k_err(ab, "failed to set mhi state: %s(%d)\n",
		   ath11k_mhi_state_to_str(mhi_state), mhi_state);
	return ret;
}

int ath11k_pci_start_mhi(struct ath11k_pci *ar_pci)
{
	int ret;

	ar_pci->mhi_ctrl->timeout_ms = MHI_TIMEOUT_DEFAULT_MS;

	ret = ath11k_pci_set_mhi_state(ar_pci, ATH11K_MHI_INIT);
	if (ret)
		goto out;

	ret = ath11k_pci_set_mhi_state(ar_pci, ATH11K_MHI_POWER_ON);
	if (ret)
		goto out;

	return 0;

out:
	return ret;
}

void ath11k_pci_stop_mhi(struct ath11k_pci *ar_pci)
{
	ath11k_pci_set_mhi_state(ar_pci, ATH11K_MHI_RESUME);
	ath11k_pci_set_mhi_state(ar_pci, ATH11K_MHI_POWER_OFF);
	ath11k_pci_set_mhi_state(ar_pci, ATH11K_MHI_DEINIT);
}

