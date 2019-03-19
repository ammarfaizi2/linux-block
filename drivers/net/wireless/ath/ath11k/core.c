// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2018-2019 The Linux Foundation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/remoteproc.h>
#include <linux/firmware.h>
#include "ahb.h"
#include "core.h"
#include "dp_tx.h"
#include "debug.h"

unsigned int ath11k_debug_mask;

module_param_named(debug_mask, ath11k_debug_mask, uint, 0644);

MODULE_PARM_DESC(debug_mask, "Debugging mask");

static const struct ath11k_hw_params ath11k_hw_params = {
			.name = "ipq8074",
			.fw = {
				.dir = IPQ8074_FW_DIR,
				.board_size = IPQ8074_MAX_BOARD_DATA_SZ,
				.cal_size =  IPQ8074_MAX_CAL_DATA_SZ,
			},
};

static int ath11k_core_create_board_name(struct ath11k_base *sc, char *name,
					 size_t name_len)
{
	/* Note: bus is fixed to ahb. When other bus type supported,
	 * make it to dynamic.
	 */
	scnprintf(name, name_len,
		  "bus=ahb,qmi-chip-id=%d,qmi-board-id=%d",
		  sc->qmi.target.chip_id,
		  sc->qmi.target.board_id);

	ath11k_dbg(sc, ATH11K_DBG_BOOT, "boot using board name '%s'\n", name);

	return 0;
}

static const struct firmware *ath11k_fetch_fw_file(struct ath11k_base *sc,
							const char *dir,
							const char *file)
{
	char filename[100];
	const struct firmware *fw;
	int ret;

	if (file == NULL)
		return ERR_PTR(-ENOENT);

	if (dir == NULL)
		dir = ".";

	snprintf(filename, sizeof(filename), "%s/%s", dir, file);
	ret = request_firmware_direct(&fw, filename, sc->dev);
	ath11k_dbg(sc, ATH11K_DBG_BOOT, "boot fw request '%s': %d\n",
		   filename, ret);

	if (ret)
		return ERR_PTR(ret);
	ath11k_warn(sc, "Downloading BDF: %s, size: %zu\n",
		    filename, fw->size);

	return fw;
}

void ath11k_core_free_bdf(struct ath11k_base *sc, struct ath11k_board_data *bd)
{
	if (!IS_ERR(bd->fw))
		release_firmware(bd->fw);

	memset(bd, 0, sizeof(*bd));
}

static int ath11k_core_parse_bd_ie_board(struct ath11k_base *sc,
					 struct ath11k_board_data *bd,
					 const void *buf, size_t buf_len,
					 const char *boardname,
					 int bd_ie_type)
{
	const struct ath11k_fw_ie *hdr;
	bool name_match_found;
	int ret, board_ie_id;
	size_t board_ie_len;
	const void *board_ie_data;

	name_match_found = false;

	/* go through ATH11K_BD_IE_BOARD_ elements */
	while (buf_len > sizeof(struct ath11k_fw_ie)) {
		hdr = buf;
		board_ie_id = le32_to_cpu(hdr->id);
		board_ie_len = le32_to_cpu(hdr->len);
		board_ie_data = hdr->data;

		buf_len -= sizeof(*hdr);
		buf += sizeof(*hdr);

		if (buf_len < ALIGN(board_ie_len, 4)) {
			ath11k_err(sc, "invalid ATH11K_BD_IE_BOARD length: %zu < %zu\n",
				   buf_len, ALIGN(board_ie_len, 4));
			ret = -EINVAL;
			goto out;
		}

		switch (board_ie_id) {
		case ATH11K_BD_IE_BOARD_NAME:
			ath11k_dbg_dump(sc, ATH11K_DBG_BOOT, "board name", "",
					board_ie_data, board_ie_len);

			if (board_ie_len != strlen(boardname))
				break;

			ret = memcmp(board_ie_data, boardname, strlen(boardname));
			if (ret)
				break;

			name_match_found = true;
			ath11k_dbg(sc, ATH11K_DBG_BOOT,
				   "boot found match for name '%s'",
				   boardname);
			break;
		case ATH11K_BD_IE_BOARD_DATA:
			if (!name_match_found)
				/* no match found */
				break;

			ath11k_dbg(sc, ATH11K_DBG_BOOT,
					"boot found board data for '%s'",
					boardname);

			bd->data = board_ie_data;
			bd->len = board_ie_len;

			ret = 0;
			goto out;
		default:
			ath11k_warn(sc, "unknown ATH11K_BD_IE_BOARD found: %d\n",
				    board_ie_id);
			break;
		}

		/* jump over the padding */
		board_ie_len = ALIGN(board_ie_len, 4);

		buf_len -= board_ie_len;
		buf += board_ie_len;
	}

	/* no match found */
	ret = -ENOENT;

out:
	return ret;
}

static int ath11k_core_fetch_board_data_api_n(struct ath11k_base *sc,
					      struct ath11k_board_data *bd,
					      const char *boardname)
{
	size_t len, magic_len;
	const u8 *data;
	char *filename = ATH11K_BOARD_API2_FILE;
	size_t ie_len;
	struct ath11k_fw_ie *hdr;
	int ret, ie_id;

	if (!bd->fw)
		bd->fw = ath11k_fetch_fw_file(sc,
					      sc->hw_params.fw.dir,
					      filename);
	if (IS_ERR(bd->fw)) {
		return PTR_ERR(bd->fw);
	}

	data = bd->fw->data;
	len = bd->fw->size;

	/* magic has extra null byte padded */
	magic_len = strlen(ATH11K_BOARD_MAGIC) + 1;
	if (len < magic_len) {
		ath11k_err(sc, "failed to find magic value in %s/%s, file too short: %zu\n",
			   sc->hw_params.fw.dir, filename, len);
		ret = -EINVAL;
		goto err;
	}

	if (memcmp(data, ATH11K_BOARD_MAGIC, magic_len)) {
		ath11k_err(sc, "found invalid board magic\n");
		ret = -EINVAL;
		goto err;
	}

	/* magic is padded to 4 bytes */
	magic_len = ALIGN(magic_len, 4);
	if (len < magic_len) {
		ath11k_err(sc, "failed: %s/%s too small to contain board data, len: %zu\n",
			   sc->hw_params.fw.dir, filename, len);
		ret = -EINVAL;
		goto err;
	}

	data += magic_len;
	len -= magic_len;

	while (len > sizeof(struct ath11k_fw_ie)) {
		hdr = (struct ath11k_fw_ie *)data;
		ie_id = le32_to_cpu(hdr->id);
		ie_len = le32_to_cpu(hdr->len);

		len -= sizeof(*hdr);
		data = hdr->data;

		if (len < ALIGN(ie_len, 4)) {
			ath11k_err(sc, "invalid length for board ie_id %d ie_len %zu len %zu\n",
				   ie_id, ie_len, len);
			return -EINVAL;
		}

		switch (ie_id) {
		case ATH11K_BD_IE_BOARD:
			ret = ath11k_core_parse_bd_ie_board(sc, bd, data,
							    ie_len,
							    boardname,
							    ATH11K_BD_IE_BOARD);
			if (ret == -ENOENT)
				/* no match found, continue */
				break;
			else if(ret)
				/* there was an error, bail out */
				goto err;
			/* either found or error, so stop searching */
			goto out;
		}

		/* jump over the padding */
		ie_len = ALIGN(ie_len, 4);

		len -= ie_len;
		data += ie_len;
	}

out:
	if (!bd->data || !bd->len) {
		ath11k_err(sc,
			   "failed to fetch board data for %s from %s/%s\n",
			   boardname, sc->hw_params.fw.dir, filename);
		ret = -ENODATA;
		goto err;
	}

	return 0;

err:
	ath11k_core_free_bdf(sc, bd);
	return ret;
}

static int ath11k_core_fetch_board_data_api_1(struct ath11k_base *sc,
					      struct ath11k_board_data *bd)
{
	bd->fw = ath11k_fetch_fw_file(sc,
				      sc->hw_params.fw.dir,
				      ATH11K_DEFAULT_BOARD_FILE);
	if (IS_ERR(bd->fw))
		return PTR_ERR(bd->fw);

	bd->data = bd->fw->data;
	bd->len = bd->fw->size;

	return 0;
}

#define BOARD_NAME_SIZE 100
int ath11k_core_fetch_bdf(struct ath11k_base *sc, struct ath11k_board_data *bd)
{
	char boardname[BOARD_NAME_SIZE];
	int ret;

	ret = ath11k_core_create_board_name(sc, boardname, BOARD_NAME_SIZE);
	if (ret) {
		ath11k_err(sc, "failed to create board name: %d", ret);
		return ret;
	}

	sc->bd_api = 2;
	ret = ath11k_core_fetch_board_data_api_n(sc, bd, boardname);
	if (!ret)
		goto success;

	sc->bd_api = 1;
	ret = ath11k_core_fetch_board_data_api_1(sc, bd);
	if (ret) {
		ath11k_err(sc, "failed to fetch board-2.bin or board.bin from %s\n",
			   sc->hw_params.fw.dir);
		return ret;
	}

success:
	ath11k_dbg(sc, ATH11K_DBG_BOOT, "using board api %d\n", sc->bd_api);
	return 0;

}

struct ath11k_peer *ath11k_peer_find(struct ath11k_base *ab, int vdev_id,
				     const u8 *addr)
{
	struct ath11k_peer *peer;

	lockdep_assert_held(&ab->data_lock);

	list_for_each_entry(peer, &ab->peers, list) {
		if (peer->vdev_id != vdev_id)
			continue;
		if (memcmp(peer->addr, addr, ETH_ALEN))
			continue;

		return peer;
	}

	return NULL;
}

struct ath11k_peer *ath11k_peer_find_by_addr(struct ath11k_base *ab,
					     const u8 *addr)
{
	struct ath11k_peer *peer;

	lockdep_assert_held(&ab->data_lock);

	list_for_each_entry(peer, &ab->peers, list) {
		if (memcmp(peer->addr, addr, ETH_ALEN))
			continue;

		return peer;
	}

	return NULL;
}

struct ath11k_peer *ath11k_peer_find_by_id(struct ath11k_base *ab,
					   int peer_id)
{
	struct ath11k_peer *peer;

	lockdep_assert_held(&ab->data_lock);

	list_for_each_entry(peer, &ab->peers, list)
		if (peer_id == peer->peer_id)
			return peer;

	return NULL;
}

void ath11k_peer_unmap_event(struct ath11k_base *ab, u16 peer_id)
{
	struct ath11k_peer *peer;

	if (peer_id >= ATH11K_MAX_NUM_PEER_IDS) {
		ath11k_warn(ab,
			    "received htt peer unmap event with idx out of bounds: %hu\n",
			    peer_id);
		return;
	}

	spin_lock_bh(&ab->data_lock);

	peer = ath11k_peer_find_by_id(ab, peer_id);
	if (!peer) {
		ath11k_warn(ab, "peer-unmap-event: unknown peer id %d\n",
			    peer_id);
		goto exit;
	}

	ath11k_dbg(ab, ATH11K_DBG_DP_HTT, "htt peer unmap vdev %d peer %pM id %d\n",
		   peer->vdev_id, peer->addr, peer_id);

	list_del(&peer->list);
	kfree(peer);
	wake_up(&ab->peer_mapping_wq);

exit:
	spin_unlock_bh(&ab->data_lock);
}

void ath11k_peer_map_event(struct ath11k_base *ab, u8 vdev_id, u16 peer_id,
			   u8 *mac_addr, u16 ast_hash)
{
	struct ath11k_peer *peer;

	if (peer_id >= ATH11K_MAX_NUM_PEER_IDS) {
		ath11k_warn(ab,
			    "received htt peer map event with idx out of bounds: %hu\n",
			    peer_id);
		return;
	}

	spin_lock_bh(&ab->data_lock);
	peer = ath11k_peer_find(ab, vdev_id, mac_addr);
	if (!peer) {
		peer = kzalloc(sizeof(*peer), GFP_ATOMIC);
		if (!peer)
			goto exit;

		peer->vdev_id = vdev_id;
		peer->peer_id = peer_id;
		peer->ast_hash = ast_hash;
		ether_addr_copy(peer->addr, mac_addr);
		list_add(&peer->list, &ab->peers);
		wake_up(&ab->peer_mapping_wq);
	}

	ath11k_dbg(ab, ATH11K_DBG_DP_HTT, "htt peer map vdev %d peer %pM id %d\n",
		   vdev_id, mac_addr, peer_id);

exit:
	spin_unlock_bh(&ab->data_lock);
}

static void ath11k_core_stop(struct ath11k_base *sc)
{
	ath11k_qmi_firmware_stop(sc);
	ath11k_ahb_stop(sc);
	ath11k_wmi_detach(sc);

	/* De-Init of components as needed */
}

static int ath11k_core_soc_create(struct ath11k_base *sc)
{
	int ret;

	ret = ath11k_qmi_init_service(sc);
	if (ret) {
		ath11k_err(sc, "failed to initialize qmi :%d\n", ret);
		return ret;
	}

	ret = ath11k_debug_soc_create(sc);
	if (ret) {
		ath11k_err(sc, "failed to create ath11k debugfs\n");
		goto err_qmi_deinit;
	}

	ret = ath11k_ahb_power_up(sc);
	if (ret) {
		ath11k_err(sc, "failed to power up :%d\n", ret);
		goto err_debugfs_reg;
	}

	ret = ath11k_dp_alloc(sc);
	if (ret) {
		ath11k_err(sc, "failed to init DP: %d\n", ret);
		goto err_power_down;
	}

	return 0;

err_power_down:
	ath11k_ahb_power_down(sc);
err_debugfs_reg:
	ath11k_debug_soc_destroy(sc);
err_qmi_deinit:
	ath11k_qmi_deinit_service(sc);
	return ret;
}

static void ath11k_core_soc_destroy(struct ath11k_base *sc)
{
	ath11k_debug_soc_destroy(sc);
	ath11k_dp_free(sc);
	ath11k_reg_free(sc);
	ath11k_qmi_deinit_service(sc);
}

static int ath11k_core_pdev_create(struct ath11k_base *sc)
{
	int ret;

	ret = ath11k_mac_create(sc);
	if (ret) {
		ath11k_err(sc, "falied to create new hw device with mac80211 :%d\n",
			   ret);
		return ret;
	}

	ret = ath11k_dp_pdev_alloc(sc);
	if (ret) {
		ath11k_err(sc, "failed to attach DP pdev: %d\n", ret);
		goto err_mac_destroy;
	}

	return 0;

err_mac_destroy:
	ath11k_mac_destroy(sc);

	return ret;
}

static void ath11k_core_pdev_destroy(struct ath11k_base *sc)
{
	ath11k_mac_unregister(sc);
	ath11k_dp_pdev_free(sc);
}

static int ath11k_core_start(struct ath11k_base *sc,
			     enum ath11k_firmware_mode mode)
{
	int ret;

	ret = ath11k_qmi_firmware_start(sc, mode);
	if (ret) {
		ath11k_err(sc, "failed to attach wmi: %d\n", ret);
		return ret;
	}

	ret = ath11k_wmi_attach(sc);
	if (ret) {
		ath11k_err(sc, "failed to attach wmi: %d\n", ret);
		goto err_firmware_stop;
	}

	ret = ath11k_htc_init(sc);
	if (ret) {
		ath11k_err(sc, "failed to init htc: %d\n", ret);
		goto err_wmi_detach;
	}

	ret = ath11k_ahb_start(sc);
	if (ret) {
		ath11k_err(sc, "failed to start HIF: %d\n", ret);
		goto err_wmi_detach;
	}

	ret = ath11k_htc_wait_target(&sc->htc);
	if (ret) {
		ath11k_err(sc, "failed to connect to HTC: %d\n", ret);
		goto err_hif_stop;
	}

	ret = ath11k_dp_htt_connect(&sc->dp);
	if (ret) {
		ath11k_err(sc, "failed to connect to HTT: %d\n", ret);
		goto err_hif_stop;
	}

	ret = ath11k_wmi_connect(sc);
	if (ret) {
		ath11k_err(sc, "failed to connect wmi: %d\n", ret);
		goto err_hif_stop;
	}

	ret = ath11k_htc_start(&sc->htc);
	if (ret) {
		ath11k_err(sc, "failed to start HTC: %d\n", ret);
		goto err_hif_stop;
	}

	ret = ath11k_wmi_wait_for_service_ready(sc);
	if (ret) {
		ath11k_err(sc, "failed to receive wmi service ready event: %d\n",
			   ret);
		goto err_hif_stop;
	}

	ret = ath11k_wmi_cmd_init(sc);
	if (ret) {
		ath11k_err(sc, "failed to send wmi init cmd: %d\n", ret);
		goto err_hif_stop;
	}

	ret = ath11k_wmi_wait_for_unified_ready(sc);
	if (ret) {
		ath11k_err(sc, "failed to receive wmi unified ready event: %d\n",
			   ret);
		goto err_hif_stop;
	}

	ret = ath11k_dp_htt_h2t_ver_req_msg(sc);
	if (ret) {
		ath11k_err(sc, "failed to send htt version request message: %d\n",
			   ret);
		goto err_hif_stop;
	}

	return 0;

err_hif_stop:
	ath11k_ahb_stop(sc);
err_wmi_detach:
	ath11k_wmi_detach(sc);
err_firmware_stop:
	ath11k_qmi_firmware_stop(sc);

	return ret;
}

int ath11k_core_init(struct ath11k_base *sc)
{
	struct device *dev = sc->dev;
	struct rproc *prproc;
	phandle rproc_phandle;
	int ret;

#ifndef CONFIG_IPQ_SUBSYSTEM_RESTART
	if (of_property_read_u32(dev->of_node, "q6_rproc", &rproc_phandle)) {
		ath11k_err(sc, "failed to get q6_rproc handle\n");
		return -ENOENT;
	}

	prproc = rproc_get_by_phandle(rproc_phandle);
	if (!prproc) {
		ath11k_err(sc, "failed to get rproc\n");
		return -EINVAL;
	}
	sc->tgt_rproc = prproc;
#endif

	sc->hw_params = ath11k_hw_params;

	ret = ath11k_core_soc_create(sc);
	if (ret) {
		ath11k_err(sc, "failed to create soc core: %d\n", ret);
		return ret;
	}

	mutex_lock(&sc->core_lock);
	ret = ath11k_core_start(sc, ATH11K_FIRMWARE_MODE_NORMAL);
	if (ret) {
		mutex_unlock(&sc->core_lock);
		ath11k_core_soc_destroy(sc);
		ath11k_err(sc, "failed to init core: %d\n", ret);
		return ret;
	}

	ret = ath11k_core_pdev_create(sc);
	if (ret) {
		mutex_unlock(&sc->core_lock);
		ath11k_core_soc_destroy(sc);
		ath11k_err(sc, "failed to create pdev core: %d\n", ret);
		return ret;
	}

	ath11k_ahb_ext_irq_enable(sc);

	mutex_unlock(&sc->core_lock);

	return 0;
}

void ath11k_core_deinit(struct ath11k_base *sc)
{
	mutex_lock(&sc->core_lock);

	ath11k_ahb_ext_irq_disable(sc);
	ath11k_core_pdev_destroy(sc);
	ath11k_core_stop(sc);

	mutex_unlock(&sc->core_lock);

	ath11k_ahb_power_down(sc);
	ath11k_mac_destroy(sc);
	ath11k_core_soc_destroy(sc);
}

void ath11k_core_free(struct ath11k_base *sc)
{
	flush_workqueue(sc->qmi.wq);
	destroy_workqueue(sc->qmi.wq);
	destroy_workqueue(sc->qmi.qmi_resp_wq);

	kfree(sc);
}

struct ath11k_base *ath11k_core_alloc(struct device *dev)
{
	struct ath11k_base *sc;

	sc = kzalloc(sizeof(*sc), GFP_KERNEL);
	if (!sc)
		return NULL;

	init_completion(&sc->fw_ready);

	sc->qmi.wq = create_singlethread_workqueue("ath11k_qmi_wq");
	if (!sc->qmi.wq)
		goto err_qmi_wq;

	sc->qmi.qmi_resp_wq = create_singlethread_workqueue("ath11k_qmi_resp_wq");
	if (!sc->qmi.wq)
		goto err_qmi_resp_wq;

	mutex_init(&sc->core_lock);
	spin_lock_init(&sc->data_lock);

	spin_lock_init(&sc->qmi.event_msg_lock);
	INIT_WORK(&sc->qmi.event_work, ath11k_qmi_event_work);
	INIT_LIST_HEAD(&sc->qmi.event_msg_list);
	INIT_LIST_HEAD(&sc->peers);
	init_waitqueue_head(&sc->peer_mapping_wq);
	init_waitqueue_head(&sc->wmi_sc.tx_credits_wq);
	INIT_WORK(&sc->qmi.msg_recv_work, ath11k_qmi_msg_recv_work);

	timer_setup(&sc->rx_replenish_retry, ath11k_ce_rx_replenish_retry, 0);

	sc->dev = dev;

	return sc;

err_qmi_resp_wq:
	destroy_workqueue(sc->qmi.wq);
err_qmi_wq:
	kfree(sc);

	return NULL;
}

static int __init ath11k_init(void)
{
	int ret;

	ret = ath11k_ahb_init();
	if (ret)
		printk(KERN_ERR "failed to register ath11k ahb driver: %d\n",
		       ret);
	return ret;
}
module_init(ath11k_init);

static void __exit ath11k_exit(void)
{
	ath11k_ahb_exit();
}
module_exit(ath11k_exit);

MODULE_DESCRIPTION("Driver support for Qualcomm Technologies 802.11ax wireless chip");
MODULE_LICENSE("Dual BSD/GPL");
