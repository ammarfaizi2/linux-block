// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2018-2019 The Linux Foundation. All rights reserved.
 */

#include <linux/vmalloc.h>
#include "core.h"
#include "debug.h"
#include "wmi.h"
#include "hal_rx.h"
#include "dp_rx.h"

void ath11k_info(struct ath11k_base *sc, const char *fmt, ...)
{
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	va_start(args, fmt);
	vaf.va = &args;
	dev_info(sc->dev, "%pV", &vaf);
	/* TODO: Trace the log */
	va_end(args);
}

void ath11k_err(struct ath11k_base *sc, const char *fmt, ...)
{
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	va_start(args, fmt);
	vaf.va = &args;
	dev_err(sc->dev, "%pV", &vaf);
	/* TODO: Trace the log */
	va_end(args);
}

void ath11k_warn(struct ath11k_base *sc, const char *fmt, ...)
{
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	va_start(args, fmt);
	vaf.va = &args;
	dev_warn_ratelimited(sc->dev, "%pV", &vaf);
	/* TODO: Trace the log */
	va_end(args);
}

#ifdef CONFIG_ATH11K_DEBUG
void ath11k_dbg(struct ath11k_base *ab, enum ath11k_debug_mask mask,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	if (ath11k_debug_mask & mask)
		dev_printk(KERN_DEBUG, ab->dev, "%pV", &vaf);

	/* TODO: trace log */

	va_end(args);
}

void ath11k_dbg_dump(struct ath11k_base *ab,
		     enum ath11k_debug_mask mask,
		     const char *msg, const char *prefix,
		     const void *buf, size_t len)
{
	char linebuf[256];
	size_t linebuflen;
	const void *ptr;

	if (ath11k_debug_mask & mask) {
		if (msg)
			ath11k_dbg(ab, mask, "%s\n", msg);

		for (ptr = buf; (ptr - buf) < len; ptr += 16) {
			linebuflen = 0;
			linebuflen += scnprintf(linebuf + linebuflen,
						sizeof(linebuf) - linebuflen,
						"%s%08x: ",
						(prefix ? prefix : ""),
						(unsigned int)(ptr - buf));
			hex_dump_to_buffer(ptr, len - (ptr - buf), 16, 1,
					   linebuf + linebuflen,
					   sizeof(linebuf) - linebuflen, true);
			dev_printk(KERN_DEBUG, ab->dev, "%s\n", linebuf);
		}
	}

}

#endif

#ifdef CONFIG_ATH11K_DEBUGFS
static void ath11k_fw_stats_pdevs_free(struct list_head *head)
{
	struct ath11k_fw_stats_pdev *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath11k_fw_stats_vdevs_free(struct list_head *head)
{
	struct ath11k_fw_stats_vdev *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath11k_fw_stats_bcn_free(struct list_head *head)
{
	struct ath11k_fw_stats_bcn *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath11k_fw_stats_peers_free(struct list_head *head)
{
	struct ath11k_fw_stats_peer *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath11k_fw_stats_peers_extd_free(struct list_head *head)
{
	struct ath11k_fw_stats_peer_extd *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath11k_debug_fw_stats_reset(struct ath11k *ar)
{
	spin_lock_bh(&ar->data_lock);
	ar->debug.fw_stats_done = false;
	ath11k_fw_stats_pdevs_free(&ar->debug.fw_stats.pdevs);
	ath11k_fw_stats_vdevs_free(&ar->debug.fw_stats.vdevs);
	ath11k_fw_stats_peers_free(&ar->debug.fw_stats.peers);
	ath11k_fw_stats_peers_extd_free(&ar->debug.fw_stats.peers_extd);
	spin_unlock_bh(&ar->data_lock);
}

void ath11k_debug_fw_stats_process(struct ath11k_base *ab, u8 *evt_buf, u32 len)
{
	struct ath11k_fw_stats stats = {};
	struct ath11k *ar;
	struct ath11k_pdev *pdev;
	struct ath11k_peer *peer;
	bool is_end;
	static unsigned int num_vdev, num_bcn, num_peer;
	size_t total_vdevs_started = 0;
	size_t num_peer_stats = 0;
	int i, ret, total_num_peers = 0;

	INIT_LIST_HEAD(&stats.pdevs);
	INIT_LIST_HEAD(&stats.vdevs);
	INIT_LIST_HEAD(&stats.peers);
	INIT_LIST_HEAD(&stats.bcn);
	INIT_LIST_HEAD(&stats.peers_extd);

	ret = ath11k_wmi_pull_fw_stats(ab, evt_buf, len, &stats);
	if (ret) {
		ath11k_warn(ab, "failed to pull fw stats: %d\n", ret);
		goto free;
	}

	ar = ath11k_get_ar_by_pdev_id(ab, stats.pdev_id);
	if (!ar) {
		ath11k_warn(ab, "failed to get ar for pdev_id %d: %d\n",
			    stats.pdev_id, ret);
		goto free;
	}

	spin_lock_bh(&ar->data_lock);

	if (stats.stats_id == WMI_REQUEST_PDEV_STAT) {
		list_splice_tail_init(&stats.pdevs, &ar->debug.fw_stats.pdevs);
		ar->debug.fw_stats_done = true;
		goto complete;
	}

	if (stats.stats_id == WMI_REQUEST_VDEV_STAT) {
		if (list_empty(&stats.vdevs)) {
			ath11k_warn(ab, "empty vdev stats");
			goto complete;
		}
		/* FW sends all the active VDEV stats irrespective of PDEV,
		 * hence limit until the count of all VDEVs started
		 */
		for (i = 0; i < ab->num_radios; i++) {
			pdev = rcu_dereference(ab->pdevs_active[i]);
			if (pdev && pdev->ar)
				total_vdevs_started += ar->num_started_vdevs;
		}

		is_end = ((++num_vdev) == total_vdevs_started ? true : false);

		list_splice_tail_init(&stats.vdevs,
				      &ar->debug.fw_stats.vdevs);

		if (is_end) {
			ar->debug.fw_stats_done = true;
			num_vdev = 0;
		}
		goto complete;
	}

	if (stats.stats_id == WMI_REQUEST_BCN_STAT) {
		if (list_empty(&stats.bcn)) {
			ath11k_warn(ab, "empty bcn stats");
			goto complete;
		}
		/* Mark end until we reached the count of all started VDEVs
		 * within the PDEV
		 */
		is_end = ((++num_bcn) == ar->num_started_vdevs ? true : false);

		list_splice_tail_init(&stats.bcn,
				      &ar->debug.fw_stats.bcn);

		if (is_end) {
			ar->debug.fw_stats_done = true;
			num_bcn = 0;
		}
		goto complete;
	}

	if (stats.stats_id & (WMI_REQUEST_PEER_STAT |
			      WMI_REQUEST_PEER_EXTD_STAT)) {
		if (list_empty(&stats.peers) && list_empty(&stats.peers_extd)) {
			ath11k_warn(ab, "empty peer, peer extd stats");
			goto complete;
		}
		/* FW splits the peer stats when exceeding htc-wmi buffer limit
		 * and send back-to-back 'update stats' event. Hence we save the
		 * peer stats based on the count until reaching total peers count
		 */
		num_peer_stats = ath11k_wmi_fw_stats_num_peers(&stats.peers);

		spin_lock_bh(&ab->data_lock);
		list_for_each_entry(peer, &ab->peers, list)
			total_num_peers++;
		spin_unlock_bh(&ab->data_lock);

		for (i = 0; i < num_peer_stats; i++) {
			num_peer++;
			list_splice_tail_init(&stats.peers,
					      &ar->debug.fw_stats.peers);

			list_splice_tail_init(&stats.peers_extd,
					      &ar->debug.fw_stats.peers_extd);
			ath11k_sta_update_rx_duration(ar, &stats);
		}

		if (num_peer >= total_num_peers) {
			ar->debug.fw_stats_done = true;
			num_peer = 0;
		}
	}
complete:
	complete(&ar->debug.fw_stats_complete);
	spin_unlock_bh(&ar->data_lock);

free:
	ath11k_fw_stats_pdevs_free(&stats.pdevs);
	ath11k_fw_stats_vdevs_free(&stats.vdevs);
	ath11k_fw_stats_bcn_free(&stats.bcn);
	ath11k_fw_stats_peers_free(&stats.peers);
	ath11k_fw_stats_peers_extd_free(&stats.peers_extd);
}

static int ath11k_debug_fw_stats_request(struct ath11k *ar,
					 struct stats_request_params *req_param)
{
	struct ath11k_base *ab = ar->ab;
	unsigned long timeout, time_left;
	int ret;

	lockdep_assert_held(&ar->conf_mutex);

	/* FW stats can get split when exceeding the stats data buffer limit.
	 * In that case, since there is no end marking for the back-to-back
	 * received 'update stats' event, we keep a 3 seconds timeout in case,
	 * fw_stats_done is not marked yet
	 */
	timeout = jiffies + msecs_to_jiffies(3 * HZ);

	ath11k_debug_fw_stats_reset(ar);

	reinit_completion(&ar->debug.fw_stats_complete);

	ret = ath11k_wmi_send_stats_request_cmd(ar, req_param);

	if (ret) {
		ath11k_warn(ab, "could not request fw stats (%d)\n",
			    ret);
		return ret;
	}

	time_left =
	wait_for_completion_timeout(&ar->debug.fw_stats_complete,
				    1 * HZ);
	if (!time_left)
		return -ETIMEDOUT;

	for (;;) {
		if (time_after(jiffies, timeout))
			break;

		spin_lock_bh(&ar->data_lock);
		if (ar->debug.fw_stats_done) {
			spin_unlock_bh(&ar->data_lock);
			break;
		}
		spin_unlock_bh(&ar->data_lock);
	}
	return 0;
}

static int ath11k_open_pdev_stats(struct inode *inode, struct file *file)
{
	struct ath11k *ar = inode->i_private;
	struct ath11k_base *ab = ar->ab;
	struct stats_request_params req_param;
	void *buf = NULL;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH11K_STATE_ON) {
		ret = -ENETDOWN;
		goto err_unlock;
	}

	buf = vmalloc(ATH11K_FW_STATS_BUF_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	req_param.pdev_id = ar->pdev->pdev_id;
	req_param.vdev_id = 0;
	req_param.stats_id = WMI_REQUEST_PDEV_STAT;

	ret = ath11k_debug_fw_stats_request(ar, &req_param);
	if (ret) {
		ath11k_warn(ab, "failed to request fw pdev stats: %d\n", ret);
		goto err_free;
	}

	ath11k_wmi_fw_stats_fill(ar, &ar->debug.fw_stats, req_param.stats_id,
				 buf);

	file->private_data = buf;

	mutex_unlock(&ar->conf_mutex);
	return 0;

err_free:
	vfree(buf);

err_unlock:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static int ath11k_release_pdev_stats(struct inode *inode, struct file *file)
{
	vfree(file->private_data);

	return 0;
}

static ssize_t ath11k_read_pdev_stats(struct file *file,
				      char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	const char *buf = file->private_data;
	size_t len = strlen(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_pdev_stats = {
	.open = ath11k_open_pdev_stats,
	.release = ath11k_release_pdev_stats,
	.read = ath11k_read_pdev_stats,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath11k_open_vdev_stats(struct inode *inode, struct file *file)
{
	struct ath11k *ar = inode->i_private;
	struct stats_request_params req_param;
	void *buf = NULL;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH11K_STATE_ON) {
		ret = -ENETDOWN;
		goto err_unlock;
	}

	buf = vmalloc(ATH11K_FW_STATS_BUF_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	req_param.pdev_id = ar->pdev->pdev_id;
	/* VDEV stats is always sent for all active VDEVs from FW */
	req_param.vdev_id = 0;
	req_param.stats_id = WMI_REQUEST_VDEV_STAT;

	ret = ath11k_debug_fw_stats_request(ar, &req_param);
	if (ret) {
		ath11k_warn(ar->ab, "failed to request fw vdev stats: %d\n", ret);
		goto err_free;
	}

	ath11k_wmi_fw_stats_fill(ar, &ar->debug.fw_stats, req_param.stats_id,
				 buf);

	file->private_data = buf;

	mutex_unlock(&ar->conf_mutex);
	return 0;

err_free:
	vfree(buf);

err_unlock:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static int ath11k_release_vdev_stats(struct inode *inode, struct file *file)
{
	vfree(file->private_data);

	return 0;
}

static ssize_t ath11k_read_vdev_stats(struct file *file,
				      char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	const char *buf = file->private_data;
	size_t len = strlen(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_vdev_stats = {
	.open = ath11k_open_vdev_stats,
	.release = ath11k_release_vdev_stats,
	.read = ath11k_read_vdev_stats,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath11k_open_bcn_stats(struct inode *inode, struct file *file)
{
	struct ath11k *ar = inode->i_private;
	struct ath11k_vif *arvif;
	struct stats_request_params req_param;
	void *buf = NULL;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH11K_STATE_ON) {
		ret = -ENETDOWN;
		goto err_unlock;
	}

	buf = vmalloc(ATH11K_FW_STATS_BUF_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	req_param.stats_id = WMI_REQUEST_BCN_STAT;
	req_param.pdev_id = ar->pdev->pdev_id;

	/* loop all active VDEVs for bcn stats */
	list_for_each_entry(arvif, &ar->arvifs, list) {
		if (!arvif->is_up)
			continue;

		req_param.vdev_id = arvif->vdev_id;
		ret = ath11k_debug_fw_stats_request(ar, &req_param);
		if (ret) {
			ath11k_warn(ar->ab, "failed to request fw bcn stats: %d\n", ret);
			goto err_free;
		}
	}

	ath11k_wmi_fw_stats_fill(ar, &ar->debug.fw_stats, req_param.stats_id,
				 buf);

	/* since beacon stats request is looped for all active VDEVs, saved fw
	 * stats is not freed for each request until done for all active VDEVs
	 */
	spin_lock_bh(&ar->data_lock);
	ath11k_fw_stats_bcn_free(&ar->debug.fw_stats.bcn);
	spin_unlock_bh(&ar->data_lock);

	file->private_data = buf;

	mutex_unlock(&ar->conf_mutex);
	return 0;

err_free:
	vfree(buf);

err_unlock:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static int ath11k_release_bcn_stats(struct inode *inode, struct file *file)
{
	vfree(file->private_data);

	return 0;
}

static ssize_t ath11k_read_bcn_stats(struct file *file,
				     char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	const char *buf = file->private_data;
	size_t len = strlen(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_bcn_stats = {
	.open = ath11k_open_bcn_stats,
	.release = ath11k_release_bcn_stats,
	.read = ath11k_read_bcn_stats,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath11k_open_peer_stats(struct inode *inode, struct file *file)
{
	struct ath11k *ar = inode->i_private;
	struct stats_request_params req_param;
	void *buf = NULL;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH11K_STATE_ON) {
		ret = -ENETDOWN;
		goto err_unlock;
	}

	buf = vmalloc(ATH11K_FW_STATS_BUF_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	req_param.pdev_id = ar->pdev->pdev_id;
	req_param.vdev_id = 0;
	req_param.stats_id = (WMI_REQUEST_PEER_STAT |
			      WMI_REQUEST_PEER_EXTD_STAT);

	ret = ath11k_debug_fw_stats_request(ar, &req_param);
	if (ret) {
		ath11k_warn(ar->ab, "failed to request fw vdev stats: %d\n", ret);
		goto err_free;
	}

	ath11k_wmi_fw_stats_fill(ar, &ar->debug.fw_stats, req_param.stats_id,
				 buf);

	file->private_data = buf;

	mutex_unlock(&ar->conf_mutex);
	return 0;

err_free:
	vfree(buf);

err_unlock:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static int ath11k_release_peer_stats(struct inode *inode, struct file *file)
{
	vfree(file->private_data);

	return 0;
}

static ssize_t ath11k_read_peer_stats(struct file *file,
				      char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	const char *buf = file->private_data;
	size_t len = strlen(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_peer_stats = {
	.open = ath11k_open_peer_stats,
	.release = ath11k_release_peer_stats,
	.read = ath11k_read_peer_stats,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath11k_read_simulate_fw_crash(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	const char buf[] =
		"To simulate firmware crash write one of the keywords to this file:\n"
		"`assert` - this will send WMI_FORCE_FW_HANG_CMDID to firmware to cause assert.\n"
		"`hw-restart` - this will simply queue hw restart without fw/hw actually crashing.\n";

	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

/* Simulate firmware crash:
 * 'soft': Call wmi command causing firmware hang. This firmware hang is
 * recoverable by warm firmware reset.
 * 'hard': Force firmware crash by setting any vdev parameter for not allowed
 * vdev id. This is hard firmware crash because it is recoverable only by cold
 * firmware reset.
 */
static ssize_t ath11k_write_simulate_fw_crash(struct file *file,
					      const char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ath11k_base *ab = file->private_data;
	struct ath11k_pdev *pdev;
	struct ath11k *ar = ab->pdevs[0].ar;
	struct crash_inject param;
	char buf[32] = {0};
	ssize_t rc;
	int i, ret, radioup;

	for (i = 0; i < ab->num_radios; i++) {
		pdev = &ab->pdevs[i];
		ar = pdev->ar;
		if (ar && ar->state == ATH11K_STATE_ON) {
			radioup = 1;
			break;
		}
	}
	/* filter partial writes and invalid commands */
	if (*ppos != 0 || count >= sizeof(buf) || count == 0)
		return -EINVAL;

	rc = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);
	if (rc < 0)
		return rc;

	/* drop the possible '\n' from the end */
	if (buf[*ppos - 1] == '\n')
		buf[*ppos - 1] = '\0';

	if (radioup == 0) {
		ret = -ENETDOWN;
		goto exit;
	}

	if (!strcmp(buf, "assert")) {
		ath11k_info(ab, "simulating firmware assert crash\n");
		param.type = ATH11K_WMI_FW_HANG_ASSERT_TYPE;
		param.delay_time_ms = ATH11K_WMI_FW_HANG_DELAY;
		ret = ath11k_send_crash_inject_cmd(&ab->wmi_sc.wmi[0], &param);
	} else {
		ret = -EINVAL;
		goto exit;
	}

	if (ret) {
		ath11k_warn(ab, "failed to simulate firmware crash: %d\n", ret);
		goto exit;
	}

	ret = count;

exit:
	return ret;
}

static const struct file_operations fops_simulate_fw_crash = {
	.read = ath11k_read_simulate_fw_crash,
	.write = ath11k_write_simulate_fw_crash,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath11k_write_enable_extd_tx_stats(struct file *file,
						 const char __user *ubuf,
						 size_t count, loff_t *ppos)
{
	struct ath11k *ar = file->private_data;
	u32 filter;
	int ret;

	if (kstrtouint_from_user(ubuf, count, 0, &filter))
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH11K_STATE_ON) {
		ret = -ENETDOWN;
		goto out;
	}

	if (filter == ar->debug.extd_tx_stats) {
		ret = count;
		goto out;
	}

	ar->debug.extd_tx_stats = filter;
	ret = count;

out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static ssize_t ath11k_read_enable_extd_tx_stats(struct file *file,
						char __user *ubuf,
						size_t count, loff_t *ppos)

{
	char buf[32] = {0};
	struct ath11k *ar = file->private_data;
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%08x\n",
			ar->debug.extd_tx_stats);
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_extd_tx_stats = {
	.read = ath11k_read_enable_extd_tx_stats,
	.write = ath11k_write_enable_extd_tx_stats,
	.open = simple_open
};

static ssize_t ath11k_write_extd_rx_stats(struct file *file,
					  const char __user *ubuf,
					  size_t count, loff_t *ppos)
{
	struct ath11k *ar = file->private_data;
	struct htt_rx_ring_tlv_filter tlv_filter = {0};
	u32 enable, rx_filter = 0, ring_id;
	int ret;

	if (kstrtouint_from_user(ubuf, count, 0, &enable))
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH11K_STATE_ON) {
		ret = -ENETDOWN;
		goto exit;
	}

	if (enable < 0 || enable > 1) {
		ret = -EINVAL;
		goto exit;
	}

	if (enable == ar->debug.extd_rx_stats) {
		ret = count;
		goto exit;
	}

	if (enable) {
		rx_filter =  HTT_RX_FILTER_TLV_FLAGS_MPDU_START;
		rx_filter |= HTT_RX_FILTER_TLV_FLAGS_PPDU_START;
		rx_filter |= HTT_RX_FILTER_TLV_FLAGS_PPDU_END;
		rx_filter |= HTT_RX_FILTER_TLV_FLAGS_PPDU_END_USER_STATS;
		rx_filter |= HTT_RX_FILTER_TLV_FLAGS_PPDU_END_USER_STATS_EXT;
		rx_filter |= HTT_RX_FILTER_TLV_FLAGS_PPDU_END_STATUS_DONE;

		tlv_filter.rx_filter = rx_filter;
		tlv_filter.pkt_filter_flags0 = HTT_RX_FP_MGMT_FILTER_FLAGS0;
		tlv_filter.pkt_filter_flags1 = HTT_RX_FP_MGMT_FILTER_FLAGS1;
		tlv_filter.pkt_filter_flags2 = HTT_RX_FP_CTRL_FILTER_FLASG2;
		tlv_filter.pkt_filter_flags3 = HTT_RX_FP_CTRL_FILTER_FLASG3 |
			HTT_RX_FP_DATA_FILTER_FLASG3;
	}

	ring_id = ar->dp.rx_mon_status_refill_ring.refill_buf_ring.ring_id;
	ret = ath11k_dp_htt_rx_filter_setup(ar->ab, ring_id, ar->dp.mac_id,
					    HAL_RXDMA_MONITOR_STATUS,
					    DP_RX_BUFFER_SIZE, &tlv_filter);

	if (ret) {
		ath11k_warn(ar->ab, "failed to set rx filter for moniter status ring\n");
		goto exit;
	}

	ar->debug.extd_rx_stats = enable;
	ret = count;
exit:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static ssize_t ath11k_read_extd_rx_stats(struct file *file,
					 char __user *ubuf,
					 size_t count, loff_t *ppos)
{
	struct ath11k *ar = file->private_data;
	char buf[32];
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%d\n",
			ar->debug.extd_rx_stats);
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_extd_rx_stats = {
	.read = ath11k_read_extd_rx_stats,
	.write = ath11k_write_extd_rx_stats,
	.open = simple_open,
};

static ssize_t ath11k_debug_dump_soc_rx_stats(struct file *file,
					      char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ath11k_base *ab = file->private_data;
	struct ath11k_soc_dp_rx_stats *soc_stats = &ab->soc_stats;
	int len = 0, i, retval;
	const int size = 4096;
	char *buf;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len += scnprintf(buf + len, size - len, "SOC Rx stats:\n");
	len += scnprintf(buf + len, size - len, "err ring pkts: %u\n",
			 soc_stats->err_ring_pkts);
	len += scnprintf(buf + len, size - len, "Invalid RBM: %u\n",
			 soc_stats->invalid_rbm);
	len += scnprintf(buf + len, size - len, "RXDMA errors:");
	for (i = 0; i < HAL_REO_ENTR_RING_RXDMA_ECODE_MAX; i++)
		len += scnprintf(buf + len, size - len, "%u ",
				 soc_stats->rxdma_error[i]);

	len += scnprintf(buf + len, size - len, "\nREO errors:");
	for (i = 0; i < HAL_REO_DEST_RING_ERROR_CODE_MAX; i++)
		len += scnprintf(buf + len, size - len, "%u ",
				 soc_stats->reo_error[i]);

	len += scnprintf(buf + len, size - len, "\nHAL REO errors:");
	for (i = 0; i < DP_REO_DST_RING_MAX; i++)
		len += scnprintf(buf + len, size - len, "%u ",
				 soc_stats->hal_reo_error[i]);
	len += scnprintf(buf + len, size - len, "\n");

	if (len > size)
		len = size;
	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return retval;
}

static const struct file_operations fops_soc_rx_stats = {
	.read = ath11k_debug_dump_soc_rx_stats,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

int ath11k_debug_soc_create(struct ath11k_base *ab)
{
	ab->debugfs_soc = debugfs_create_dir("ath11k", NULL);

	if (IS_ERR_OR_NULL(ab->debugfs_soc)) {
		if (IS_ERR(ab->debugfs_soc))
			return PTR_ERR(ab->debugfs_soc);
		return -ENOMEM;
	}

	debugfs_create_file("simulate_fw_crash", 0600, ab->debugfs_soc, ab,
			    &fops_simulate_fw_crash);

	debugfs_create_file("soc_rx_stats", 0600, ab->debugfs_soc, ab,
			    &fops_soc_rx_stats);

	return 0;
}

void ath11k_debug_soc_destroy(struct ath11k_base *ab)
{
	debugfs_remove_recursive(ab->debugfs_soc);
	ab->debugfs_soc = NULL;
}

void ath11k_debug_fw_stats_init(struct ath11k *ar)
{
	struct dentry *fwstats_dir = debugfs_create_dir("fw_stats",
							ar->debug.debugfs_pdev);

	ar->debug.fw_stats.debugfs_fwstats = fwstats_dir;

	/* all stats debugfs files created are under "fw_stats" directory
	 * created per PDEV
	 */
	debugfs_create_file("pdev_stats", 0600, fwstats_dir, ar,
			    &fops_pdev_stats);
	debugfs_create_file("vdev_stats", 0600, fwstats_dir, ar,
			    &fops_vdev_stats);
	debugfs_create_file("beacon_stats", 0600, fwstats_dir, ar,
			    &fops_bcn_stats);
	debugfs_create_file("peer_stats", 0600, fwstats_dir, ar,
			    &fops_peer_stats);

	INIT_LIST_HEAD(&ar->debug.fw_stats.pdevs);
	INIT_LIST_HEAD(&ar->debug.fw_stats.vdevs);
	INIT_LIST_HEAD(&ar->debug.fw_stats.bcn);
	INIT_LIST_HEAD(&ar->debug.fw_stats.peers);
	INIT_LIST_HEAD(&ar->debug.fw_stats.peers_extd);

	init_completion(&ar->debug.fw_stats_complete);
}

int ath11k_debug_register(struct ath11k *ar)
{
	struct ath11k_base *ab = ar->ab;
	char pdev_name[5];
	char buf[100] = {0};

	snprintf(pdev_name, sizeof(pdev_name), "%s%d", "mac", ar->pdev_idx);

	ar->debug.debugfs_pdev = debugfs_create_dir(pdev_name, ab->debugfs_soc);

	if (IS_ERR_OR_NULL(ar->debug.debugfs_pdev)) {
		if (IS_ERR(ar->debug.debugfs_pdev))
			return PTR_ERR(ar->debug.debugfs_pdev);

		return -ENOMEM;
	}

	/* Create a symlink under ieee80211/phy* */
	snprintf(buf, 100, "../../%pd2", ar->debug.debugfs_pdev);
	debugfs_create_symlink("ath11k", ar->hw->wiphy->debugfsdir, buf);

	ath11k_htt_stats_debugfs_init(ar);

	ath11k_debug_fw_stats_init(ar);

	debugfs_create_file("ext_tx_stats", 0644,
			    ar->debug.debugfs_pdev, ar,
			    &fops_extd_tx_stats);
	debugfs_create_file("ext_rx_stats", 0644,
			    ar->debug.debugfs_pdev, ar,
			    &fops_extd_rx_stats);
	return 0;
}

void ath11k_debug_unregister(struct ath11k *ar)
{
}
#endif /* CONFIG_ATH11K_DEBUGFS */
