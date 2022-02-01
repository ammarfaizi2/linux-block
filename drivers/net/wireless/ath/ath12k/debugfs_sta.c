// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/vmalloc.h>

#include "debugfs_sta.h"
#include "core.h"
#include "peer.h"
#include "debug.h"
#include "dp_tx.h"
#include "debugfs_htt_stats.h"

void ath12k_debugfs_sta_add_tx_stats(struct ath12k_sta *arsta,
				     struct ath12k_per_peer_tx_stats *peer_stats,
				     u8 legacy_rate_idx)
{
	struct rate_info *txrate = &arsta->txrate;
	struct ath12k_htt_tx_stats *tx_stats;
	int gi, mcs, bw, nss, ru_type, ppdu_type;

	if (!arsta->tx_stats)
		return;

	tx_stats = arsta->tx_stats;
	gi = FIELD_GET(RATE_INFO_FLAGS_SHORT_GI, arsta->txrate.flags);
	mcs = txrate->mcs;
	bw = ath12k_mac_mac80211_bw_to_ath12k_bw(txrate->bw);
	nss = txrate->nss - 1;

#define STATS_OP_FMT(name) tx_stats->stats[ATH12K_STATS_TYPE_##name]

	if (txrate->flags & RATE_INFO_FLAGS_HE_MCS) {
		STATS_OP_FMT(SUCC).he[0][mcs] += peer_stats->succ_bytes;
		STATS_OP_FMT(SUCC).he[1][mcs] += peer_stats->succ_pkts;
		STATS_OP_FMT(FAIL).he[0][mcs] += peer_stats->failed_bytes;
		STATS_OP_FMT(FAIL).he[1][mcs] += peer_stats->failed_pkts;
		STATS_OP_FMT(RETRY).he[0][mcs] += peer_stats->retry_bytes;
		STATS_OP_FMT(RETRY).he[1][mcs] += peer_stats->retry_pkts;
	} else if (txrate->flags & RATE_INFO_FLAGS_VHT_MCS) {
		STATS_OP_FMT(SUCC).vht[0][mcs] += peer_stats->succ_bytes;
		STATS_OP_FMT(SUCC).vht[1][mcs] += peer_stats->succ_pkts;
		STATS_OP_FMT(FAIL).vht[0][mcs] += peer_stats->failed_bytes;
		STATS_OP_FMT(FAIL).vht[1][mcs] += peer_stats->failed_pkts;
		STATS_OP_FMT(RETRY).vht[0][mcs] += peer_stats->retry_bytes;
		STATS_OP_FMT(RETRY).vht[1][mcs] += peer_stats->retry_pkts;
	} else if (txrate->flags & RATE_INFO_FLAGS_MCS) {
		STATS_OP_FMT(SUCC).ht[0][mcs] += peer_stats->succ_bytes;
		STATS_OP_FMT(SUCC).ht[1][mcs] += peer_stats->succ_pkts;
		STATS_OP_FMT(FAIL).ht[0][mcs] += peer_stats->failed_bytes;
		STATS_OP_FMT(FAIL).ht[1][mcs] += peer_stats->failed_pkts;
		STATS_OP_FMT(RETRY).ht[0][mcs] += peer_stats->retry_bytes;
		STATS_OP_FMT(RETRY).ht[1][mcs] += peer_stats->retry_pkts;
	} else {
		mcs = legacy_rate_idx;

		STATS_OP_FMT(SUCC).legacy[0][mcs] += peer_stats->succ_bytes;
		STATS_OP_FMT(SUCC).legacy[1][mcs] += peer_stats->succ_pkts;
		STATS_OP_FMT(FAIL).legacy[0][mcs] += peer_stats->failed_bytes;
		STATS_OP_FMT(FAIL).legacy[1][mcs] += peer_stats->failed_pkts;
		STATS_OP_FMT(RETRY).legacy[0][mcs] += peer_stats->retry_bytes;
		STATS_OP_FMT(RETRY).legacy[1][mcs] += peer_stats->retry_pkts;
	}

	ppdu_type = peer_stats->ppdu_type;
	if ((ppdu_type == HTT_PPDU_STATS_PPDU_TYPE_MU_OFDMA ||
	     ppdu_type == HTT_PPDU_STATS_PPDU_TYPE_MU_MIMO_OFDMA) &&
	     (txrate->flags & RATE_INFO_FLAGS_HE_MCS)) {
		ru_type = peer_stats->ru_tones;

		if (ru_type <= NL80211_RATE_INFO_HE_RU_ALLOC_996) {
			STATS_OP_FMT(SUCC).ru_loc[0][ru_type] += peer_stats->succ_bytes;
			STATS_OP_FMT(SUCC).ru_loc[1][ru_type] += peer_stats->succ_pkts;
			STATS_OP_FMT(FAIL).ru_loc[0][ru_type] += peer_stats->failed_bytes;
			STATS_OP_FMT(FAIL).ru_loc[1][ru_type] += peer_stats->failed_pkts;
			STATS_OP_FMT(RETRY).ru_loc[0][ru_type] += peer_stats->retry_bytes;
			STATS_OP_FMT(RETRY).ru_loc[1][ru_type] += peer_stats->retry_pkts;
			if (peer_stats->is_ampdu) {
				STATS_OP_FMT(AMPDU).ru_loc[0][ru_type] +=
					peer_stats->succ_bytes + peer_stats->retry_bytes;
				STATS_OP_FMT(AMPDU).ru_loc[1][ru_type] +=
					peer_stats->succ_pkts + peer_stats->retry_pkts;
			}
		}
	}

	if (ppdu_type < HTT_PPDU_STATS_PPDU_TYPE_MAX) {
		STATS_OP_FMT(SUCC).transmit_type[0][ppdu_type] += peer_stats->succ_bytes;
		STATS_OP_FMT(SUCC).transmit_type[1][ppdu_type] += peer_stats->succ_pkts;
		STATS_OP_FMT(FAIL).transmit_type[0][ppdu_type] +=
							peer_stats->failed_bytes;
		STATS_OP_FMT(FAIL).transmit_type[1][ppdu_type] += peer_stats->failed_pkts;
		STATS_OP_FMT(RETRY).transmit_type[0][ppdu_type] +=
							peer_stats->retry_bytes;
		STATS_OP_FMT(RETRY).transmit_type[1][ppdu_type] += peer_stats->retry_pkts;
		if (peer_stats->is_ampdu) {
			STATS_OP_FMT(AMPDU).transmit_type[0][ppdu_type] +=
				peer_stats->succ_bytes + peer_stats->retry_bytes;
			STATS_OP_FMT(AMPDU).transmit_type[1][ppdu_type] +=
				peer_stats->succ_pkts + peer_stats->retry_pkts;
		}
	}

	if (peer_stats->is_ampdu) {
		tx_stats->ba_fails += peer_stats->ba_fails;

		if (txrate->flags & RATE_INFO_FLAGS_HE_MCS) {
			STATS_OP_FMT(AMPDU).he[0][mcs] +=
			peer_stats->succ_bytes + peer_stats->retry_bytes;
			STATS_OP_FMT(AMPDU).he[1][mcs] +=
			peer_stats->succ_pkts + peer_stats->retry_pkts;
		} else if (txrate->flags & RATE_INFO_FLAGS_MCS) {
			STATS_OP_FMT(AMPDU).ht[0][mcs] +=
			peer_stats->succ_bytes + peer_stats->retry_bytes;
			STATS_OP_FMT(AMPDU).ht[1][mcs] +=
			peer_stats->succ_pkts + peer_stats->retry_pkts;
		} else {
			STATS_OP_FMT(AMPDU).vht[0][mcs] +=
			peer_stats->succ_bytes + peer_stats->retry_bytes;
			STATS_OP_FMT(AMPDU).vht[1][mcs] +=
			peer_stats->succ_pkts + peer_stats->retry_pkts;
		}
		STATS_OP_FMT(AMPDU).bw[0][bw] +=
			peer_stats->succ_bytes + peer_stats->retry_bytes;
		STATS_OP_FMT(AMPDU).nss[0][nss] +=
			peer_stats->succ_bytes + peer_stats->retry_bytes;
		STATS_OP_FMT(AMPDU).gi[0][gi] +=
			peer_stats->succ_bytes + peer_stats->retry_bytes;
		STATS_OP_FMT(AMPDU).bw[1][bw] +=
			peer_stats->succ_pkts + peer_stats->retry_pkts;
		STATS_OP_FMT(AMPDU).nss[1][nss] +=
			peer_stats->succ_pkts + peer_stats->retry_pkts;
		STATS_OP_FMT(AMPDU).gi[1][gi] +=
			peer_stats->succ_pkts + peer_stats->retry_pkts;
	} else {
		tx_stats->ack_fails += peer_stats->ba_fails;
	}

	STATS_OP_FMT(SUCC).bw[0][bw] += peer_stats->succ_bytes;
	STATS_OP_FMT(SUCC).nss[0][nss] += peer_stats->succ_bytes;
	STATS_OP_FMT(SUCC).gi[0][gi] += peer_stats->succ_bytes;

	STATS_OP_FMT(SUCC).bw[1][bw] += peer_stats->succ_pkts;
	STATS_OP_FMT(SUCC).nss[1][nss] += peer_stats->succ_pkts;
	STATS_OP_FMT(SUCC).gi[1][gi] += peer_stats->succ_pkts;

	STATS_OP_FMT(FAIL).bw[0][bw] += peer_stats->failed_bytes;
	STATS_OP_FMT(FAIL).nss[0][nss] += peer_stats->failed_bytes;
	STATS_OP_FMT(FAIL).gi[0][gi] += peer_stats->failed_bytes;

	STATS_OP_FMT(FAIL).bw[1][bw] += peer_stats->failed_pkts;
	STATS_OP_FMT(FAIL).nss[1][nss] += peer_stats->failed_pkts;
	STATS_OP_FMT(FAIL).gi[1][gi] += peer_stats->failed_pkts;

	STATS_OP_FMT(RETRY).bw[0][bw] += peer_stats->retry_bytes;
	STATS_OP_FMT(RETRY).nss[0][nss] += peer_stats->retry_bytes;
	STATS_OP_FMT(RETRY).gi[0][gi] += peer_stats->retry_bytes;

	STATS_OP_FMT(RETRY).bw[1][bw] += peer_stats->retry_pkts;
	STATS_OP_FMT(RETRY).nss[1][nss] += peer_stats->retry_pkts;
	STATS_OP_FMT(RETRY).gi[1][gi] += peer_stats->retry_pkts;

	tx_stats->tx_duration += peer_stats->duration;

	tx_stats->ru_start = peer_stats->ru_start;
	tx_stats->ru_tones = peer_stats->ru_tones;

	if (peer_stats->mu_grpid <= MAX_MU_GROUP_ID &&
	    peer_stats->ppdu_type != HTT_PPDU_STATS_PPDU_TYPE_SU) {
		if (peer_stats->mu_grpid & (MAX_MU_GROUP_ID - 1))
			tx_stats->mu_group[peer_stats->mu_grpid] =
						(peer_stats->mu_pos + 1);
	}
}

void ath12k_debugfs_sta_update_txcompl(struct ath12k *ar,
				       struct sk_buff *msdu,
				       struct hal_tx_status *ts)
{
	struct ath12k_base *ab = ar->ab;
	struct ath12k_per_peer_tx_stats *peer_stats = &ar->cached_stats;
	enum hal_tx_rate_stats_pkt_type pkt_type;
	enum hal_tx_rate_stats_sgi sgi;
	enum hal_tx_rate_stats_bw bw;
	struct ath12k_peer *peer;
	struct ath12k_sta *arsta;
	struct ieee80211_sta *sta;
	u16 num_tones_in_ru;
	u16 rate;
	u8 rate_idx = 0;
	int ret;
	u8 mcs;

	rcu_read_lock();
	spin_lock_bh(&ab->base_lock);
	peer = ath12k_peer_find_by_id(ab, ts->peer_id);
	if (!peer || !peer->sta) {
		ath12k_warn(ab, "failed to find the peer\n");
		spin_unlock_bh(&ab->base_lock);
		rcu_read_unlock();
		return;
	}

	sta = peer->sta;
	arsta = (struct ath12k_sta *)sta->drv_priv;

	memset(&arsta->txrate, 0, sizeof(arsta->txrate));
	pkt_type = FIELD_GET(HAL_TX_RATE_STATS_INFO0_PKT_TYPE,
			     ts->rate_stats);
	mcs = FIELD_GET(HAL_TX_RATE_STATS_INFO0_MCS,
			ts->rate_stats);
	sgi = FIELD_GET(HAL_TX_RATE_STATS_INFO0_SGI,
			ts->rate_stats);
	bw = FIELD_GET(HAL_TX_RATE_STATS_INFO0_BW, ts->rate_stats);
	num_tones_in_ru = FIELD_GET(HAL_TX_RATE_STATS_INFO0_TONES_IN_RU,
				    ts->rate_stats);

	if (pkt_type == HAL_TX_RATE_STATS_PKT_TYPE_11A ||
	    pkt_type == HAL_TX_RATE_STATS_PKT_TYPE_11B) {
		ret = ath12k_mac_hw_ratecode_to_legacy_rate(mcs,
							    pkt_type,
							    &rate_idx,
							    &rate);
		if (ret < 0)
			goto err_out;
		arsta->txrate.legacy = rate;
	} else if (pkt_type == HAL_TX_RATE_STATS_PKT_TYPE_11N) {
		if (mcs > 7) {
			ath12k_warn(ab, "Invalid HT mcs index %d\n", mcs);
			goto err_out;
		}

		arsta->txrate.mcs = mcs + 8 * (arsta->last_txrate.nss - 1);
		arsta->txrate.flags = RATE_INFO_FLAGS_MCS;
		if (sgi)
			arsta->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
	} else if (pkt_type == HAL_TX_RATE_STATS_PKT_TYPE_11AC) {
		if (mcs > 9) {
			ath12k_warn(ab, "Invalid VHT mcs index %d\n", mcs);
			goto err_out;
		}

		arsta->txrate.mcs = mcs;
		arsta->txrate.flags = RATE_INFO_FLAGS_VHT_MCS;
		if (sgi)
			arsta->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
	} else if (pkt_type == HAL_TX_RATE_STATS_PKT_TYPE_11AX) {
		arsta->txrate.mcs = mcs;
		arsta->txrate.flags = RATE_INFO_FLAGS_HE_MCS;
		arsta->txrate.he_gi = ath12k_he_gi_to_nl80211_he_gi(sgi);
		arsta->txrate.he_ru_alloc =
			ath12k_he_ru_tones_to_nl80211_he_ru_alloc(num_tones_in_ru);
	}

	arsta->txrate.nss = arsta->last_txrate.nss;
	arsta->txrate.bw = ath12k_mac_bw_to_mac80211_bw(bw);

	/* Currently only OFDMA flag is available in tx complettion status
	 *  to indicate MUOFDMA ppdu type. Use SU ppdu type as of now to
	 * indicate both SU/MU MIMO for failed/retry count.
	 */
	if (ts->flags & HAL_TX_STATUS_FLAGS_OFDMA)
		peer_stats->ppdu_type = HTT_PPDU_STATS_PPDU_TYPE_MU_OFDMA;
	else
		peer_stats->ppdu_type = HTT_PPDU_STATS_PPDU_TYPE_SU;

	peer_stats->ru_tones = arsta->txrate.he_ru_alloc;

	ath12k_debugfs_sta_add_tx_stats(arsta, peer_stats, rate_idx);

err_out:
	spin_unlock_bh(&ab->base_lock);
	rcu_read_unlock();
}

static ssize_t ath12k_dbg_sta_dump_tx_stats(struct file *file,
					    char __user *user_buf,
					    size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	struct ath12k_htt_data_stats *stats;
	static const char *str_name[ATH12K_STATS_TYPE_MAX] = {"success", "fail",
							      "retry", "ampdu"};
	static const char *str[ATH12K_COUNTER_TYPE_MAX] = {"bytes", "packets"};
	int len = 0, i, j, k, retval = 0;
	const int size = 2 * 4096;
	char *buf, mu_group_id[MAX_MU_GROUP_LENGTH] = {0};
	u32 index;
	static const char *fields[HAL_WBM_REL_HTT_TX_COMP_STATUS_MAX] = {
			 [HAL_WBM_REL_HTT_TX_COMP_STATUS_OK] = "Acked pkt count",
			 [HAL_WBM_REL_HTT_TX_COMP_STATUS_TTL] = "Status ttl pkt count",
			 [HAL_WBM_REL_HTT_TX_COMP_STATUS_DROP] = "Dropped pkt count",
			 [HAL_WBM_REL_HTT_TX_COMP_STATUS_REINJ] = "Reinj pkt count",
			 [HAL_WBM_REL_HTT_TX_COMP_STATUS_INSPECT] = "Inspect pkt count",
			 [HAL_WBM_REL_HTT_TX_COMP_STATUS_MEC_NOTIFY] =
								"MEC notify pkt count"
			};
	int idx;

	if (!arsta->tx_stats || !arsta->wbm_tx_stats)
		return -ENOENT;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&ar->conf_mutex);

	spin_lock_bh(&ar->data_lock);
	for (k = 0; k < ATH12K_STATS_TYPE_MAX; k++) {
		for (j = 0; j < ATH12K_COUNTER_TYPE_MAX; j++) {
			stats = &arsta->tx_stats->stats[k];
			len += scnprintf(buf + len, size - len, "%s_%s\n",
					 str_name[k],
					 str[j]);
			len += scnprintf(buf + len, size - len, "==========\n");
			len += scnprintf(buf + len, size - len,
					 " HE MCS %s\n\t",
					 str[j]);
			for (i = 0; i < ATH12K_HE_MCS_NUM; i++)
				len += scnprintf(buf + len, size - len,
						 "%llu ",
						 stats->he[j][i]);
			len += scnprintf(buf + len, size - len, "\n");
			len += scnprintf(buf + len, size - len,
					 " VHT MCS %s\n\t",
					 str[j]);
			for (i = 0; i < ATH12K_VHT_MCS_NUM; i++)
				len += scnprintf(buf + len, size - len,
						 "%llu ",
						 stats->vht[j][i]);
			len += scnprintf(buf + len, size - len, "\n");
			len += scnprintf(buf + len, size - len, " HT MCS %s\n\t",
					 str[j]);
			for (i = 0; i < ATH12K_HT_MCS_NUM; i++)
				len += scnprintf(buf + len, size - len,
						 "%llu ", stats->ht[j][i]);
			len += scnprintf(buf + len, size - len, "\n");
			len += scnprintf(buf + len, size - len,
					 " BW %s (20,40,80,160,320 MHz)\n", str[j]);
			len += scnprintf(buf + len, size - len,
					 "\t%llu %llu %llu %llu %llu\n",
					 stats->bw[j][0], stats->bw[j][1],
					 stats->bw[j][2], stats->bw[j][3],
					 stats->bw[j][4]);
			len += scnprintf(buf + len, size - len,
					 " NSS %s (1x1,2x2,3x3,4x4)\n", str[j]);
			len += scnprintf(buf + len, size - len,
					 "\t%llu %llu %llu %llu\n",
					 stats->nss[j][0], stats->nss[j][1],
					 stats->nss[j][2], stats->nss[j][3]);
			len += scnprintf(buf + len, size - len,
					 " GI %s (0.4us,0.8us,1.6us,3.2us)\n",
					 str[j]);
			len += scnprintf(buf + len, size - len,
					 "\t%llu %llu %llu %llu\n",
					 stats->gi[j][0], stats->gi[j][1],
					 stats->gi[j][2], stats->gi[j][3]);
			len += scnprintf(buf + len, size - len,
					 " legacy rate %s (1,2 ... Mbps)\n  ",
					 str[j]);
			for (i = 0; i < ATH12K_LEGACY_NUM; i++)
				len += scnprintf(buf + len, size - len, "%llu ",
						 stats->legacy[j][i]);

			len += scnprintf(buf + len, size - len, "\n ru %s:\n", str[j]);
			len += scnprintf(buf + len, size - len,
					 "\tru 26: %llu\n", stats->ru_loc[j][0]);
			len += scnprintf(buf + len, size - len,
					 "\tru 52: %llu\n", stats->ru_loc[j][1]);
			len += scnprintf(buf + len, size - len,
					 "\tru 106: %llu\n", stats->ru_loc[j][2]);
			len += scnprintf(buf + len, size - len,
					 "\tru 242: %llu\n", stats->ru_loc[j][3]);
			len += scnprintf(buf + len, size - len,
					 "\tru 484: %llu\n", stats->ru_loc[j][4]);
			len += scnprintf(buf + len, size - len,
					 "\tru 996: %llu\n", stats->ru_loc[j][5]);

			len += scnprintf(buf + len, size - len,
					 " ppdu type %s:\n", str[j]);
			if (k == ATH12K_STATS_TYPE_FAIL ||
			    k == ATH12K_STATS_TYPE_RETRY) {
				len += scnprintf(buf + len, size - len,
						 "\tSU/MIMO: %llu\n",
						 stats->transmit_type[j][0]);
				len += scnprintf(buf + len, size - len,
						 "\tOFDMA/OFDMA_MIMO: %llu\n",
						 stats->transmit_type[j][2]);
			} else {
				len += scnprintf(buf + len, size - len,
						 "\tSU: %llu\n",
						 stats->transmit_type[j][0]);
				len += scnprintf(buf + len, size - len,
						 "\tMIMO: %llu\n",
						 stats->transmit_type[j][1]);
				len += scnprintf(buf + len, size - len,
						 "\tOFDMA: %llu\n",
						 stats->transmit_type[j][2]);
				len += scnprintf(buf + len, size - len,
						 "\tOFDMA_MIMO: %llu\n",
						 stats->transmit_type[j][3]);
			}
		}
	}

	len += scnprintf(buf + len, size - len, "\n");

	for (i = 0; i < MAX_MU_GROUP_ID;) {
		index = 0;
		for (j = 0; j < MAX_MU_GROUP_SHOW && i < MAX_MU_GROUP_ID; j++) {
			index += snprintf(&mu_group_id[index],
					  MAX_MU_GROUP_LENGTH - index,
					  " %d",
					  arsta->tx_stats->mu_group[i]);
			i++;
		}
		len += scnprintf(buf + len, size - len,
				 "User position list for GID %02d->%d: [%s]\n",
				 i - MAX_MU_GROUP_SHOW, i - 1, mu_group_id);
	}
	len += scnprintf(buf + len, size - len,
			 "\nLast Packet RU index [%d], Size [%d]\n",
			 arsta->tx_stats->ru_start, arsta->tx_stats->ru_tones);

	len += scnprintf(buf + len, size - len,
			 "\nTX duration\n %llu usecs\n",
			 arsta->tx_stats->tx_duration);
	len += scnprintf(buf + len, size - len,
			 "BA fails\n %llu\n", arsta->tx_stats->ba_fails);
	len += scnprintf(buf + len, size - len,
			 "ack fails\n %llu\n\n", arsta->tx_stats->ack_fails);

	len += scnprintf(buf + len, size - len,
			 "WBM tx completion stats of data pkts :\n");

	for (idx = 0; idx <= HAL_WBM_REL_HTT_TX_COMP_STATUS_MEC_NOTIFY; idx++) {
		len += scnprintf(buf + len, size - len,
				 "%-23s :  %llu\n",
				 fields[idx],
				 arsta->wbm_tx_stats->wbm_tx_comp_stats[idx]);
	}

	spin_unlock_bh(&ar->data_lock);

	if (len > size)
		len = size;
	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	mutex_unlock(&ar->conf_mutex);
	return retval;
}

static const struct file_operations fops_tx_stats = {
	.read = ath12k_dbg_sta_dump_tx_stats,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath12k_dbg_sta_dump_rx_stats(struct file *file,
					    char __user *user_buf,
					    size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	struct ath12k_rx_peer_stats *rx_stats = arsta->rx_stats;
	int len = 0, i, retval = 0;
	const int size = 4 * 4096;
	char *buf;
	int he_rates_avail;
	int rate_table_len;
	static const char *legacy_rate_str[HAL_RX_MAX_NUM_LEGACY_RATES] = {
					"1Mbps", "2Mbps", "5.5Mbps", "6Mbps",
					"9Mbps", "11Mbps", "12Mbps", "18Mbps",
					"24Mbps", "36 Mbps", "48Mbps", "54Mbps"};
	if (!rx_stats)
		return -ENOENT;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	he_rates_avail = (rx_stats->pream_cnt[HAL_RX_PREAMBLE_11AX] > 1) ? 1 : 0;
	rate_table_len = he_rates_avail ? ATH12K_RX_RATE_TABLE_11AX_NUM :
					      ATH12K_RX_RATE_TABLE_NUM;
	mutex_lock(&ar->conf_mutex);
	spin_lock_bh(&ar->ab->base_lock);

	len += scnprintf(buf + len, size - len, "RX peer stats:\n");
	len += scnprintf(buf + len, size - len, "Num of MSDUs: %llu\n",
			 rx_stats->num_msdu);
	len += scnprintf(buf + len, size - len, "Num of MSDUs with TCP L4: %llu\n",
			 rx_stats->tcp_msdu_count);
	len += scnprintf(buf + len, size - len, "Num of MSDUs with UDP L4: %llu\n",
			 rx_stats->udp_msdu_count);
	len += scnprintf(buf + len, size - len, "Num of MSDUs part of AMPDU: %llu\n",
			 rx_stats->ampdu_msdu_count);
	len += scnprintf(buf + len, size - len, "Num of MSDUs not part of AMPDU: %llu\n",
			 rx_stats->non_ampdu_msdu_count);
	len += scnprintf(buf + len, size - len, "Num of MSDUs using STBC: %llu\n",
			 rx_stats->stbc_count);
	len += scnprintf(buf + len, size - len, "Num of MSDUs beamformed: %llu\n",
			 rx_stats->beamformed_count);
	len += scnprintf(buf + len, size - len, "Num of MPDUs with FCS ok: %llu\n",
			 rx_stats->num_mpdu_fcs_ok);
	len += scnprintf(buf + len, size - len, "Num of MPDUs with FCS error: %llu\n",
			 rx_stats->num_mpdu_fcs_err);
	len += scnprintf(buf + len, size - len,
			 "preamble: 11A %llu 11B %llu 11N %llu 11AC %llu 11AX %llu\n",
			 rx_stats->pream_cnt[0], rx_stats->pream_cnt[1],
			 rx_stats->pream_cnt[2], rx_stats->pream_cnt[3],
			 rx_stats->pream_cnt[4]);
	len += scnprintf(buf + len, size - len,
			 "reception type: SU %llu MU_MIMO %llu MU_OFDMA %llu MU_OFDMA_MIMO %llu\n",
			 rx_stats->reception_type[0], rx_stats->reception_type[1],
			 rx_stats->reception_type[2], rx_stats->reception_type[3]);
	len += scnprintf(buf + len, size - len, "TID(0-15) Legacy TID(16):");
	for (i = 0; i <= IEEE80211_NUM_TIDS; i++)
		len += scnprintf(buf + len, size - len, "%llu ", rx_stats->tid_count[i]);
	len += scnprintf(buf + len, size - len, "\nRX Duration:%llu\n",
			 rx_stats->rx_duration);

	len += scnprintf(buf + len, size - len, "\nRX success packet stats:\n");
	len += scnprintf(buf + len, size - len, "\nHE packet stats:\n");
	for (i = 0; i <= HAL_RX_MAX_MCS_HE; i++)
		len += scnprintf(buf + len, size - len, "MCS %d: %llu%s", i,
				 rx_stats->pkt_stats.he_mcs_count[i],
				 (i + 1) % 6 ? "\t" : "\n");
	len += scnprintf(buf + len, size - len, "\nVHT packet stats:\n");
	for (i = 0; i <= HAL_RX_MAX_MCS_VHT; i++)
		len += scnprintf(buf + len, size - len, "MCS %d: %llu%s", i,
				 rx_stats->pkt_stats.vht_mcs_count[i],
				 (i + 1) % 5 ? "\t" : "\n");
	len += scnprintf(buf + len, size - len, "\nHT packet stats:\n");
	for (i = 0; i <= HAL_RX_MAX_MCS_HT; i++)
		len += scnprintf(buf + len, size - len, "MCS %d: %llu%s", i,
				 rx_stats->pkt_stats.ht_mcs_count[i],
				 (i + 1) % 8 ? "\t" : "\n");
	len += scnprintf(buf + len, size - len, "\nLegacy rate packet stats:\n");
	for (i = 0; i < HAL_RX_MAX_NUM_LEGACY_RATES; i++)
		len += scnprintf(buf + len, size - len, "%s: %llu%s", legacy_rate_str[i],
				 rx_stats->pkt_stats.legacy_count[i],
				 (i + 1) % 4 ? "\t" : "\n");
	len += scnprintf(buf + len, size - len, "\nNSS packet stats:\n");
	for (i = 0; i < HAL_RX_MAX_NSS; i++)
		len += scnprintf(buf + len, size - len, "%dx%d: %llu ", i + 1, i + 1,
				 rx_stats->pkt_stats.nss_count[i]);
	len += scnprintf(buf + len, size - len,
			 "\n\nGI: 0.8us %llu 0.4us %llu 1.6us %llu 3.2us %llu\n",
			 rx_stats->pkt_stats.gi_count[0],
			 rx_stats->pkt_stats.gi_count[1],
			 rx_stats->pkt_stats.gi_count[2],
			 rx_stats->pkt_stats.gi_count[3]);
	len += scnprintf(buf + len, size - len,
			 "BW: 20Mhz %llu 40Mhz %llu 80Mhz %llu 160Mhz %llu 320Mhz %llu\n",
			 rx_stats->pkt_stats.bw_count[0],
			 rx_stats->pkt_stats.bw_count[1],
			 rx_stats->pkt_stats.bw_count[2],
			 rx_stats->pkt_stats.bw_count[3],
			 rx_stats->pkt_stats.bw_count[4]);
	len += scnprintf(buf + len, size - len, "\nRate Table (packets):\n");
	for (i = 0; i < rate_table_len; i++)
		len += scnprintf(buf + len, size - len, "%10llu%s",
				rx_stats->pkt_stats.rx_rate[i],
				(i + 1) % (he_rates_avail ? 12 : 8) ? "\t" : "\n");

	len += scnprintf(buf + len, size - len, "\nRX success byte stats:\n");
	len += scnprintf(buf + len, size - len, "\nHE byte stats:\n");
	for (i = 0; i <= HAL_RX_MAX_MCS_HE; i++)
		len += scnprintf(buf + len, size - len, "MCS %d: %llu%s", i,
				 rx_stats->byte_stats.he_mcs_count[i],
				 (i + 1) % 6 ? "\t" : "\n");

	len += scnprintf(buf + len, size - len, "\nVHT byte stats:\n");
	for (i = 0; i <= HAL_RX_MAX_MCS_VHT; i++)
		len += scnprintf(buf + len, size - len, "MCS %d: %llu%s", i,
				 rx_stats->byte_stats.vht_mcs_count[i],
				 (i + 1) % 5 ? "\t" : "\n");
	len += scnprintf(buf + len, size - len, "\nHT byte stats:\n");
	for (i = 0; i <= HAL_RX_MAX_MCS_HT; i++)
		len += scnprintf(buf + len, size - len, "MCS %d: %llu%s", i,
				 rx_stats->byte_stats.ht_mcs_count[i],
				 (i + 1) % 8 ? "\t" : "\n");
	len += scnprintf(buf + len, size - len, "\nLegacy rate byte stats:\n");
	for (i = 0; i < HAL_RX_MAX_NUM_LEGACY_RATES; i++)
		len += scnprintf(buf + len, size - len, "%s: %llu%s", legacy_rate_str[i],
				 rx_stats->byte_stats.legacy_count[i],
				 (i + 1) % 4 ? "\t" : "\n");
	len += scnprintf(buf + len, size - len, "\nNSS byte stats:\n");
	for (i = 0; i < HAL_RX_MAX_NSS; i++)
		len += scnprintf(buf + len, size - len, "%dx%d: %llu ", i + 1, i + 1,
				 rx_stats->byte_stats.nss_count[i]);
	len += scnprintf(buf + len, size - len,
			 "\n\nGI: 0.8us %llu 0.4us %llu 1.6us %llu 3.2us %llu\n",
			 rx_stats->byte_stats.gi_count[0],
			 rx_stats->byte_stats.gi_count[1],
			 rx_stats->byte_stats.gi_count[2],
			 rx_stats->byte_stats.gi_count[3]);
	len += scnprintf(buf + len, size - len,
			 "BW: 20Mhz %llu 40Mhz %llu 80Mhz %llu 160Mhz %llu 320Mhz %llu\n",
			 rx_stats->byte_stats.bw_count[0],
			 rx_stats->byte_stats.bw_count[1],
			 rx_stats->byte_stats.bw_count[2],
			 rx_stats->byte_stats.bw_count[3],
			 rx_stats->byte_stats.bw_count[4]);
	len += scnprintf(buf + len, size - len, "\nRate Table (bytes):\n");
	for (i = 0; i < rate_table_len; i++)
		len += scnprintf(buf + len, size - len, "%10llu%s",
				rx_stats->byte_stats.rx_rate[i],
				(i + 1) % (he_rates_avail ? 12 : 8) ? "\t" : "\n");
	len += scnprintf(buf + len, size - len,
			 "\nDCM: %llu\nRU26:  %llu\nRU52:  %llu\nRU106: %llu\nRU242: %llu\nRU484: %llu\nRU996: %llu\n",
			 rx_stats->dcm_count, rx_stats->ru_alloc_cnt[0],
			 rx_stats->ru_alloc_cnt[1], rx_stats->ru_alloc_cnt[2],
			 rx_stats->ru_alloc_cnt[3], rx_stats->ru_alloc_cnt[4],
			 rx_stats->ru_alloc_cnt[5]);

	len += scnprintf(buf + len, size - len, "\n");

	spin_unlock_bh(&ar->ab->base_lock);

	if (len > size)
		len = size;
	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	mutex_unlock(&ar->conf_mutex);
	return retval;
}

static const struct file_operations fops_rx_stats = {
	.read = ath12k_dbg_sta_dump_rx_stats,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int
ath12k_dbg_sta_open_htt_peer_stats(struct inode *inode, struct file *file)
{
	struct ieee80211_sta *sta = inode->i_private;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	struct debug_htt_stats_req *stats_req;
	int ret;

	stats_req = vzalloc(sizeof(*stats_req) + ATH12K_HTT_STATS_BUF_SIZE);
	if (!stats_req)
		return -ENOMEM;

	mutex_lock(&ar->conf_mutex);
	ar->debug.htt_stats.stats_req = stats_req;
	stats_req->type = ATH12K_DBG_HTT_EXT_STATS_PEER_INFO;
	memcpy(stats_req->peer_addr, sta->addr, ETH_ALEN);
	ret = ath12k_debugfs_htt_stats_req(ar);
	mutex_unlock(&ar->conf_mutex);
	if (ret < 0)
		goto out;

	file->private_data = stats_req;
	return 0;
out:
	vfree(stats_req);
	ar->debug.htt_stats.stats_req = NULL;
	return ret;
}

static int
ath12k_dbg_sta_release_htt_peer_stats(struct inode *inode, struct file *file)
{
	struct ieee80211_sta *sta = inode->i_private;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;

	mutex_lock(&ar->conf_mutex);
	vfree(file->private_data);
	ar->debug.htt_stats.stats_req = NULL;
	mutex_unlock(&ar->conf_mutex);

	return 0;
}

static ssize_t ath12k_dbg_sta_read_htt_peer_stats(struct file *file,
						  char __user *user_buf,
						  size_t count, loff_t *ppos)
{
	struct debug_htt_stats_req *stats_req = file->private_data;
	char *buf;
	u32 length = 0;

	buf = stats_req->buf;
	length = min_t(u32, stats_req->buf_len, ATH12K_HTT_STATS_BUF_SIZE);
	return simple_read_from_buffer(user_buf, count, ppos, buf, length);
}

static const struct file_operations fops_htt_peer_stats = {
	.open = ath12k_dbg_sta_open_htt_peer_stats,
	.release = ath12k_dbg_sta_release_htt_peer_stats,
	.read = ath12k_dbg_sta_read_htt_peer_stats,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath12k_dbg_sta_write_peer_pktlog(struct file *file,
						const char __user *buf,
						size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	int ret, enable;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH12K_STATE_ON) {
		ret = -ENETDOWN;
		goto out;
	}

	ret = kstrtoint_from_user(buf, count, 0, &enable);
	if (ret)
		goto out;

	ar->debug.pktlog_peer_valid = enable;
	memcpy(ar->debug.pktlog_peer_addr, sta->addr, ETH_ALEN);

	/* Send peer based pktlog enable/disable */
	ret = ath12k_wmi_pdev_peer_pktlog_filter(ar, sta->addr, enable);
	if (ret) {
		ath12k_warn(ar->ab, "failed to set peer pktlog filter %pM: %d\n",
			    sta->addr, ret);
		goto out;
	}

	ath12k_dbg(ar->ab, ATH12K_DBG_WMI, "peer pktlog filter set to %d\n",
		   enable);
	ret = count;

out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static ssize_t ath12k_dbg_sta_read_peer_pktlog(struct file *file,
					       char __user *ubuf,
					       size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	char buf[32] = {0};
	int len;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf), "%08x %pM\n",
			ar->debug.pktlog_peer_valid,
			ar->debug.pktlog_peer_addr);
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_peer_pktlog = {
	.write = ath12k_dbg_sta_write_peer_pktlog,
	.read = ath12k_dbg_sta_read_peer_pktlog,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath12k_dbg_sta_write_delba(struct file *file,
					  const char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	u32 tid, initiator, reason;
	int ret;
	char buf[64] = {0};

	ret = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos,
				     user_buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(buf, "%u %u %u", &tid, &initiator, &reason);
	if (ret != 3)
		return -EINVAL;

	/* Valid TID values are 0 through 15 */
	if (tid > HAL_DESC_REO_NON_QOS_TID - 1)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	if (ar->state != ATH12K_STATE_ON ||
	    arsta->aggr_mode != ATH12K_DBG_AGGR_MODE_MANUAL) {
		ret = count;
		goto out;
	}

	ret = ath12k_wmi_delba_send(ar, arsta->arvif->vdev_id, sta->addr,
				    tid, initiator, reason);
	if (ret) {
		ath12k_warn(ar->ab, "failed to send delba: vdev_id %u peer %pM tid %u initiator %u reason %u\n",
			    arsta->arvif->vdev_id, sta->addr, tid, initiator,
			    reason);
	}
	ret = count;
out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_delba = {
	.write = ath12k_dbg_sta_write_delba,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath12k_dbg_sta_write_addba_resp(struct file *file,
					       const char __user *user_buf,
					       size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	u32 tid, status;
	int ret;
	char buf[64] = {0};

	ret = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos,
				     user_buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(buf, "%u %u", &tid, &status);
	if (ret != 2)
		return -EINVAL;

	/* Valid TID values are 0 through 15 */
	if (tid > HAL_DESC_REO_NON_QOS_TID - 1)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	if (ar->state != ATH12K_STATE_ON ||
	    arsta->aggr_mode != ATH12K_DBG_AGGR_MODE_MANUAL) {
		ret = count;
		goto out;
	}

	ret = ath12k_wmi_addba_set_resp(ar, arsta->arvif->vdev_id, sta->addr,
					tid, status);
	if (ret) {
		ath12k_warn(ar->ab, "failed to send addba response: vdev_id %u peer %pM tid %u status%u\n",
			    arsta->arvif->vdev_id, sta->addr, tid, status);
	}
	ret = count;
out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_addba_resp = {
	.write = ath12k_dbg_sta_write_addba_resp,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath12k_dbg_sta_write_addba(struct file *file,
					  const char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	u32 tid, buf_size;
	int ret;
	char buf[64] = {0};

	ret = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos,
				     user_buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(buf, "%u %u", &tid, &buf_size);
	if (ret != 2)
		return -EINVAL;

	/* Valid TID values are 0 through 15 */
	if (tid > HAL_DESC_REO_NON_QOS_TID - 1)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	if (ar->state != ATH12K_STATE_ON ||
	    arsta->aggr_mode != ATH12K_DBG_AGGR_MODE_MANUAL) {
		ret = count;
		goto out;
	}

	ret = ath12k_wmi_addba_send(ar, arsta->arvif->vdev_id, sta->addr,
				    tid, buf_size);
	if (ret) {
		ath12k_warn(ar->ab, "failed to send addba request: vdev_id %u peer %pM tid %u buf_size %u\n",
			    arsta->arvif->vdev_id, sta->addr, tid, buf_size);
	}

	ret = count;
out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_addba = {
	.write = ath12k_dbg_sta_write_addba,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath12k_dbg_sta_read_aggr_mode(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	char buf[64];
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len,
			"aggregation mode: %s\n\n%s\n%s\n",
			(arsta->aggr_mode == ATH12K_DBG_AGGR_MODE_AUTO) ?
			"auto" : "manual", "auto = 0", "manual = 1");
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath12k_dbg_sta_write_aggr_mode(struct file *file,
					      const char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	u32 aggr_mode;
	int ret;

	if (kstrtouint_from_user(user_buf, count, 0, &aggr_mode))
		return -EINVAL;

	if (aggr_mode >= ATH12K_DBG_AGGR_MODE_MAX)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	if (ar->state != ATH12K_STATE_ON ||
	    aggr_mode == arsta->aggr_mode) {
		ret = count;
		goto out;
	}

	ret = ath12k_wmi_addba_clear_resp(ar, arsta->arvif->vdev_id, sta->addr);
	if (ret) {
		ath12k_warn(ar->ab, "failed to clear addba session ret: %d\n",
			    ret);
		goto out;
	}

	arsta->aggr_mode = aggr_mode;
out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_aggr_mode = {
	.read = ath12k_dbg_sta_read_aggr_mode,
	.write = ath12k_dbg_sta_write_aggr_mode,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t
ath12k_write_htt_peer_stats_reset(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath12k_sta *arsta = (struct ath12k_sta *)sta->drv_priv;
	struct ath12k *ar = arsta->arvif->ar;
	struct htt_ext_stats_cfg_params cfg_params = { 0 };
	int ret;
	u8 type;

	ret = kstrtou8_from_user(user_buf, count, 0, &type);
	if (ret)
		return ret;

	if (!type)
		return ret;

	mutex_lock(&ar->conf_mutex);
	cfg_params.cfg0 = HTT_STAT_PEER_INFO_MAC_ADDR;
	cfg_params.cfg0 |= FIELD_PREP(GENMASK(15, 1),
				HTT_PEER_STATS_REQ_MODE_FLUSH_TQM);

	cfg_params.cfg1 = HTT_STAT_DEFAULT_PEER_REQ_TYPE;

	cfg_params.cfg2 |= FIELD_PREP(GENMASK(7, 0), sta->addr[0]);
	cfg_params.cfg2 |= FIELD_PREP(GENMASK(15, 8), sta->addr[1]);
	cfg_params.cfg2 |= FIELD_PREP(GENMASK(23, 16), sta->addr[2]);
	cfg_params.cfg2 |= FIELD_PREP(GENMASK(31, 24), sta->addr[3]);

	cfg_params.cfg3 |= FIELD_PREP(GENMASK(7, 0), sta->addr[4]);
	cfg_params.cfg3 |= FIELD_PREP(GENMASK(15, 8), sta->addr[5]);

	cfg_params.cfg3 |= ATH12K_HTT_PEER_STATS_RESET;

	ret = ath12k_dp_tx_htt_h2t_ext_stats_req(ar,
						 ATH12K_DBG_HTT_EXT_STATS_PEER_INFO,
						 &cfg_params,
						 0ULL);
	if (ret) {
		ath12k_warn(ar->ab, "failed to send htt peer stats request: %d\n", ret);
		mutex_unlock(&ar->conf_mutex);
		return ret;
	}

	mutex_unlock(&ar->conf_mutex);

	ret = count;

	return ret;
}

static const struct file_operations fops_htt_peer_stats_reset = {
	.write = ath12k_write_htt_peer_stats_reset,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

void ath12k_debugfs_sta_op_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			       struct ieee80211_sta *sta, struct dentry *dir)
{
	struct ath12k *ar = hw->priv;

	if (ath12k_debugfs_is_extd_tx_stats_enabled(ar))
		debugfs_create_file("tx_stats", 0400, dir, sta,
				    &fops_tx_stats);
	if (ath12k_debugfs_is_extd_rx_stats_enabled(ar))
		debugfs_create_file("rx_stats", 0400, dir, sta,
				    &fops_rx_stats);

	debugfs_create_file("htt_peer_stats", 0400, dir, sta,
			    &fops_htt_peer_stats);

	debugfs_create_file("peer_pktlog", 0644, dir, sta,
			    &fops_peer_pktlog);

	debugfs_create_file("aggr_mode", 0644, dir, sta, &fops_aggr_mode);
	debugfs_create_file("addba", 0200, dir, sta, &fops_addba);
	debugfs_create_file("addba_resp", 0200, dir, sta, &fops_addba_resp);
	debugfs_create_file("delba", 0200, dir, sta, &fops_delba);

	if (test_bit(WMI_TLV_SERVICE_PER_PEER_HTT_STATS_RESET,
		     ar->ab->wmi_ab.svc_map))
		debugfs_create_file("htt_peer_stats_reset", 0600, dir, sta,
				    &fops_htt_peer_stats_reset);
}
