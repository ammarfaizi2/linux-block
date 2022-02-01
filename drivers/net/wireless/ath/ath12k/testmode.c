// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "testmode.h"
#include <net/netlink.h>
#include "debug.h"
#include "wmi.h"
#include "hw.h"
#include "core.h"
#include "testmode_i.h"

static const struct nla_policy ath12k_tm_policy[ATH12K_TM_ATTR_MAX + 1] = {
	[ATH12K_TM_ATTR_CMD]		= { .type = NLA_U32 },
	[ATH12K_TM_ATTR_DATA]		= { .type = NLA_BINARY,
					    .len = ATH12K_TM_DATA_MAX_LEN },
	[ATH12K_TM_ATTR_WMI_CMDID]	= { .type = NLA_U32 },
	[ATH12K_TM_ATTR_VERSION_MAJOR]	= { .type = NLA_U32 },
	[ATH12K_TM_ATTR_VERSION_MINOR]	= { .type = NLA_U32 },
};

/* Returns true if callee consumes the skb and the skb should be discarded.
 * Returns false if skb is not used. Does not sleep.
 */
bool ath12k_tm_event_wmi(struct ath12k *ar, u32 cmd_id, struct sk_buff *skb)
{
	struct sk_buff *nl_skb;
	bool consumed;
	int ret;

	ath12k_dbg(ar->ab, ATH12K_DBG_TESTMODE,
		   "testmode event wmi cmd_id %d skb %pK skb->len %d\n",
		   cmd_id, skb, skb->len);

	ath12k_dbg_dump(ar->ab, ATH12K_DBG_TESTMODE, NULL, "", skb->data, skb->len);

	spin_lock_bh(&ar->data_lock);

	consumed = true;

	nl_skb = cfg80211_testmode_alloc_event_skb(ar->hw->wiphy,
						   2 * sizeof(u32) + skb->len,
						   GFP_ATOMIC);
	if (!nl_skb) {
		ath12k_warn(ar->ab,
			    "failed to allocate skb for testmode wmi event\n");
		goto out;
	}

	ret = nla_put_u32(nl_skb, ATH12K_TM_ATTR_CMD, ATH12K_TM_CMD_WMI);
	if (ret) {
		ath12k_warn(ar->ab,
			    "failed to put testmode wmi event cmd attribute: %d\n",
			    ret);
		kfree_skb(nl_skb);
		goto out;
	}

	ret = nla_put_u32(nl_skb, ATH12K_TM_ATTR_WMI_CMDID, cmd_id);
	if (ret) {
		ath12k_warn(ar->ab,
			    "failed to put testmode wmi even cmd_id: %d\n",
			    ret);
		kfree_skb(nl_skb);
		goto out;
	}

	ret = nla_put(nl_skb, ATH12K_TM_ATTR_DATA, skb->len, skb->data);
	if (ret) {
		ath12k_warn(ar->ab,
			    "failed to copy skb to testmode wmi event: %d\n",
			    ret);
		kfree_skb(nl_skb);
		goto out;
	}

	cfg80211_testmode_event(nl_skb, GFP_ATOMIC);

out:
	spin_unlock_bh(&ar->data_lock);

	return consumed;
}

static int ath12k_tm_cmd_get_version(struct ath12k *ar, struct nlattr *tb[])
{
	struct sk_buff *skb;
	int ret;

	ath12k_dbg(ar->ab, ATH12K_DBG_TESTMODE,
		   "testmode cmd get version_major %d version_minor %d\n",
		   ATH12K_TESTMODE_VERSION_MAJOR,
		   ATH12K_TESTMODE_VERSION_MINOR);

	skb = cfg80211_testmode_alloc_reply_skb(ar->hw->wiphy,
						nla_total_size(sizeof(u32)));
	if (!skb)
		return -ENOMEM;

	ret = nla_put_u32(skb, ATH12K_TM_ATTR_VERSION_MAJOR,
			  ATH12K_TESTMODE_VERSION_MAJOR);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	ret = nla_put_u32(skb, ATH12K_TM_ATTR_VERSION_MINOR,
			  ATH12K_TESTMODE_VERSION_MINOR);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	return cfg80211_testmode_reply(skb);
}

static int ath12k_tm_cmd_wmi(struct ath12k *ar, struct nlattr *tb[])
{
	struct ath12k_pdev_wmi *wmi = ar->wmi;
	struct sk_buff *skb;
	u32 cmd_id, buf_len;
	int ret;
	void *buf;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH12K_STATE_ON) {
		ret = -ENETDOWN;
		goto out;
	}

	if (!tb[ATH12K_TM_ATTR_DATA]) {
		ret = -EINVAL;
		goto out;
	}

	if (!tb[ATH12K_TM_ATTR_WMI_CMDID]) {
		ret = -EINVAL;
		goto out;
	}

	buf = nla_data(tb[ATH12K_TM_ATTR_DATA]);
	buf_len = nla_len(tb[ATH12K_TM_ATTR_DATA]);
	cmd_id = nla_get_u32(tb[ATH12K_TM_ATTR_WMI_CMDID]);

	ath12k_dbg(ar->ab, ATH12K_DBG_TESTMODE,
		   "testmode cmd wmi cmd_id %d buf %pK buf_len %d\n",
		   cmd_id, buf, buf_len);

	ath12k_dbg_dump(ar->ab, ATH12K_DBG_TESTMODE, NULL, "", buf, buf_len);

	skb = ath12k_wmi_alloc_skb(wmi->wmi_ab, buf_len);
	if (!skb) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(skb->data, buf, buf_len);

	ret = ath12k_wmi_cmd_send(wmi, skb, cmd_id);
	if (ret) {
		dev_kfree_skb(skb);
		ath12k_warn(ar->ab, "failed to transmit wmi command (testmode): %d\n",
			    ret);
		goto out;
	}

	ret = 0;

out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

int ath12k_tm_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		  void *data, int len)
{
	struct ath12k *ar = hw->priv;
	struct nlattr *tb[ATH12K_TM_ATTR_MAX + 1];
	int ret;

	ret = nla_parse(tb, ATH12K_TM_ATTR_MAX, data, len, ath12k_tm_policy,
			NULL);
	if (ret)
		return ret;

	if (!tb[ATH12K_TM_ATTR_CMD])
		return -EINVAL;

	switch (nla_get_u32(tb[ATH12K_TM_ATTR_CMD])) {
	case ATH12K_TM_CMD_GET_VERSION:
		return ath12k_tm_cmd_get_version(ar, tb);
	case ATH12K_TM_CMD_WMI:
		return ath12k_tm_cmd_wmi(ar, tb);
	default:
		return -EOPNOTSUPP;
	}
}
