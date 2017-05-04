/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * TODO:
 * 	- handle reboot/reset use case
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/soc/qcom/apr.h>
#include <linux/rpmsg.h>
#include <linux/of.h>

static struct workqueue_struct *apr_reset_workqueue;
static void apr_reset_deregister(struct work_struct *work);
struct apr_reset_work {
	void *handle;
	struct work_struct work;
};

struct apr_ops {
	int (*get_dest_id)(char *dest);
	uint16_t (*get_data_src)(struct apr_hdr *hdr);
};

struct apr;
typedef void (*apr_svc_cb_fn)(struct apr* apr, void *buf, int len, void *priv);

struct apr {
	struct rpmsg_endpoint *ch;
	u32 id;
	u32 dest_id;
	int	client_id;
	apr_svc_cb_fn      func;
	char               data[APR_MAX_BUF];
	void               *priv;
	uint8_t svc_cnt;
	uint8_t rvd;
	struct mutex m_lock;

	struct mutex svcs_list_lock;
	struct list_head svcs;
};

struct apr_svc_table {
	char name[64];
	int idx;
	int id;
	int client_id;
};

static const struct apr_svc_table svc_tbl_qdsp6[] = {
	{
		.name = "AFE",
		.idx = 0,
		.id = APR_SVC_AFE,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "ASM",
		.idx = 1,
		.id = APR_SVC_ASM,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "ADM",
		.idx = 2,
		.id = APR_SVC_ADM,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "CORE",
		.idx = 3,
		.id = APR_SVC_ADSP_CORE,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "TEST",
		.idx = 4,
		.id = APR_SVC_TEST_CLIENT,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "MVM",
		.idx = 5,
		.id = APR_SVC_ADSP_MVM,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "CVS",
		.idx = 6,
		.id = APR_SVC_ADSP_CVS,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "CVP",
		.idx = 7,
		.id = APR_SVC_ADSP_CVP,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "USM",
		.idx = 8,
		.id = APR_SVC_USM,
		.client_id = APR_CLIENT_AUDIO,
	},
	{
		.name = "VIDC",
		.idx = 9,
		.id = APR_SVC_VIDC,
	},
	{
		.name = "LSM",
		.idx = 10,
		.id = APR_SVC_LSM,
		.client_id = APR_CLIENT_AUDIO,
	},
};

static struct apr_svc_table svc_tbl_voice[] = {
	{
		.name = "VSM",
		.idx = 0,
		.id = APR_SVC_VSM,
		.client_id = APR_CLIENT_VOICE,
	},
	{
		.name = "VPM",
		.idx = 1,
		.id = APR_SVC_VPM,
		.client_id = APR_CLIENT_VOICE,
	},
	{
		.name = "MVS",
		.idx = 2,
		.id = APR_SVC_MVS,
		.client_id = APR_CLIENT_VOICE,
	},
	{
		.name = "MVM",
		.idx = 3,
		.id = APR_SVC_MVM,
		.client_id = APR_CLIENT_VOICE,
	},
	{
		.name = "CVS",
		.idx = 4,
		.id = APR_SVC_CVS,
		.client_id = APR_CLIENT_VOICE,
	},
	{
		.name = "CVP",
		.idx = 5,
		.id = APR_SVC_CVP,
		.client_id = APR_CLIENT_VOICE,
	},
	{
		.name = "SRD",
		.idx = 6,
		.id = APR_SVC_SRD,
		.client_id = APR_CLIENT_VOICE,
	},
	{
		.name = "TEST",
		.idx = 7,
		.id = APR_SVC_TEST_CLIENT,
		.client_id = APR_CLIENT_VOICE,
	},
};

int apr_smd_write(struct apr *apr, void *data, int len)
{
	int ret;
	ret = rpmsg_send(apr->ch, data, len);
	if (ret) { 
		pr_err("apr_tal: Error in write %d\n", ret);
		return ret;;
	}
	return len;
}

int apr_smd_close(struct apr *apr)
{
	if (!apr->ch)
		return -EINVAL;

	apr->ch = NULL;
	apr->func = NULL;
	apr->priv = NULL;
	return 0;
}

static int qcom_smd_q6_callback(struct rpmsg_device *rpdev,
				 void *data,
				 int count,
				 void *priv,
				 u32 addr)
{
	struct apr *apr = dev_get_drvdata(&rpdev->dev);

	memcpy(apr->data, data, count);
	if (apr->func)
		apr->func(apr, apr->data, count, apr->priv);

	return 0;
}

static int qcom_smd_apr_get_client_id(const char *name)
{
	if (!strcmp(name, "apr_audio_svc"))
		return APR_CLIENT_AUDIO;
	else if (!strcmp(name, "apr_voice_svc"))
		return APR_CLIENT_VOICE;

	return -EINVAL;
}

int apr_send_pkt(void *handle, uint32_t *buf)
{
	struct apr_svc *svc = handle;
	struct apr *clnt = dev_get_drvdata(svc->dev->parent);
	struct apr_hdr *hdr;
	uint16_t dest_id;
	uint16_t client_id;
	uint16_t w_len;
	unsigned long flags;

	if (!handle || !buf) {
		pr_debug("APR: Wrong parameters\n");
		return -EINVAL;
	}
	if (svc->need_reset) {
		pr_debug("apr: send_pkt service need reset\n");
		return -ENETRESET;
	}

	spin_lock_irqsave(&svc->w_lock, flags);
	dest_id = svc->dest_id;
	client_id = svc->client_id;

	hdr = (struct apr_hdr *)buf;

	hdr->src_domain = APR_DOMAIN_APPS;
	hdr->src_svc = svc->id;
	hdr->dest_domain = svc->dest_domain;
	hdr->dest_svc = svc->id;

	w_len = apr_smd_write(clnt, buf, hdr->pkt_size);
	if (w_len != hdr->pkt_size)
		pr_debug("Unable to write APR pkt successfully: %d\n", w_len);
	spin_unlock_irqrestore(&svc->w_lock, flags);

	return w_len;
}

#define DEST_ID APR_DEST_MODEM
int apr_v2_get_dest_id(char *dest)
{
        if (!strcmp(dest, "ADSP"))
                return APR_DEST_QDSP6;
        else
                return APR_DEST_MODEM;
}

int apr_v3_get_dest_id(char *dest)
{
	return DEST_ID;
}

uint16_t apr_v2_get_data_src(struct apr_hdr *hdr)
{
        if (hdr->src_domain == APR_DOMAIN_MODEM)
                return APR_DEST_MODEM;
        else if (hdr->src_domain == APR_DOMAIN_ADSP)
                return APR_DEST_QDSP6;
        else {
                pr_debug("APR: Pkt from wrong source: %d\n", hdr->src_domain);
                return APR_DEST_MAX;            /*RETURN INVALID VALUE*/
        }

}

uint16_t apr_v3_get_data_src(struct apr_hdr *hdr)
{
	return DEST_ID;
}

int apr_get_svc(const char *svc_name, int domain_id, int *client_id,
		int *svc_idx, int *svc_id)
{
	int i;
	int size;
	struct apr_svc_table *tbl;
	int ret = 0;

	if ((domain_id == APR_DOMAIN_ADSP)) {
		tbl = (struct apr_svc_table *)&svc_tbl_qdsp6;
		size = ARRAY_SIZE(svc_tbl_qdsp6);
	} else {
		tbl = (struct apr_svc_table *)&svc_tbl_voice;
		size = ARRAY_SIZE(svc_tbl_voice);
	}

	for (i = 0; i < size; i++) {
		if (!strcmp(svc_name, tbl[i].name)) {
			*client_id = tbl[i].client_id;
			*svc_idx = tbl[i].idx;
			*svc_id = tbl[i].id;
			break;
		}
	}

	pr_debug("%s: svc_name = %s c_id = %d domain_id = %d\n",
		 __func__, svc_name, *client_id, domain_id);
	if (i == size) {
		pr_debug("%s: APR: Wrong svc name %s\n", __func__, svc_name);
		ret = -EINVAL;
	}

	return ret;
}

struct apr_svc *apr_register(struct device *dev, char *dest, char *svc_name, apr_fn svc_fn,
			     uint32_t src_port, void *priv)
{
	int client_id = 0;
	int svc_idx = 0;
	int svc_id = 0;
	int dest_id = 0;
	int domain_id = 0;
	int temp_port = 0;
	struct apr_svc *p, *svc = NULL;
	struct apr *client = dev_get_drvdata(dev->parent);

	if (!client || !dest || !svc_name || !svc_fn)
		return NULL;

	if (!strcmp(dest, "ADSP"))
		domain_id = APR_DOMAIN_ADSP;
	else if (!strcmp(dest, "MODEM")) {
		domain_id = APR_DOMAIN_MODEM;
	} else {
		pr_debug("APR: wrong destination\n");
		goto done;
	}

	dest_id = client->dest_id;

	if (apr_get_svc(svc_name, domain_id, &client_id, &svc_idx, &svc_id)) {
		pr_err("%s: apr_get_svc failed\n", __func__);
		goto done;
	}

	list_for_each_entry(p, &client->svcs, node) {
		if (svc_id == p->id) {
			svc = p;
			break;
		}
	}

	if (!svc)
		svc = kzalloc(sizeof(*svc), GFP_KERNEL);

	if (!svc)
		return NULL;
	
	mutex_init(&svc->m_lock);
	spin_lock_init(&svc->w_lock);

	
	mutex_lock(&svc->m_lock);
	if (svc->need_reset) {
		mutex_unlock(&svc->m_lock);
		pr_debug("APR: Service needs reset\n");
		goto done;
	}
	svc->priv = priv;
	svc->id = svc_id;
	svc->dest_id = dest_id;
	svc->client_id = client_id;
	svc->dest_domain = domain_id;
	svc->dev = dev;
	if (src_port != 0xFFFFFFFF) {
		temp_port = ((src_port >> 8) * 8) + (src_port & 0xFF);
		pr_debug("port = %d t_port = %d\n", src_port, temp_port);
		if (temp_port >= APR_MAX_PORTS || temp_port < 0) {
			pr_debug("APR: temp_port out of bounds\n");
			mutex_unlock(&svc->m_lock);
			return NULL;
		}
		if (!svc->port_cnt && !svc->svc_cnt)
			client->svc_cnt++;
		svc->port_cnt++;
		svc->port_fn[temp_port] = svc_fn;
		svc->port_priv[temp_port] = priv;
	} else {
		if (!svc->fn) {
			if (!svc->port_cnt && !svc->svc_cnt)
				client->svc_cnt++;
			svc->fn = svc_fn;
			if (svc->port_cnt)
				svc->svc_cnt++;
		}
	}

	mutex_unlock(&svc->m_lock);

	mutex_lock(&client->svcs_list_lock);
	list_add_tail(&svc->node, &client->svcs);
	mutex_unlock(&client->svcs_list_lock);
done:
	return svc;
}

void apr_cb_func(struct apr *client, void *buf, int len, void *priv)
{
	struct apr_client_data data;
	struct apr_svc *p, *c_svc = NULL;
	struct apr_hdr *hdr;
	uint16_t hdr_size;
	uint16_t msg_type;
	uint16_t ver;
	uint16_t src;
	uint16_t svc;
	uint16_t clnt;
	int i;
	int temp_port = 0;
	uint32_t *ptr;

	pr_debug("APR2: len = %d\n", len);
	ptr = buf;
	pr_debug("\n*****************\n");
	for (i = 0; i < len/4; i++)
		pr_debug("%x  ", ptr[i]);
	pr_debug("\n");
	pr_debug("\n*****************\n");

	if (!buf || len <= APR_HDR_SIZE) {
		pr_err("APR: Improper apr pkt received:%p %d\n", buf, len);
		return;
	}
	hdr = buf;
	ver = hdr->hdr_field;
	ver = (ver & 0x000F);
	if (ver > APR_PKT_VER + 1) {
		pr_err("APR: Wrong version: %d\n", ver);
		return;
	}

	hdr_size = hdr->hdr_field;
	hdr_size = ((hdr_size & 0x00F0) >> 0x4) * 4;
	if (hdr_size < APR_HDR_SIZE) {
		pr_debug("APR: Wrong hdr size:%d\n", hdr_size);
		return;
	}

	if (hdr->pkt_size < APR_HDR_SIZE) {
		pr_debug("APR: Wrong paket size\n");
		return;
	}
	msg_type = hdr->hdr_field;
	msg_type = (msg_type >> 0x08) & 0x0003;
	if (msg_type >= APR_MSG_TYPE_MAX && msg_type != APR_BASIC_RSP_RESULT) {
		pr_debug("APR: Wrong message type: %d\n", msg_type);
		return;
	}

	if (hdr->src_domain >= APR_DOMAIN_MAX ||
		hdr->dest_domain >= APR_DOMAIN_MAX ||
		hdr->src_svc >= APR_SVC_MAX ||
		hdr->dest_svc >= APR_SVC_MAX) {
		pr_debug("APR: Wrong APR header\n");
		return;
	}

	svc = hdr->dest_svc;
	if (hdr->src_domain == APR_DOMAIN_MODEM) {
		if (svc == APR_SVC_MVS || svc == APR_SVC_MVM ||
		    svc == APR_SVC_CVS || svc == APR_SVC_CVP ||
		    svc == APR_SVC_TEST_CLIENT)
			clnt = APR_CLIENT_VOICE;
		else {
			pr_debug("APR: Wrong svc :%d\n", svc);
			return;
		}
	} else if (hdr->src_domain == APR_DOMAIN_ADSP) {
		if (svc == APR_SVC_AFE || svc == APR_SVC_ASM ||
		    svc == APR_SVC_VSM || svc == APR_SVC_VPM ||
		    svc == APR_SVC_ADM || svc == APR_SVC_ADSP_CORE ||
		    svc == APR_SVC_USM ||
		    svc == APR_SVC_TEST_CLIENT || svc == APR_SVC_ADSP_MVM ||
		    svc == APR_SVC_ADSP_CVS || svc == APR_SVC_ADSP_CVP ||
		    svc == APR_SVC_LSM)
			clnt = APR_CLIENT_AUDIO;
		else if (svc == APR_SVC_VIDC)
			clnt = APR_CLIENT_AUDIO;
		else {
			pr_debug("APR: Wrong svc :%d\n", svc);
			return;
		}
	} else {
		pr_debug("APR: Pkt from wrong source: %d\n", hdr->src_domain);
		return;
	}

	src = apr_v2_get_data_src(hdr);
	if (src == APR_DEST_MAX)
		return;

	pr_debug("src =%d clnt = %d\n", src, clnt);

	list_for_each_entry(p, &client->svcs, node) {
		if (svc == p->id) {
			c_svc = p;
			break;
		}
	}

	if (!c_svc) {	
		pr_debug("APR: service is not registered\n");
		return;
	}
	pr_debug("%x %x %x %p %p\n", c_svc->id, c_svc->dest_id,
		 c_svc->client_id, c_svc->fn, c_svc->priv);
	data.payload_size = hdr->pkt_size - hdr_size;
	data.opcode = hdr->opcode;
	data.src = src;
	data.src_port = hdr->src_port;
	data.dest_port = hdr->dest_port;
	data.token = hdr->token;
	data.msg_type = msg_type;
	if (data.payload_size > 0)
		data.payload = (char *)hdr + hdr_size;

	temp_port = ((data.dest_port >> 8) * 8) + (data.dest_port & 0xFF);
	pr_debug("port = %d t_port = %d\n", data.src_port, temp_port);
	if (c_svc->port_cnt && c_svc->port_fn[temp_port])
		c_svc->port_fn[temp_port](&data,  c_svc->port_priv[temp_port]);
	else if (c_svc->fn)
		c_svc->fn(&data, c_svc->priv);
	else
		pr_debug("APR: Rxed a packet for NULL callback\n");
}

static void apr_reset_deregister(struct work_struct *work)
{
	struct apr_svc *handle = NULL;
	struct apr_reset_work *apr_reset =
			container_of(work, struct apr_reset_work, work);

	handle = apr_reset->handle;
	pr_debug("%s:handle[%p]\n", __func__, handle);
	apr_deregister(handle);
	kfree(apr_reset);
}

int apr_deregister(void *handle)
{
	struct apr_svc *svc = handle;
	struct apr *clnt = dev_get_drvdata(svc->dev->parent);
	uint16_t dest_id;
	uint16_t client_id;

	if (!handle)
		return -EINVAL;

	mutex_lock(&svc->m_lock);
	dest_id = svc->dest_id;
	client_id = svc->client_id;

	if (svc->port_cnt > 0 || svc->svc_cnt > 0) {
		if (svc->port_cnt)
			svc->port_cnt--;
		else if (svc->svc_cnt)
			svc->svc_cnt--;
		if (!svc->port_cnt && !svc->svc_cnt) {
			clnt->svc_cnt--;
			svc->need_reset = 0x0;
		}
	} else if (clnt->svc_cnt > 0) {
		clnt->svc_cnt--;
		if (!clnt->svc_cnt) {
			svc->need_reset = 0x0;
			pr_debug("%s: service is reset %p\n", __func__, svc);
		}
	}

	if (!svc->port_cnt && !svc->svc_cnt) {
		svc->priv = NULL;
		svc->id = 0;
		svc->fn = NULL;
		svc->dest_id = 0;
		svc->client_id = 0;
		svc->need_reset = 0x0;
		mutex_unlock(&svc->m_lock);
		
		mutex_lock(&clnt->svcs_list_lock);
		list_del(&svc->node);
		mutex_unlock(&clnt->svcs_list_lock);		
		kfree(svc);
		goto done;
	}

	mutex_unlock(&svc->m_lock);
done:
	if (clnt &&
	    !clnt->svc_cnt) {
		apr_smd_close(clnt);
	}

	return 0;
}

void apr_reset(void *handle)
{
	struct apr_reset_work *apr_reset_worker = NULL;

	if (!handle)
		return;
	pr_debug("%s: handle[%p]\n", __func__, handle);

	if (apr_reset_workqueue == NULL) {
		pr_debug("%s: apr_reset_workqueue is NULL\n", __func__);
		return;
	}

	apr_reset_worker = kzalloc(sizeof(struct apr_reset_work),
							GFP_ATOMIC);

	if (apr_reset_worker == NULL) {
		pr_debug("%s: mem failure\n", __func__);
		return;
	}

	apr_reset_worker->handle = handle;
	INIT_WORK(&apr_reset_worker->work, apr_reset_deregister);
	queue_work(apr_reset_workqueue, &apr_reset_worker->work);
}

static int qcom_smd_q6_probe(struct rpmsg_device *rpdev)
{
	struct device *dev = &rpdev->dev;
	const char *name;
	struct apr *apr;
	int ret;

	apr = devm_kzalloc(dev, sizeof(*apr), GFP_KERNEL);
	if (!apr)
		return -ENOMEM;

	ret = of_property_read_string(dev->of_node, "qcom,smd-channels", &name);
	if (ret) {
		dev_err(dev, "qcom,smd-channels name not found\n");
		return -EINVAL;
	}
	apr->client_id = qcom_smd_apr_get_client_id(name);
	if (apr->client_id < 0)
		return -EINVAL;

	apr->ch = rpdev->ept;
	ret = of_property_read_u32(dev->parent->of_node, "qcom,smd-edge", &apr->dest_id);
	if (ret) {
		dev_err(dev, "qcom,smd-edge not found\n");
		return -EINVAL;
	}

	dev_set_drvdata(&rpdev->dev, apr);

	apr->func = apr_cb_func; 
	apr->id = apr->client_id;
	INIT_LIST_HEAD(&apr->svcs);
	//apr_init_client(apr);
	apr_reset_workqueue = create_singlethread_workqueue("apr_driver");
	if (!apr_reset_workqueue)
		return -ENOMEM;

	pr_info("apr_tal:Q6 Is Up\n");
	dev_info(dev, "APR:TAL: probed for client id %d  dest id %d\n", apr->client_id, apr->dest_id);

	return of_platform_populate(rpdev->dev.of_node, NULL, NULL, &rpdev->dev);
}

static void qcom_smd_q6_remove(struct rpmsg_device *rpdev)
{
//FIXME ?? Shutdown/teardown path...
}

struct apr_ops apr_v2_ops = {
	.get_data_src = apr_v2_get_data_src,
	.get_dest_id = apr_v2_get_dest_id,
};

struct apr_ops apr_v3_ops = {
	.get_data_src = apr_v3_get_data_src,
	.get_dest_id = apr_v3_get_dest_id,
};

static const struct of_device_id qcom_smd_q6_of_match[] = {
	{ .compatible = "qcom,smd-apr" },
	{ .compatible = "qcom,smd-apr-apq8064", .data = &apr_v2_ops },
	{ .compatible = "qcom,smd-apr-msm8916", .data = &apr_v3_ops },
	{ .compatible = "qcom,smd-apr-msm8996", .data = &apr_v2_ops },
	{}
};

static struct rpmsg_driver qcom_smd_q6_driver = {
	.probe = qcom_smd_q6_probe,
	.remove = qcom_smd_q6_remove,
	.callback = qcom_smd_q6_callback,
	.drv  = {
		.name  = "qcom_smd_q6",
		.owner = THIS_MODULE,
		.of_match_table = qcom_smd_q6_of_match,
	},
};
module_rpmsg_driver(qcom_smd_q6_driver);

MODULE_AUTHOR("Srinivas Kandagatla <srinivas.kandagatla@linaro.org");
MODULE_DESCRIPTION("Qualcomm SMD backed apr driver");
MODULE_LICENSE("GPL v2");
