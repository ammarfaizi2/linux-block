/* Copyright (c) 2012-2016, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/**
 * TODO:
 */
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <dt-bindings/sound/qcom,afe.h>
#include <linux/delay.h>
#include <linux/soc/qcom/apr.h>
#include "adsp_err.h"
#include "q6afe-v2.h"

/* AFE Cmds */
#define AFE_PORT_CMD_DEVICE_START 	0x000100E5
#define AFE_PORT_CMD_DEVICE_STOP	0x000100E6
#define AFE_PORT_CMD_SET_PARAM_V2	0x000100EF

/* Responses */
#define AFE_PORT_CMDRSP_GET_PARAM_V2	0x00010106

/* params */
#define AFE_PARAM_ID_HDMI_CONFIG     	0x00010210
#define AFE_API_VERSION_HDMI_CONFIG	0x1

/* AFE Modules */
#define AFE_MODULE_AUDIO_DEV_INTERFACE	0x0001020C

/* Port IDs */
#define AFE_PORT_ID_MULTICHAN_HDMI_RX       0x100E

#define TIMEOUT_MS 1000
#define AFE_CMD_RESP_AVAIL	0
#define AFE_CMD_RESP_NONE	1

struct q6afev2 {
	void *apr;
	struct device *dev;
	int	state;
	int	status;

	struct mutex afe_cmd_lock;
	struct list_head port_list;
	struct mutex port_list_lock;
	struct list_head node;
};

static LIST_HEAD(q6afe_list);
static DEFINE_MUTEX(q6afe_list_mutex);

struct afe_port_cmd_device_start {
	struct apr_hdr hdr;
	u16                  port_id;
	u16                  reserved;
} __packed;

struct afe_port_cmd_device_stop {
	struct apr_hdr hdr;
	u16                  port_id;
	u16                  reserved;
/* Reserved for 32-bit alignment. This field must be set to 0.*/
} __packed;

struct afe_port_param_data_v2 {
	u32 module_id;
	u32 param_id;
	u16 param_size;
	u16 reserved;
} __packed;

struct afe_port_cmd_set_param_v2 {
	u16 port_id;
	u16 payload_size;
	u32 payload_address_lsw;
	u32 payload_address_msw;
	u32 mem_map_handle;
} __packed;

struct afe_param_id_hdmi_multi_chan_audio_cfg {
	u32                  hdmi_cfg_minor_version;
	u16                  datatype;
	u16                  channel_allocation;
	u32                  sample_rate;
	u16                  bit_width;
	u16                  reserved;
} __packed;

union afe_port_config {
	struct afe_param_id_hdmi_multi_chan_audio_cfg hdmi_multi_ch;
} __packed;

struct afe_audioif_config_command {
	struct apr_hdr			hdr;
	struct afe_port_cmd_set_param_v2 param;
	struct afe_port_param_data_v2    pdata;
	union afe_port_config            port;
} __packed;

struct afe_port_map {
	int port_id;
	int token;
	int is_rx;
};

/* Port map of index vs real hw port ids */
static struct afe_port_map port_maps[AFE_PORT_MAX] = {
	[AFE_PORT_HDMI_RX] = {AFE_PORT_ID_MULTICHAN_HDMI_RX, AFE_PORT_HDMI_RX, 1},
};

static struct q6afev2 *of_parse_q6afe_port(struct device *dev, const char *name, int *id)
{
	struct q6afev2 *p;
	struct of_phandle_args args;
	int ret;

	ret = of_parse_phandle_with_fixed_args(dev->of_node, name, 1, 0,  &args);
	if (ret < 0) {
		dev_err(dev, "Failed to parse qcom,afe-port\n");
		return NULL;
	}

	*id = args.args[0];

	list_for_each_entry(p, &q6afe_list, node)
		if (p->dev->of_node == args.np)
			return p;

	return NULL;
}

static struct q6afe_port *afe_find_port(struct q6afev2 *afe, int token)
{
	struct q6afe_port *p;

	list_for_each_entry(p, &afe->port_list, node)
		if (p->token == token)
			return p;

	return NULL;
}

static int32_t afe_callback(struct apr_client_data *data, void *priv)
{
	struct q6afev2 *afe = priv;
	struct q6afe_port *port;

	pr_err("DEBUG: %s \n", __func__);
	if (!data) {
		pr_err("%s: Invalid param data\n", __func__);
		return -EINVAL;
	}
	if (data->opcode == RESET_EVENTS) {
		pr_debug("%s: reset event = %d %d apr[%p]\n",
			__func__,
			data->reset_event, data->reset_proc, afe->apr);

		if (afe->apr) {
			apr_reset(afe->apr);
			afe->state = AFE_CMD_RESP_AVAIL;
			afe->apr = NULL;
		}
		return 0;
	}

	if (data->payload_size) {
		uint32_t *payload;
		uint16_t port_id = 0;
		payload = data->payload;
		if (data->opcode == APR_BASIC_RSP_RESULT) {
			pr_debug("%s:opcode = 0x%x cmd = 0x%x status = 0x%x token=%d\n",
				__func__, data->opcode,
				payload[0], payload[1], data->token);
			if (payload[1] != 0) {
				afe->status = payload[1];
				pr_err("%s: cmd = 0x%x returned error = 0x%x\n",
					__func__, payload[0], payload[1]);
			}
			switch (payload[0]) {
			case AFE_PORT_CMD_SET_PARAM_V2:
			case AFE_PORT_CMD_DEVICE_STOP:
			case AFE_PORT_CMD_DEVICE_START:
			afe->state = AFE_CMD_RESP_AVAIL;
			port = afe_find_port(afe, data->token);
			if (port)
				wake_up(&port->wait);

				break;
			default:
				pr_err("%s: Unknown cmd 0x%x\n", __func__,
						payload[0]);
				break;
			}
		}
		pr_debug("%s: port_id = 0x%x\n", __func__, port_id);
	}
	return 0;
}

int q6afe_get_port_id(int index)
{
	if (index < 0 || index > AFE_MAX_PORTS) {
		pr_err("%s: AFE port index[%d] invalid!\n",
				__func__, index);
		return -EINVAL;
	}

	return port_maps[index].port_id;
}

int afe_get_port_type_from_index(u16 index)
{
	pr_err("DEBUG::: %s  port id %d \n", __func__, index);
/*
	int index = afe_get_port_index(port_id);

*/
	if (index < 0 || index > AFE_MAX_PORTS) {
		pr_err("%s: AFE port index[%d] invalid! for port id %d\n",
				__func__, index, index);
		return -EINVAL;
	}
	if (port_maps[index].is_rx)
		return MSM_AFE_PORT_TYPE_RX;
	else
		return MSM_AFE_PORT_TYPE_TX;
}

/*
 * afe_apr_send_pkt : returns 0 on success, negative otherwise.
 */

static int afe_apr_send_pkt(struct q6afev2 *afe, void *data, wait_queue_head_t *wait)
{
	int ret;

	if (wait)
		afe->state = AFE_CMD_RESP_NONE;

	afe->status = 0;
	ret = apr_send_pkt(afe->apr, data);
	if (ret > 0) {
		if (wait) {
			ret = wait_event_timeout(*wait, (afe->state == AFE_CMD_RESP_AVAIL),
					msecs_to_jiffies(TIMEOUT_MS));
			if (!ret) {
				ret = -ETIMEDOUT;
			} else if (afe->status > 0) {
				pr_err("%s: DSP returned error[%s]\n", __func__,
					adsp_err_get_err_str(afe->status));
				ret = adsp_err_get_lnx_err_code(afe->status);
			} else {
				ret = 0;
			}
		} else {
			ret = 0;
		}
	} else if (ret == 0) {
		pr_err("%s: packet not transmitted\n", __func__);
		/* apr_send_pkt can return 0 when nothing is transmitted */
		ret = -EINVAL;
	}

	pr_debug("%s: leave %d\n", __func__, ret);
	return ret;
}

static int afe_send_cmd_port_start(struct q6afe_port *port)
{
	u16 port_id = port->id;
	struct afe_port_cmd_device_start start;
	struct q6afev2 *afe = port->afe.v2;
	int ret, index;

	pr_debug("%s: enter\n", __func__);
	index = port->token;
	start.hdr.hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
					    APR_HDR_LEN(APR_HDR_SIZE),
					    APR_PKT_VER);
	start.hdr.pkt_size = sizeof(start);
	start.hdr.src_port = 0;
	start.hdr.dest_port = 0;
	start.hdr.token = index;
	start.hdr.opcode = AFE_PORT_CMD_DEVICE_START;
	start.port_id = port_id;
	pr_debug("%s: cmd device start opcode[0x%x] port id[0x%x]\n",
		 __func__, start.hdr.opcode, start.port_id);

	ret = afe_apr_send_pkt(afe, &start, &port->wait);
	if (ret) {
		pr_err("%s: AFE enable for port 0x%x failed %d\n", __func__,
		       port_id, ret);
	}

	return ret;
}

static int afe_port_start(struct q6afe_port *port, union afe_port_config *afe_config)
{
	struct afe_audioif_config_command config;
	struct q6afev2 *afe = port->afe.v2;
	int ret = 0;
	int port_id = port->id;
	int cfg_type;
	int index = 0;

	if (!afe_config) {
		pr_err("%s: Error, no configuration data\n", __func__);
		ret = -EINVAL;
		return ret;
	}

	pr_debug("%s: port id: 0x%x\n", __func__, port_id);

	index = port->token;

	mutex_lock(&afe->afe_cmd_lock);
	/* Also send the topology id here: */
	config.hdr.hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
				APR_HDR_LEN(APR_HDR_SIZE), APR_PKT_VER);
	config.hdr.pkt_size = sizeof(config);
	config.hdr.src_port = 0;
	config.hdr.dest_port = 0;
	config.hdr.token = index;

	cfg_type = port->cfg_type;
	config.hdr.opcode = AFE_PORT_CMD_SET_PARAM_V2;
	config.param.port_id = port_id;
	config.param.payload_size = sizeof(config) - sizeof(struct apr_hdr) -
				    sizeof(config.param);
	config.param.payload_address_lsw = 0x00;
	config.param.payload_address_msw = 0x00;
	config.param.mem_map_handle = 0x00;
	config.pdata.module_id = AFE_MODULE_AUDIO_DEV_INTERFACE;
	config.pdata.param_id = cfg_type;
	config.pdata.param_size = sizeof(config.port);

	config.port = *afe_config;

	ret = afe_apr_send_pkt(afe, &config, &port->wait);
	if (ret) {
		pr_err("%s: AFE enable for port 0x%x failed %d\n",
			__func__, port_id, ret);
		goto fail_cmd;
	}

	ret = afe_send_cmd_port_start(port);

fail_cmd:
	mutex_unlock(&afe->afe_cmd_lock);
	return ret;
}

int afe_get_port_index(u16 port_id)
{
	int i;

	for (i = 0; i < AFE_PORT_MAX; i++) {
		if (port_maps[i].port_id == port_id)
			return i;
	}

	return -EINVAL;
}

int q6afe_port_stop(struct q6afe_port *port)
{
	int port_id = port->id;
	struct afe_port_cmd_device_stop stop;
	struct q6afev2 *afe = port->afe.v2;
	int ret = 0;
	int index = 0;

	pr_debug("%s: port_id = 0x%x\n", __func__, port_id);

	port_id = port->id;
	index = port->token;
	if (index < 0 || index > AFE_MAX_PORTS) {
		pr_err("%s: AFE port index[%d] invalid!\n",
				__func__, index);
		return -EINVAL;
	}
	pr_err("DEBUG::: %s  port id %d \n", __func__, port_id);
	
	stop.hdr.hdr_field = APR_HDR_FIELD(APR_MSG_TYPE_SEQ_CMD,
				APR_HDR_LEN(APR_HDR_SIZE), APR_PKT_VER);
	stop.hdr.pkt_size = sizeof(stop);
	stop.hdr.src_port = 0;
	stop.hdr.dest_port = 0;
	stop.hdr.token = index;
	stop.hdr.opcode = AFE_PORT_CMD_DEVICE_STOP;
	stop.port_id = port_id;
	stop.reserved = 0;

	ret = afe_apr_send_pkt(afe, &stop, &port->wait);
	if (ret)
		pr_err("%s: AFE close failed %d\n", __func__, ret);

	return ret;
}

int q6afe_hdmi_port_start(struct q6afe_port *port, struct q6afe_hdmi_cfg *cfg)
{
	union afe_port_config            port_cfg;

	port_cfg.hdmi_multi_ch.hdmi_cfg_minor_version = AFE_API_VERSION_HDMI_CONFIG;
	port_cfg.hdmi_multi_ch.datatype = cfg->datatype;
	port_cfg.hdmi_multi_ch.channel_allocation = cfg->channel_allocation;
	port_cfg.hdmi_multi_ch.sample_rate = cfg->sample_rate;
	port_cfg.hdmi_multi_ch.bit_width = cfg->bit_width;

	return afe_port_start(port, &port_cfg);
}

struct q6afe_port *q6afe_port_get(struct device *dev, const char *name)
{
	int port_id, index  = 0;
	struct q6afev2 *afe = of_parse_q6afe_port(dev, name, &index);
	struct q6afe_port *port;
	int token;
	int cfg_type;

	if (!afe) {
		dev_err(dev, "Unable to find instance of afe service\n");
		return ERR_PTR(-ENOENT);
	}

	token = index;
	if (token < 0 || token > AFE_MAX_PORTS) {
		pr_err("%s: AFE port token[%d] invalid!\n",
				__func__, token);
		return ERR_PTR(-EINVAL);
	}

	port_id = port_maps[index].port_id;


	port = devm_kzalloc(dev, sizeof(*port), GFP_KERNEL);
	if (!port)
		return ERR_PTR(-ENOMEM);


	init_waitqueue_head(&port->wait);

	port->token = token;
	port->id = port_id;

	port->afe.v2 = afe;
	switch (port_id) {
	case AFE_PORT_ID_MULTICHAN_HDMI_RX:
		cfg_type = AFE_PARAM_ID_HDMI_CONFIG;
		break;
	default:
		pr_err("%s: Invalid port id 0x%x\n", __func__, port_id);
		return ERR_PTR(-EINVAL);
	}

	port->cfg_type = cfg_type;

	mutex_lock(&afe->port_list_lock);
	list_add_tail(&port->node, &afe->port_list);
	mutex_unlock(&afe->port_list_lock);



	return port;

}

int q6afe_port_put(struct q6afe_port *port)
{
	struct q6afev2 *afe = port->afe.v2;

	mutex_lock(&afe->port_list_lock);
	list_del(&port->node);
	mutex_unlock(&afe->port_list_lock);

	return 0;
}

static int q6afev2_probe(struct platform_device *pdev)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct q6afev2 *afe = devm_kzalloc(dev, sizeof(*afe), GFP_KERNEL);

	if (!afe)
		return -ENOMEM;
	
	afe->apr = apr_register(dev, "ADSP", "AFE", afe_callback, 0xFFFFFFFF, afe);
	if (afe->apr == NULL) {
		pr_err("%s: Unable to register AFE\n", __func__);
		ret = -ENODEV;
	}

	mutex_init(&afe->afe_cmd_lock);

	afe->dev = dev;
	INIT_LIST_HEAD(&afe->port_list);
	mutex_init(&afe->port_list_lock);
	mutex_lock(&q6afe_list_mutex);
	list_add_tail(&afe->node, &q6afe_list);
	mutex_unlock(&q6afe_list_mutex);

	platform_set_drvdata(pdev, afe);
	return 0;
}

static int q6afev2_remove(struct platform_device *pdev)
{
	struct q6afev2 *afe = platform_get_drvdata(pdev);

	apr_deregister(afe->apr);
	return 0;
}

static const struct of_device_id qcom_q6afe_match[] = {
	{ .compatible = "qcom,q6afe-v2",},
	{ }
};

static struct platform_driver qcom_q6afe_driver = {
	.probe = q6afev2_probe,
	.remove = q6afev2_remove,
	.driver = {
		.name = "qcom-q6afe-v2",
		.of_match_table = qcom_q6afe_match,
	},
};

module_platform_driver(qcom_q6afe_driver);
