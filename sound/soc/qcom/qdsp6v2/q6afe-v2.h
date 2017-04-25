#ifndef __Q6AFE_V2_H__
#define __Q6AFE_V2_H__
#include <dt-bindings/sound/qcom,afe.h>
#define MSM_AFE_PORT_TYPE_RX 0
#define MSM_AFE_PORT_TYPE_TX 1
#define AFE_MAX_PORTS AFE_PORT_MAX 

struct q6afe_hdmi_cfg {
	u16                  datatype;
	u16                  channel_allocation;
	u32                  sample_rate;
	u16                  bit_width;
};

struct q6afev1;
struct q6afev2;

struct q6afe_port {
	wait_queue_head_t wait;
	int token;
	int id;
	int cfg_type;
	union {
		struct q6afev2 *v2;
	//	struct q6afev1 *v1;
	} afe;
	struct list_head	node;
};

int q6afe_get_port_id(int index);

int afe_get_port_type_from_index(u16 port_id);
int afe_get_port_index(u16 port_id);
//int afe_convert_virtual_to_portid(u16 port_id);


struct q6afe_port *q6afe_port_get(struct device *dev, const char *name);
int q6afe_hdmi_port_start(struct q6afe_port *port, struct q6afe_hdmi_cfg *cfg);
int q6afe_port_stop(struct q6afe_port *port);
int q6afe_port_put(struct q6afe_port *port);

#endif /* __Q6AFE_V2_H__ */
