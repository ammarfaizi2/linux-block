// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple RTKit library
 * Copyright (C) The Asahi Linux Contributors
 */

//#define DEBUG

#include "rtkit-internal.h"

enum { APPLE_RTKIT_WORK_MSG,
       APPLE_RTKIT_WORK_REINIT,
};

enum { APPLE_RTKIT_PWR_STATE_OFF = 0x00,
       APPLE_RTKIT_PWR_STATE_SLEEP = 0x01,
       APPLE_RTKIT_PWR_STATE_GATED = 0x02,
       APPLE_RTKIT_PWR_STATE_QUIESCED = 0x10,
       APPLE_RTKIT_PWR_STATE_ON = 0x20,
};

enum { APPLE_RTKIT_EP_MGMT = 0,
       APPLE_RTKIT_EP_CRASHLOG = 1,
       APPLE_RTKIT_EP_SYSLOG = 2,
       APPLE_RTKIT_EP_DEBUG = 3,
       APPLE_RTKIT_EP_IOREPORT = 4,
       APPLE_RTKIT_EP_OSLOG = 8,
};

#define APPLE_RTKIT_MGMT_TYPE GENMASK(59, 52)

enum { APPLE_RTKIT_MGMT_HELLO = 1,
       APPLE_RTKIT_MGMT_HELLO_REPLY = 2,
       APPLE_RTKIT_MGMT_STARTEP = 5,
       APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE = 6,
       APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE_ACK = 7,
       APPLE_RTKIT_MGMT_EPMAP = 8,
       APPLE_RTKIT_MGMT_EPMAP_REPLY = 8,
       APPLE_RTKIT_MGMT_SET_AP_PWR_STATE = 0xb,
       APPLE_RTKIT_MGMT_SET_AP_PWR_STATE_ACK = 0xb,
};

#define APPLE_RTKIT_MGMT_HELLO_MINVER GENMASK(15, 0)
#define APPLE_RTKIT_MGMT_HELLO_MAXVER GENMASK(31, 16)

#define APPLE_RTKIT_MGMT_EPMAP_LAST   BIT(51)
#define APPLE_RTKIT_MGMT_EPMAP_BASE   GENMASK(34, 32)
#define APPLE_RTKIT_MGMT_EPMAP_BITMAP GENMASK(31, 0)

#define APPLE_RTKIT_MGMT_EPMAP_REPLY_MORE BIT(0)

#define APPLE_RTKIT_MGMT_STARTEP_EP   GENMASK(39, 32)
#define APPLE_RTKIT_MGMT_STARTEP_FLAG BIT(1)

#define APPLE_RTKIT_MGMT_PWR_STATE GENMASK(15, 0)

#define APPLE_RTKIT_CRASHLOG_CRASH 1

#define APPLE_RTKIT_BUFFER_REQUEST	1
#define APPLE_RTKIT_BUFFER_REQUEST_SIZE GENMASK(51, 44)
#define APPLE_RTKIT_BUFFER_REQUEST_IOVA GENMASK(41, 0)

#define APPLE_RTKIT_SYSLOG_TYPE GENMASK(59, 52)

#define APPLE_RTKIT_SYSLOG_LOG 5

#define APPLE_RTKIT_SYSLOG_INIT	     8
#define APPLE_RTKIT_SYSLOG_N_ENTRIES GENMASK(7, 0)
#define APPLE_RTKIT_SYSLOG_MSG_SIZE  GENMASK(31, 24)

#define APPLE_RTKIT_OSLOG_TYPE GENMASK(63, 56)
#define APPLE_RTKIT_OSLOG_INIT	1
#define APPLE_RTKIT_OSLOG_ACK	3

#define APPLE_RTKIT_MIN_SUPPORTED_VERSION 11
#define APPLE_RTKIT_MAX_SUPPORTED_VERSION 12

bool apple_rtkit_is_running(struct apple_rtkit *rtk)
{
	if (rtk->crashed)
		return false;
	if ((rtk->iop_power_state & 0xff) != APPLE_RTKIT_PWR_STATE_ON)
		return false;
	if ((rtk->ap_power_state & 0xff) != APPLE_RTKIT_PWR_STATE_ON)
		return false;
	return true;
}
EXPORT_SYMBOL_GPL(apple_rtkit_is_running);

bool apple_rtkit_is_crashed(struct apple_rtkit *rtk)
{
	return rtk->crashed;
}
EXPORT_SYMBOL_GPL(apple_rtkit_is_crashed);

static void apple_rtkit_management_send(struct apple_rtkit *rtk, u8 type,
					u64 msg)
{
	msg &= ~APPLE_RTKIT_MGMT_TYPE;
	msg |= FIELD_PREP(APPLE_RTKIT_MGMT_TYPE, type);
	apple_rtkit_send_message(rtk, APPLE_RTKIT_EP_MGMT, msg);
}

static void apple_rtkit_management_rx_hello(struct apple_rtkit *rtk, u64 msg)
{
	u64 reply;

	int min_ver = FIELD_GET(APPLE_RTKIT_MGMT_HELLO_MINVER, msg);
	int max_ver = FIELD_GET(APPLE_RTKIT_MGMT_HELLO_MAXVER, msg);
	int want_ver = min(APPLE_RTKIT_MAX_SUPPORTED_VERSION, max_ver);

	rtk_dbg("Min ver %d, max ver %d\n", min_ver, max_ver);

	if (min_ver > APPLE_RTKIT_MAX_SUPPORTED_VERSION) {
		rtk_err("Firmware min version %d is too new\n", min_ver);
		goto abort_boot;
	}

	if (max_ver < APPLE_RTKIT_MIN_SUPPORTED_VERSION) {
		rtk_err("Firmware max version %d is too old\n", max_ver);
		goto abort_boot;
	}

	rtk_info("Initializing (protocol version %d)\n", want_ver);
	rtk->version = want_ver;

	reply = FIELD_PREP(APPLE_RTKIT_MGMT_HELLO_MINVER, want_ver);
	reply |= FIELD_PREP(APPLE_RTKIT_MGMT_HELLO_MAXVER, want_ver);
	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_HELLO_REPLY, reply);

	return;

abort_boot:
	rtk->boot_result = -ENOTSUPP;
	complete_all(&rtk->epmap_completion);
}

static void apple_rtkit_management_rx_epmap(struct apple_rtkit *rtk, u64 msg)
{
	int i, ep;
	u64 reply;
	unsigned long bitmap = FIELD_GET(APPLE_RTKIT_MGMT_EPMAP_BITMAP, msg);
	u32 base = FIELD_GET(APPLE_RTKIT_MGMT_EPMAP_BASE, msg);

	rtk_dbg("received endpoint bitmap %lx with base %x\n", bitmap, base);

	for_each_set_bit (i, &bitmap, 32) {
		ep = 32 * base + i;
		rtk_dbg("Discovered endpoint 0x%02x\n", ep);
		set_bit(ep, rtk->endpoints);
	}

	reply = FIELD_PREP(APPLE_RTKIT_MGMT_EPMAP_BASE, base);
	if (msg & APPLE_RTKIT_MGMT_EPMAP_LAST)
		reply |= APPLE_RTKIT_MGMT_EPMAP_LAST;
	else
		reply |= APPLE_RTKIT_MGMT_EPMAP_REPLY_MORE;

	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_EPMAP_REPLY, reply);

	if (!(msg & APPLE_RTKIT_MGMT_EPMAP_LAST))
		return;

	for_each_set_bit (ep, rtk->endpoints, APPLE_RTKIT_APP_ENDPOINT_START) {
		switch (ep) {
		/* the management endpoint is started by default */
		case APPLE_RTKIT_EP_MGMT:
			break;

		/* without starting these RTKit refuses to boot */
		case APPLE_RTKIT_EP_SYSLOG:
		case APPLE_RTKIT_EP_CRASHLOG:
		case APPLE_RTKIT_EP_DEBUG:
		case APPLE_RTKIT_EP_IOREPORT:
		case APPLE_RTKIT_EP_OSLOG:
			rtk_dbg("Starting system endpoint 0x%02x\n", ep);
			apple_rtkit_start_ep(rtk, ep);
			break;

		default:
			rtk_warn("Unknown system endpoint: 0x%02x\n", ep);
		}
	}

	complete_all(&rtk->epmap_completion);
}

static void apple_rtkit_management_rx_iop_pwr_ack(struct apple_rtkit *rtk,
						  u64 msg)
{
	unsigned new_state = FIELD_GET(APPLE_RTKIT_MGMT_PWR_STATE, msg);

	rtk_dbg("IOP power state transition: 0x%x -> 0x%x\n",
		rtk->iop_power_state, new_state);
	rtk->iop_power_state = new_state;

	complete_all(&rtk->iop_pwr_ack_completion);
}

static void apple_rtkit_management_rx_ap_pwr_ack(struct apple_rtkit *rtk,
						 u64 msg)
{
	unsigned new_state = FIELD_GET(APPLE_RTKIT_MGMT_PWR_STATE, msg);

	rtk_dbg("AP power state transition: 0x%x -> 0x%x\n",
		rtk->ap_power_state, new_state);
	rtk->ap_power_state = new_state;

	complete_all(&rtk->ap_pwr_ack_completion);
}

static void apple_rtkit_management_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_MGMT_TYPE, msg);

	switch (type) {
	case APPLE_RTKIT_MGMT_HELLO:
		apple_rtkit_management_rx_hello(rtk, msg);
		break;
	case APPLE_RTKIT_MGMT_EPMAP:
		apple_rtkit_management_rx_epmap(rtk, msg);
		break;
	case APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE_ACK:
		apple_rtkit_management_rx_iop_pwr_ack(rtk, msg);
		break;
	case APPLE_RTKIT_MGMT_SET_AP_PWR_STATE_ACK:
		apple_rtkit_management_rx_ap_pwr_ack(rtk, msg);
		break;
	default:
		rtk_warn("unknown management message: 0x%llx (type: 0x%02x)\n",
			 msg, type);
	}
}

static int apple_rtkit_common_rx_get_buffer(struct apple_rtkit *rtk,
					    struct apple_rtkit_shmem *buffer,
					    u8 ep, u64 msg)
{
	size_t n_4kpages = FIELD_GET(APPLE_RTKIT_BUFFER_REQUEST_SIZE, msg);
	size_t size = n_4kpages << 12;
	dma_addr_t iova = FIELD_GET(APPLE_RTKIT_BUFFER_REQUEST_IOVA, msg);
	u64 reply;
	int err;

	rtk_dbg("buffer request for 0x%zx bytes at 0x%llx\n", size, iova);

	if (iova && (!rtk->ops->shmem_setup || !rtk->ops->shmem_destroy))
		return -EINVAL;

	if (rtk->ops->shmem_setup) {
		err = rtk->ops->shmem_setup(rtk->cookie, buffer, iova, size);
		if (err < 0)
			return err;
	} else {
		buffer->buffer =
			dma_alloc_coherent(rtk->dev, size, &iova, GFP_KERNEL);
		if (!buffer->buffer)
			return -ENOMEM;

		buffer->size = size;
		buffer->iova = iova;
	}

	if (!buffer->is_mapped) {
		reply = FIELD_PREP(APPLE_RTKIT_SYSLOG_TYPE,
				   APPLE_RTKIT_BUFFER_REQUEST);
		reply |= FIELD_PREP(APPLE_RTKIT_BUFFER_REQUEST_SIZE, n_4kpages);
		reply |= FIELD_PREP(APPLE_RTKIT_BUFFER_REQUEST_IOVA, buffer->iova);
		apple_rtkit_send_message(rtk, ep, reply);
	}

	return 0;
}

static void apple_rtkit_free_buffer(struct apple_rtkit *rtk,
				    struct apple_rtkit_shmem *bfr)
{
	if (bfr->size == 0)
		return;

	if (rtk->ops->shmem_destroy) {
		rtk->ops->shmem_destroy(rtk->cookie, bfr);
	} else if (bfr->buffer) {
		dma_free_coherent(rtk->dev, bfr->size, bfr->buffer, bfr->iova);
	}

	bfr->buffer = NULL;
	bfr->iomem = NULL;
	bfr->iova = 0;
	bfr->size = 0;
	bfr->is_mapped = false;
}

static void apple_rtkit_memcpy(struct apple_rtkit *rtk, void *dst,
			       struct apple_rtkit_shmem *bfr, size_t offset,
			       size_t len)
{
	if (bfr->iomem)
		memcpy_fromio(dst, bfr->iomem + offset, len);
	else
		memcpy(dst, bfr->buffer + offset, len);
}

static void apple_rtkit_crashlog_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_SYSLOG_TYPE, msg);
	u8 *bfr;

	if (type != APPLE_RTKIT_CRASHLOG_CRASH) {
		rtk_warn("Unknown crashlog message: %llx\n", msg);
		return;
	}

	if (!rtk->crashlog_buffer.size) {
		apple_rtkit_common_rx_get_buffer(rtk, &rtk->crashlog_buffer,
						 APPLE_RTKIT_EP_CRASHLOG, msg);
		return;
	}

	rtk_err("co-processor has crashed.\n");

	/*
	 * create a shadow copy here to make sure the co-processor isn't able
	 * to change the log while we're dumping it. this also ensures
	 * the buffer is in normal memory and not iomem for e.g. the SMC
	 */
	bfr = kzalloc(rtk->crashlog_buffer.size, GFP_KERNEL);
	if (bfr) {
		apple_rtkit_memcpy(rtk, bfr, &rtk->crashlog_buffer, 0,
				   rtk->crashlog_buffer.size);
		apple_rtkit_crashlog_dump(rtk, bfr, rtk->crashlog_buffer.size);
		kfree(bfr);
	} else {
		rtk_err("Couldn't allocate crashlog shadow buffer.");
	}

	rtk->crashed = true;
	if (rtk->ops->crashed)
		rtk->ops->crashed(rtk->cookie);
}

static void apple_rtkit_ioreport_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_SYSLOG_TYPE, msg);

	switch (type) {
	case APPLE_RTKIT_BUFFER_REQUEST:
		apple_rtkit_common_rx_get_buffer(rtk, &rtk->ioreport_buffer,
						 APPLE_RTKIT_EP_IOREPORT, msg);
		break;
	/* unknown, must be ACKed or the co-processor will hang */
	case 0x8:
	case 0xc:
		apple_rtkit_send_message(rtk, APPLE_RTKIT_EP_IOREPORT, msg);
		break;
	default:
		rtk_warn("Unknown ioreport message: %llx\n", msg);
	}
}

static void apple_rtkit_syslog_rx_init(struct apple_rtkit *rtk, u64 msg)
{
	rtk->syslog_n_entries = FIELD_GET(APPLE_RTKIT_SYSLOG_N_ENTRIES, msg);
	rtk->syslog_msg_size = FIELD_GET(APPLE_RTKIT_SYSLOG_MSG_SIZE, msg);

	rtk->syslog_msg_buffer = kzalloc(rtk->syslog_msg_size, GFP_KERNEL);

	rtk_dbg("syslog initialized: entries: %zd, msg_size: %zd\n",
		rtk->syslog_n_entries, rtk->syslog_msg_size);
}

static void apple_rtkit_syslog_rx_log(struct apple_rtkit *rtk, u64 msg)
{
	u8 idx = msg & 0xff;
	char log_context[24];
	size_t entry_size = 0x20 + rtk->syslog_msg_size;

	if (!rtk->syslog_buffer.size) {
		rtk_warn(
			"received syslog message but syslog_buffer.size is zero");
		goto done;
	}
	if (!rtk->syslog_buffer.buffer && !rtk->syslog_buffer.iomem) {
		rtk_warn("received syslog message but have no "
			 "syslog_buffer.buffer or syslog_buffer.iomem");
		goto done;
	}
	if (idx > rtk->syslog_n_entries) {
		rtk_warn("syslog index %d out of range", idx);
		goto done;
	}

	apple_rtkit_memcpy(rtk, log_context, &rtk->syslog_buffer,
			   idx * entry_size + 8, sizeof(log_context));
	apple_rtkit_memcpy(rtk, rtk->syslog_msg_buffer, &rtk->syslog_buffer,
			   idx * entry_size + 8 + sizeof(log_context),
			   rtk->syslog_msg_size);

	log_context[sizeof(log_context) - 1] = 0;
	rtk->syslog_msg_buffer[rtk->syslog_msg_size - 1] = 0;
	rtk_info("syslog message: %s: %s", log_context, rtk->syslog_msg_buffer);

done:
	apple_rtkit_send_message(rtk, APPLE_RTKIT_EP_SYSLOG, msg);
}

static void apple_rtkit_syslog_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_SYSLOG_TYPE, msg);

	switch (type) {
	case APPLE_RTKIT_BUFFER_REQUEST:
		apple_rtkit_common_rx_get_buffer(rtk, &rtk->syslog_buffer,
						 APPLE_RTKIT_EP_SYSLOG, msg);
		break;
	case APPLE_RTKIT_SYSLOG_INIT:
		apple_rtkit_syslog_rx_init(rtk, msg);
		break;
	case APPLE_RTKIT_SYSLOG_LOG:
		apple_rtkit_syslog_rx_log(rtk, msg);
		break;
	default:
		rtk_warn("Unknown syslog message: %llx\n", msg);
	}
}

static void apple_rtkit_oslog_rx_init(struct apple_rtkit *rtk, u64 msg)
{
	u64 ack;
	rtk_dbg("oslog init: msg: %llx\n", msg);

	ack = FIELD_PREP(APPLE_RTKIT_OSLOG_TYPE, APPLE_RTKIT_OSLOG_ACK);

	apple_rtkit_send_message(rtk, APPLE_RTKIT_EP_OSLOG, ack);
}

static void apple_rtkit_oslog_rx(struct apple_rtkit *rtk, u64 msg)
{
	u8 type = FIELD_GET(APPLE_RTKIT_OSLOG_TYPE, msg);

	switch (type) {
	case APPLE_RTKIT_OSLOG_INIT:
		apple_rtkit_oslog_rx_init(rtk, msg);
		break;
	default:
		rtk_warn("Unknown oslog message: %llx\n", msg);
	}
}

static void apple_rtkit_rx(struct apple_rtkit *rtk, struct apple_mbox_msg *msg)
{
	u8 ep = msg->msg1;

	if (!test_bit(ep, rtk->endpoints))
		rtk_warn("Message to undiscovered endpoint 0x%02x", ep);

	switch (ep) {
	case APPLE_RTKIT_EP_MGMT:
		apple_rtkit_management_rx(rtk, msg->msg0);
		break;
	case APPLE_RTKIT_EP_CRASHLOG:
		apple_rtkit_crashlog_rx(rtk, msg->msg0);
		break;
	case APPLE_RTKIT_EP_SYSLOG:
		apple_rtkit_syslog_rx(rtk, msg->msg0);
		break;
	case APPLE_RTKIT_EP_IOREPORT:
		apple_rtkit_ioreport_rx(rtk, msg->msg0);
		break;
	case APPLE_RTKIT_EP_OSLOG:
		apple_rtkit_oslog_rx(rtk, msg->msg0);
		break;
	case APPLE_RTKIT_APP_ENDPOINT_START ... 0xff:
		rtk->ops->recv_message(rtk->cookie, ep, msg->msg0);
		break;
	default:
		rtk_warn("message to unknown endpoint %02x: %llx\n", ep,
			 msg->msg0);
	}
}

static void apple_rtkit_do_reinit(struct apple_rtkit *rtk)
{
	apple_rtkit_free_buffer(rtk, &rtk->ioreport_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->crashlog_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->syslog_buffer);

	if (rtk->syslog_msg_buffer)
		kfree(rtk->syslog_msg_buffer);

	rtk->syslog_msg_buffer = NULL;
	rtk->syslog_n_entries = 0;
	rtk->syslog_msg_size = 0;

	bitmap_zero(rtk->endpoints, APPLE_RTKIT_MAX_ENDPOINTS);
	set_bit(APPLE_RTKIT_EP_MGMT, rtk->endpoints);

	reinit_completion(&rtk->epmap_completion);
	reinit_completion(&rtk->iop_pwr_ack_completion);
	reinit_completion(&rtk->ap_pwr_ack_completion);

	rtk->crashed = false;
	rtk->iop_power_state = APPLE_RTKIT_PWR_STATE_OFF;
	rtk->ap_power_state = APPLE_RTKIT_PWR_STATE_OFF;

	complete_all(&rtk->reinit_completion);
}

static int apple_rtkit_worker(void *data)
{
	struct apple_rtkit *rtk = data;
	struct apple_rtkit_work work;

	while (!kthread_should_stop()) {
		wait_event_interruptible(rtk->wq,
					 kfifo_len(&rtk->work_fifo) > 0 ||
					 kthread_should_stop());

		if (kthread_should_stop())
			break;

		while (kfifo_out_spinlocked(&rtk->work_fifo, &work, 1,
					    &rtk->work_lock) == 1) {
			switch (work.type) {
			case APPLE_RTKIT_WORK_MSG:
				apple_rtkit_rx(rtk, &work.msg);
				break;
			case APPLE_RTKIT_WORK_REINIT:
				apple_rtkit_do_reinit(rtk);
				break;
			}
		}
	}

	return 0;
}

static void apple_rtkit_rx_callback(struct mbox_client *cl, void *mssg)
{
	struct apple_rtkit *rtk = container_of(cl, struct apple_rtkit, mbox_cl);
	struct apple_mbox_msg *msg = mssg;
	struct apple_rtkit_work work;

	dma_rmb();

	memcpy(&work.msg, msg, sizeof(*msg));
	work.type = APPLE_RTKIT_WORK_MSG;

	kfifo_in_spinlocked(&rtk->work_fifo, &work, 1, &rtk->work_lock);
	wake_up(&rtk->wq);
}

int apple_rtkit_send_message(struct apple_rtkit *rtk, u8 ep, u64 message)
{
	struct apple_mbox_msg msg;

	if (rtk->crashed)
		return -EINVAL;
	if (ep >= APPLE_RTKIT_APP_ENDPOINT_START &&
	    !apple_rtkit_is_running(rtk))
		return -EINVAL;

	msg.msg0 = (u64)message;
	msg.msg1 = ep;
	dma_wmb();

	return mbox_send_message(rtk->mbox_chan, &msg);
}
EXPORT_SYMBOL_GPL(apple_rtkit_send_message);

int apple_rtkit_start_ep(struct apple_rtkit *rtk, u8 endpoint)
{
	u64 msg;

	if (!test_bit(endpoint, rtk->endpoints))
		return -EINVAL;
	if (endpoint >= APPLE_RTKIT_APP_ENDPOINT_START &&
	    !apple_rtkit_is_running(rtk))
		return -EINVAL;

	msg = FIELD_PREP(APPLE_RTKIT_MGMT_STARTEP_EP, endpoint);
	msg |= APPLE_RTKIT_MGMT_STARTEP_FLAG;
	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_STARTEP, msg);

	return 0;
}
EXPORT_SYMBOL_GPL(apple_rtkit_start_ep);

static int apple_rtkit_start_worker(struct apple_rtkit *rtk)
{
	rtk->task = kthread_run(apple_rtkit_worker, rtk, "%s-rtkit-worker",
				dev_name(rtk->dev));
	if (IS_ERR(rtk->task))
		return PTR_ERR(rtk->task);
	return 0;
}

struct apple_rtkit *apple_rtkit_init(struct device *dev, void *cookie,
				     const char *mbox_name, int mbox_idx,
				     const struct apple_rtkit_ops *ops)
{
	struct apple_rtkit *rtk;
	int ret;

	if (!ops)
		return ERR_PTR(-EINVAL);

	rtk = kzalloc(sizeof(*rtk), GFP_KERNEL);
	if (!rtk)
		return ERR_PTR(-ENOMEM);

	rtk->dev = dev;
	rtk->cookie = cookie;
	rtk->ops = ops;

	INIT_KFIFO(rtk->work_fifo);
	spin_lock_init(&rtk->work_lock);
	init_waitqueue_head(&rtk->wq);
	init_completion(&rtk->epmap_completion);
	init_completion(&rtk->reinit_completion);
	init_completion(&rtk->iop_pwr_ack_completion);
	init_completion(&rtk->ap_pwr_ack_completion);

	bitmap_zero(rtk->endpoints, APPLE_RTKIT_MAX_ENDPOINTS);
	set_bit(APPLE_RTKIT_EP_MGMT, rtk->endpoints);

	ret = apple_rtkit_start_worker(rtk);
	if (ret)
		return ERR_PTR(ret);

	rtk->mbox_cl.dev = dev;
	rtk->mbox_cl.tx_block = true;
	rtk->mbox_cl.knows_txdone = false;
	rtk->mbox_cl.rx_callback = &apple_rtkit_rx_callback;

	if (mbox_name)
		rtk->mbox_chan =
			mbox_request_channel_byname(&rtk->mbox_cl, mbox_name);
	else
		rtk->mbox_chan = mbox_request_channel(&rtk->mbox_cl, mbox_idx);

	if (IS_ERR(rtk->mbox_chan))
		return (struct apple_rtkit *)rtk->mbox_chan;

	return rtk;
}
EXPORT_SYMBOL_GPL(apple_rtkit_init);

static int apple_rtkit_wait_for_completion(struct completion *c)
{
	long t;

	t = wait_for_completion_interruptible_timeout(c,
						      msecs_to_jiffies(1000));
	if (t == -ERESTARTSYS)
		return t;
	else if (t == 0)
		return -ETIME;
	else
		return 0;
}

int apple_rtkit_reinit(struct apple_rtkit *rtk)
{
	struct apple_rtkit_work work;

	reinit_completion(&rtk->reinit_completion);

	work.type = APPLE_RTKIT_WORK_REINIT;
	kfifo_in_spinlocked(&rtk->work_fifo, &work, 1, &rtk->work_lock);
	wake_up(&rtk->wq);

	return apple_rtkit_wait_for_completion(&rtk->reinit_completion);
}
EXPORT_SYMBOL_GPL(apple_rtkit_reinit);

static int apple_rtkit_set_ap_power_state(struct apple_rtkit *rtk,
					  unsigned state)
{
	u64 msg;
	int ret;

	reinit_completion(&rtk->ap_pwr_ack_completion);

	msg = FIELD_PREP(APPLE_RTKIT_MGMT_PWR_STATE, state);
	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_SET_AP_PWR_STATE,
				    msg);

	ret = apple_rtkit_wait_for_completion(&rtk->ap_pwr_ack_completion);
	if (ret)
		return ret;

	if (rtk->ap_power_state != state)
		return -EINVAL;
	return 0;
}

static int apple_rtkit_set_iop_power_state(struct apple_rtkit *rtk,
					   unsigned state)
{
	u64 msg;
	int ret;

	reinit_completion(&rtk->iop_pwr_ack_completion);

	msg = FIELD_PREP(APPLE_RTKIT_MGMT_PWR_STATE, state);
	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE,
				    msg);

	ret = apple_rtkit_wait_for_completion(&rtk->iop_pwr_ack_completion);
	if (ret)
		return ret;

	if (rtk->iop_power_state != state)
		return -EINVAL;
	return 0;
}

int apple_rtkit_boot(struct apple_rtkit *rtk)
{
	int ret;

	if (apple_rtkit_is_running(rtk))
		return 0;
	if (rtk->crashed)
		return -EINVAL;

	rtk_dbg("waiting for boot to finish\n");
	ret = apple_rtkit_wait_for_completion(&rtk->epmap_completion);
	if (ret)
		return ret;
	if (rtk->boot_result)
		return rtk->boot_result;

	rtk_dbg("waiting for IOP power state ACK\n");
	ret = apple_rtkit_wait_for_completion(&rtk->iop_pwr_ack_completion);
	if (ret)
		return ret;

	return apple_rtkit_set_ap_power_state(rtk, APPLE_RTKIT_PWR_STATE_ON);
}
EXPORT_SYMBOL_GPL(apple_rtkit_boot);

int apple_rtkit_shutdown(struct apple_rtkit *rtk)
{
	int ret;

	/* if OFF is used here the co-processor will not wake up again */
	ret = apple_rtkit_set_ap_power_state(rtk,
					     APPLE_RTKIT_PWR_STATE_QUIESCED);
	if (ret)
		return ret;

	ret = apple_rtkit_set_iop_power_state(rtk, APPLE_RTKIT_PWR_STATE_SLEEP);
	if (ret)
		return ret;

	return apple_rtkit_reinit(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_shutdown);

int apple_rtkit_hibernate(struct apple_rtkit *rtk)
{
	int ret;

	ret = apple_rtkit_set_ap_power_state(rtk,
					     APPLE_RTKIT_PWR_STATE_QUIESCED);
	if (ret)
		return ret;

	ret = apple_rtkit_set_iop_power_state(rtk,
					      APPLE_RTKIT_PWR_STATE_QUIESCED);
	if (ret)
		return ret;

	ret = apple_rtkit_reinit(rtk);
	if (ret)
		return ret;

	// TODO: apple_rtkit_reinit resets these so we have to restore them here :/
	rtk->iop_power_state = APPLE_RTKIT_PWR_STATE_QUIESCED;
	rtk->ap_power_state = APPLE_RTKIT_PWR_STATE_QUIESCED;
	return 0;
}
EXPORT_SYMBOL_GPL(apple_rtkit_hibernate);

int apple_rtkit_wake(struct apple_rtkit *rtk)
{
	u64 msg;

	if (apple_rtkit_is_running(rtk))
		return -EINVAL;

	reinit_completion(&rtk->iop_pwr_ack_completion);

	/*
	 * Use open-coded apple_rtkit_set_iop_power_state since apple_rtkit_boot
	 * will wait for the completion anyway.
	 */
	msg = FIELD_PREP(APPLE_RTKIT_MGMT_PWR_STATE, APPLE_RTKIT_PWR_STATE_ON);
	apple_rtkit_management_send(rtk, APPLE_RTKIT_MGMT_SET_IOP_PWR_STATE,
				    msg);

	return apple_rtkit_boot(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_wake);

void apple_rtkit_free(struct apple_rtkit *rtk)
{
	kthread_stop(rtk->task);
	mbox_free_channel(rtk->mbox_chan);

	apple_rtkit_free_buffer(rtk, &rtk->ioreport_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->crashlog_buffer);
	apple_rtkit_free_buffer(rtk, &rtk->syslog_buffer);

	if (rtk->syslog_msg_buffer)
		kfree(rtk->syslog_msg_buffer);

	kfree(rtk);
}
EXPORT_SYMBOL_GPL(apple_rtkit_free);

struct apple_rtkit *devm_apple_rtkit_init(struct device *dev, void *cookie,
					  const char *mbox_name, int mbox_idx,
					  const struct apple_rtkit_ops *ops)
{
	struct apple_rtkit *rtk;
	int ret;

	rtk = apple_rtkit_init(dev, cookie, mbox_name, mbox_idx, ops);
	if (IS_ERR(rtk))
		return rtk;

	ret = devm_add_action_or_reset(dev, (void (*)(void *))apple_rtkit_free,
				       rtk);
	if (ret)
		return ERR_PTR(ret);

	return rtk;
}
EXPORT_SYMBOL_GPL(devm_apple_rtkit_init);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Sven Peter <sven@svenpeter.dev>");
MODULE_DESCRIPTION("Apple RTKit driver");
