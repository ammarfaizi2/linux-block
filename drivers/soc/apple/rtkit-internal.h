#ifndef _APPLE_RTKIT_INTERAL_H
#define _APPLE_RTKIT_INTERAL_H

#include <linux/apple-mailbox.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/kthread.h>
#include <linux/kfifo.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/wait.h>

#define rtk_err(format, arg...) dev_err(rtk->dev, "RTKit: " format, ##arg)
#define rtk_warn(format, arg...) dev_warn(rtk->dev, "RTKit: " format, ##arg)
#define rtk_info(format, arg...) dev_info(rtk->dev, "RTKit: " format, ##arg)
#define rtk_dbg(format, arg...) dev_dbg(rtk->dev, "RTKit: " format, ##arg)


#define APPLE_RTKIT_APP_ENDPOINT_START 0x20
#define APPLE_RTKIT_MAX_ENDPOINTS 0x100

struct apple_rtkit_work {
	unsigned type;
	struct apple_mbox_msg msg;
};

struct apple_rtkit {
	void *cookie;
	const struct apple_rtkit_ops *ops;
	struct device *dev;
	struct mbox_client mbox_cl;
	struct mbox_chan *mbox_chan;

	struct completion epmap_completion;
	struct completion reinit_completion;
	struct completion iop_pwr_ack_completion;
	struct completion ap_pwr_ack_completion;

	int boot_result;
	int version;

	unsigned iop_power_state;
	unsigned ap_power_state;
	bool crashed;

	struct task_struct *task;

	struct wait_queue_head wq;
	DECLARE_KFIFO(work_fifo, struct apple_rtkit_work, 64);
	spinlock_t work_lock;

	DECLARE_BITMAP(endpoints, APPLE_RTKIT_MAX_ENDPOINTS);

	struct apple_rtkit_shmem ioreport_buffer;
	struct apple_rtkit_shmem crashlog_buffer;

	struct apple_rtkit_shmem syslog_buffer;
	char *syslog_msg_buffer;
	size_t syslog_n_entries;
	size_t syslog_msg_size;
};

void apple_rtkit_crashlog_dump(struct apple_rtkit *rtk, u8 *bfr, size_t size);

#endif
