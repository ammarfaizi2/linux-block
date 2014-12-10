/*
 * FIDO Alliance U2F driver
 *
 * Copyright (c) 2014 Andy Lutomirski
 */

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <linux/types.h>
#include <linux/device.h>
#include <linux/input.h>
#include <linux/hid.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include "hid-ids.h"

#define U2FHID_FRAME_TYPE_MASK	0x80
#define U2FHID_FRAME_TYPE_INIT	0x80
#define U2FHID_FRAME_TYPE_CONT	0x00

#define U2FHID_CMD_INIT		0x06

#define U2FHID_REPORT_SIZE	64

struct u2fhid_header {
	u8 channel_id[4];
	u8 type;
} __packed;

struct u2fhid_frame {
	u8 channel_id[4];

	/*
	 * If the high bit is set, this is an INIT (initial) frame.  If not,
	 * then this is a CONT (continuation) frame.
	 */
	u8 type;
	union {
		struct {
			__be16 len;
			u8 data[U2FHID_REPORT_SIZE - 7];
		} __packed init;

		struct {
			u8 data[U2FHID_REPORT_SIZE - 5];
		} __packed cont;
	} __packed;
} __packed;

struct u2fhid_init_req {
	u8 nonce[8];
} __packed;

struct u2fhid_init_resp {
	u8 nonce[8];
	u8 channel_id[4];
	u8 u2fhid_version;
	u8 major_device_version;
	u8 minor_device_version;
	u8 build_device_version;
	u8 capflags;
};

struct u2f {
	u8 channel_id[4];

	spinlock_t lock;

	wait_queue_head_t wq;

	/* Any change due to data from the device will wake wq. */
	int is_receiving;

	/* Valid iff is_receiving. */
	struct u2f_recv {
		void *buffer;	/* NULL if the receive has been abandoned. */
		size_t buffer_len;

		bool got_first;
		size_t total_len;
		size_t len_received;
		u8 response_type;	/* only if got_first */

		bool check_nonce;
		u8 nonce[8];
	} recv;
};

/*
static struct class *u2f_class;

static const struct attribute_group *u2f_groups[] = {
	NULL,
};
*/

static int u2f_sendrecv(struct hid_device *hdev, struct u2f *u2f,
			u8 cmd, const void *out, int outlen,
			void *in, int inlen)
{
	int ret;
	struct {
		u8 reportnum;
		struct u2fhid_frame frame;
	} __packed frame;

	BUILD_BUG_ON(sizeof(struct u2fhid_frame) != U2FHID_REPORT_SIZE);
	BUILD_BUG_ON(sizeof(frame) != U2FHID_REPORT_SIZE + 1);

	memset(&frame, 0, sizeof(frame));
	memcpy(frame.frame.channel_id, u2f->channel_id, 4);
	frame.frame.type = cmd | U2FHID_FRAME_TYPE_INIT;
	frame.frame.init.len = cpu_to_be16(outlen);
	memcpy(frame.frame.init.data, out, outlen);

	// TODO: Handle send fragmentation

	//print_hex_dump(KERN_ERR, "u2f: ", DUMP_PREFIX_OFFSET,
	//	       16, 1, &frame, sizeof(frame), 0);

	spin_lock_irq(&u2f->lock);

	ACCESS_ONCE(u2f->is_receiving) = 1;
	memset(&u2f->recv, 0, sizeof(u2f->recv));
	u2f->recv.buffer = in;
	u2f->recv.buffer_len = inlen;

	BUG_ON(!ACCESS_ONCE(u2f->is_receiving));

	spin_unlock_irq(&u2f->lock);

	ret = hid_hw_output_report(hdev, (u8 *)&frame, sizeof(frame));
	if (ret < 0) {
		dev_err(&hdev->dev, "send failed");
		return ret;
	}

	wait_event_interruptible(u2f->wq, !ACCESS_ONCE(u2f->is_receiving));

	spin_lock_irq(&u2f->lock);
	u2f->recv.buffer = NULL;
	ret = u2f->recv.total_len;
	spin_unlock_irq(&u2f->lock);

	return ret;
}

static int u2f_init_channel(struct hid_device *hdev, struct u2f *u2f)
{
	int ret;
	struct u2fhid_init_req initreq;
	struct u2fhid_init_resp initresp;

	/* Until we are assigned a channel, use 0xffffffff. */
	memset(u2f->channel_id, 0xff, sizeof(u2f->channel_id));
	
	get_random_bytes(initreq.nonce, sizeof(initreq.nonce));

	ret = u2f_sendrecv(hdev, u2f, U2FHID_CMD_INIT,
			   &initreq, sizeof(initreq),
			   &initresp, sizeof(initresp));
	if (ret < 0)
		return ret;
	if (ret < sizeof(struct u2fhid_init_resp)) {
		dev_err(&hdev->dev, "U2FHID_INIT response was too short\n");
		return -EIO;
	}
	if (memcmp(initresp.nonce, initreq.nonce, sizeof(initreq.nonce))) {
		/*
		 * This indicates a race against a hidraw user.  We could
		 * add code to survive the race, but the race is unlikely,
		 * so just bail if it happens.
		 */
		dev_err(&hdev->dev, "U2FHID_INIT nonce mismatch\n");
		return -EIO;
	}

	memcpy(u2f->channel_id, &initresp.channel_id, sizeof(u2f->channel_id));

	dev_info(&hdev->dev, "U2FHID v%d, device v%d.%d.%d, caps 0x%x\n",
		 (int)initresp.u2fhid_version,
		 (int)initresp.major_device_version,
		 (int)initresp.minor_device_version,
		 (int)initresp.build_device_version,
		 (int)initresp.capflags);

	return 0;
}

static int u2f_probe(struct hid_device *hdev,
		const struct hid_device_id *id)
{
	int retval;
	struct u2f *u2f;

	retval = hid_parse(hdev);
	if (retval) {
		hid_err(hdev, "parse failed\n");
		goto exit;
	}

	/*
	 * U2F isn't an input device, and it uses raw reports, so trying
	 * to access it with hiddev makes no sense.
	 */
	retval = hid_hw_start(hdev, HID_CONNECT_DRIVER | HID_CONNECT_HIDRAW);
	if (retval) {
		hid_err(hdev, "hw start failed\n");
		goto exit;
	}

	u2f = devm_kzalloc(&hdev->dev, sizeof(*u2f), GFP_KERNEL);
	if (!u2f) {
		retval = -ENOMEM;
		goto exit_stop;
	}

	spin_lock_init(&u2f->lock);
	init_waitqueue_head(&u2f->wq);

	hid_set_drvdata(hdev, u2f);

	hid_device_io_start(hdev);
	retval = hid_hw_open(hdev);
	if (retval) {
		dev_err(&hdev->dev, "failed to open device");
		goto exit_stop;
	}

	retval = u2f_init_channel(hdev, u2f);
	if (retval != 0)
		goto exit_close;

	return 0;

exit_close:
	hid_hw_close(hdev);
	hid_device_io_stop(hdev);
exit_stop:
	hid_hw_stop(hdev);
exit:
	return retval;
}

static void u2f_remove(struct hid_device *hdev)
{
	hid_hw_close(hdev);
	hid_hw_stop(hdev);
}

static int u2f_raw_event(struct hid_device *hdev,
			 struct hid_report *report, u8 *data, int size)
{
	struct u2f *u2f = hid_get_drvdata(hdev);
	struct u2fhid_header *header;
	unsigned long flags;
	void *payload;
	size_t payload_len;
	
	//dev_info(&hdev->dev, "Got %d bytes\n", size);

	//print_hex_dump(KERN_ERR, "resp: ", DUMP_PREFIX_OFFSET,
	//	       16, 1, data, size, 0);

	if (size < sizeof(struct u2fhid_header))
		return 0;

	spin_lock_irqsave(&u2f->lock, flags);

	if (!u2f->is_receiving)
		goto out;

	header = (struct u2fhid_header *)data;
	if (memcmp(header->channel_id, u2f->channel_id, 4) != 0)
		goto out;

	/* Handle the frame header. */
	if (!u2f->recv.got_first) {
		if ((header->type & U2FHID_FRAME_TYPE_MASK) !=
		    U2FHID_FRAME_TYPE_INIT) {
			dev_err(&hdev->dev, "got continuation instead of init\n");
			/* XXX: error out? */
			goto out;
		}

		if (size < sizeof(struct u2fhid_header) + 2) {
			dev_err(&hdev->dev, "got short frame\n");
			goto out;
		}

		u2f->recv.response_type =
			header->type & ~U2FHID_FRAME_TYPE_MASK;
		u2f->recv.total_len =
			be16_to_cpu(*(__be16*)(header + 1));
		u2f->recv.got_first = true;

		payload = data + (sizeof(struct u2fhid_header) + 2);
		payload_len = size - (sizeof(struct u2fhid_header) + 2);
	} else {
		if (header->type !=
		    (u2f->recv.response_type | U2FHID_FRAME_TYPE_CONT)) {
			dev_err(&hdev->dev, "bad continuation\n");
			goto out;
		}

		payload = header + 1;
		payload_len = size - sizeof(struct u2fhid_header);
	}

	/* Truncate excess data. */
	if (payload_len > u2f->recv.total_len - u2f->recv.len_received)
		payload_len = u2f->recv.total_len - u2f->recv.len_received;

	/* Store the payload, if appropriate. */
	if (u2f->recv.buffer && u2f->recv.len_received < u2f->recv.buffer_len) {
		memcpy(u2f->recv.buffer + u2f->recv.len_received,
		       payload,
		       min(payload_len,
			   u2f->recv.buffer_len - u2f->recv.len_received));
	}
	u2f->recv.len_received += payload_len;

	if (u2f->recv.len_received == u2f->recv.total_len) {
		ACCESS_ONCE(u2f->is_receiving) = 0;
		wake_up_all(&u2f->wq);
	}
	
out:
	spin_unlock_irqrestore(&u2f->lock, flags);
	
	return 0;
}

static const struct hid_device_id u2f_devices[] = {
	{ HID_DEVICE(HID_BUS_ANY, HID_GROUP_FIDO_U2F, HID_ANY_ID, HID_ANY_ID) },
	{ }
};

MODULE_DEVICE_TABLE(hid, u2f_devices);

static struct hid_driver u2f_driver = {
		.name = "u2f",
		.id_table = u2f_devices,
		.probe = u2f_probe,
		.remove = u2f_remove,
		.raw_event = u2f_raw_event
};

static int __init u2f_init(void)
{
	int retval;

	/*
	u2f_class = class_create(THIS_MODULE, "u2f");
	if (IS_ERR(u2f_class))
		return PTR_ERR(u2f_class);
	u2f_class->dev_groups = u2f_groups;
	*/

	retval = hid_register_driver(&u2f_driver);
	/*
	if (retval)
		class_destroy(u2f_class);
	*/
	return retval;
}

static void __exit u2f_exit(void)
{
	hid_unregister_driver(&u2f_driver);
	//class_destroy(u2f_class);
}

module_init(u2f_init);
module_exit(u2f_exit);

MODULE_AUTHOR("Andy Lutomirski");
MODULE_DESCRIPTION("FIDO U2F HID Driver");
MODULE_LICENSE("GPL v2");
