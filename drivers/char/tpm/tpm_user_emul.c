/* TPM userspace emulation driver
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "TPM_USER: "fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include "tpm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Howells <dhowells@redhat.com>");

#define TIS_SHORT_TIMEOUT 750	/* ms */
#define TIS_LONG_TIMEOUT 2000	/* 2 sec */

#define kenter(FMT, ...) \
	pr_devel("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_devel("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

/*
 * Packet of data going to/from the TPM.  We only permit one command
 * at a time, so we don't need to deal with chains of packets.
 */
struct tpm_user_packet {
	unsigned	size;
	unsigned	cancellation;
	u8		buffer[];
};

/*
 * Emulator state.
 */
enum tpm_user_status {
	TPM_USER_INITIALISING,
	TPM_USER_IDLE,
	TPM_USER_SENDING,
	TPM_USER_AWAITING_REPLY,
	TPM_USER_CANCELLING,
	TPM_USER_GOT_REPLY,
	TPM_USER_CANCELLED,
	TPM_USER_EIO,
};

struct tpm_user_state {
	struct work_struct	initialiser_work;
	struct completion	initialiser_done;
	struct file		*file;
	struct platform_device	*pdev;
	struct tpm_chip		*chip;
	wait_queue_head_t	wq;
	struct tpm_user_packet	*to_emulator_q;
	struct tpm_user_packet	*from_emulator_q;
	spinlock_t		lock;
	enum tpm_user_status	status;
	int			initialiser_error;
};

/*
 * Read the emulator status.
 */
static u8 tpm_user_status(struct tpm_chip *chip)
{
	struct tpm_user_state *state = chip->vendor.priv;
	enum tpm_user_status status = ACCESS_ONCE(state->status);

	if (status == TPM_USER_GOT_REPLY)
		return 1;
	if (status == TPM_USER_CANCELLED ||
	    status == TPM_USER_EIO)
		return 2;
	return 0;
}

/*
 * Find out if a request has been cancelled.
 */
static bool tpm_user_is_req_cancelled(struct tpm_chip *chip, u8 status)
{
	struct tpm_user_state *state = chip->vendor.priv;
	struct tpm_user_packet *pkt = NULL;

	if (status != 2)
		return false;

	spin_lock(&state->lock);
	if (state->status == TPM_USER_CANCELLED) {
		pkt = state->from_emulator_q;
		state->from_emulator_q = NULL;
		state->status = TPM_USER_IDLE;
	}
	spin_unlock(&state->lock);
	kfree(pkt);
	return true;
}

/*
 * Send data to the emulator.
 */
static int tpm_user_send(struct tpm_chip *chip, u8 *buf, size_t len)
{
	struct tpm_user_state *state = chip->vendor.priv;
	struct tpm_user_packet *pkt;
	int ret;

	kenter(",%*phN,%zu", min_t(int, len, 16), buf, len);

	pkt = kmalloc(sizeof(struct tpm_user_packet) + len, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;
	pkt->size = len;
	memcpy(pkt->buffer, buf, len);

	spin_lock(&state->lock);
	switch (state->status) {
	case TPM_USER_IDLE:
		state->to_emulator_q = pkt;
		state->status = TPM_USER_SENDING;
		ret = 0;
		break;
	default:
		dev_err(chip->dev, "Sending in state %u\n", state->status);
	case TPM_USER_EIO:
		kfree(pkt);
		ret = -EIO;
		break;
	}
	spin_unlock(&state->lock);
	if (ret == 0)
		wake_up(&state->wq);
	return ret;
}

/*
 * Allow the TPM emulator to read requests from the driver
 */
static ssize_t tpm_user_read(struct file *file, char __user *buffer,
			     size_t buflen, loff_t *pos)
{
	struct tpm_user_state *state = file->private_data;
	struct tpm_user_packet *pkt;
	unsigned long copied;
	ssize_t ret;

	kenter("{%u},,%zu,", state->status, buflen);

again:
	mutex_lock(&file_inode(file)->i_mutex);

	ret = -EAGAIN;
	spin_lock(&state->lock);
	if (state->status == TPM_USER_EIO) {
		ret = -EIO;
		goto out;
	}

	if (state->status != TPM_USER_SENDING) {
		if (file->f_flags & O_NONBLOCK)
			goto out;
		pr_devel("sleeping\n");
		wait_event_cmd_interruptible(
			state->wq,
			state->status == TPM_USER_SENDING ||
			state->status == TPM_USER_EIO,
			spin_unlock(&state->lock),
			spin_lock(&state->lock));
		pr_devel("woken\n");

		ret = -ERESTARTSYS;
		if (signal_pending(current))
			goto out;
		ret = -EIO;
		if (state->status == TPM_USER_EIO)
			goto out;
	}

	pkt = state->to_emulator_q;
	pr_devel("dequeued send(%u)\n", pkt->size);
	ret = -EMSGSIZE;
	if (pkt->size > buflen)
		goto out;

	/* Claim responsibility for the packet. */
	state->status = TPM_USER_AWAITING_REPLY;
	state->to_emulator_q = NULL;
	spin_unlock(&state->lock);

	copied = copy_to_user(buffer, pkt->buffer, pkt->size);
	spin_lock(&state->lock);

	if (copied != 0) {
		/* Ugh - the emulator went splat.  Discard the request and
		 * reject all further requests. */
		kfree(pkt);
		dev_err(state->chip->dev, "Emulator EFAULT in read\n");
		state->status = TPM_USER_EIO;
		ret = -EFAULT;
	} else if (state->status == TPM_USER_CANCELLING) {
		pr_devel("cancel\n");
		state->status = TPM_USER_CANCELLED;
		ret = -ECANCELED;
	} else {
		ret = pkt->size;
	}

out:
	spin_unlock(&state->lock);
	mutex_unlock(&file_inode(file)->i_mutex);
	if (ret == -ECANCELED)
		goto again;
	kleave(" = %zd", ret);
	return ret;
}

/*
 * Allow the TPM emulator to respond to requests
 *
 * The buffer is should contain a packet with at least TPM_HEADER_SIZE bytes of
 * data in it.
 */
static ssize_t tpm_user_write(struct file *file,
			      const char __user *data,
			      size_t datalen,
			      loff_t *pos)
{
	struct tpm_user_state *state = file->private_data;
	struct tpm_user_packet *pkt;
	unsigned expected;
	__be32 tmpbe;
	ssize_t ret;

	kenter("{%u},,%zu,", state->status, datalen);

	/* Sanity checking the reply before we get any locks. */
	if (datalen == 0) {
		dev_err(state->chip->dev, "Empty reply\n");
		return -EMSGSIZE;
	}

	if (datalen < TPM_HEADER_SIZE) {
		dev_err(state->chip->dev, "Data packet missing TPM header\n");
		return -EMSGSIZE;
	}

	pkt = kmalloc(sizeof(struct tpm_user_packet) + datalen, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;
	pkt->size = datalen;
	ret = -EFAULT;
	if (copy_from_user(pkt->buffer, data, datalen) != 0)
		goto err_free;

	pr_debug("got reply %*phN\n", min_t(int, datalen, 16), pkt->buffer);

	memcpy(&tmpbe, pkt->buffer + 2, sizeof(tmpbe));
	expected = be32_to_cpu(tmpbe);
	if (expected != datalen) {
		dev_err(state->chip->dev, "Data packet size (%zu) != expected (%x)\n",
			datalen, expected);
		ret = -EMSGSIZE;
		goto err_free;
	}

	mutex_lock(&file_inode(file)->i_mutex);
	spin_lock(&state->lock);

	switch (state->status) {
	case TPM_USER_AWAITING_REPLY:
		BUG_ON(state->from_emulator_q != NULL);
		state->from_emulator_q = pkt;
		state->status = TPM_USER_GOT_REPLY;
		pkt = NULL;
		ret = datalen;
		break;

	case TPM_USER_CANCELLING:
		state->status = TPM_USER_CANCELLED;
		ret = -ECANCELED;
		break;

	case TPM_USER_EIO:
		ret = -EIO;
		break;

	default:
		dev_err(state->chip->dev, "Reply unexpected in state (%u)\n",
			state->status);
		ret = -EPROTO;
		break;
	}

	spin_unlock(&state->lock);
	mutex_unlock(&file_inode(file)->i_mutex);
	if (ret != -EPROTO)
		wake_up(&state->wq);
err_free:
	kfree(pkt);
	kleave(" = %zd", ret);
	return ret;
}

/*
 * Allow the TPM emulator to cancel a request with ioctl(fd,0,0).
 */
static long tpm_user_ioctl(struct file *file, unsigned cmd, unsigned long data)
{
	struct tpm_user_state *state = file->private_data;
	long ret;

	kenter("{%u},%x,%lx", state->status, cmd, data);

	if (cmd != 0 && data != 0)
		return -ENOIOCTLCMD;

	mutex_lock(&file_inode(file)->i_mutex);
	spin_lock(&state->lock);

	switch (state->status) {
	case TPM_USER_AWAITING_REPLY:
	case TPM_USER_CANCELLING:
		state->status = TPM_USER_CANCELLED;
		ret = 0;
		break;

	case TPM_USER_EIO:
		ret = -EIO;
		break;

	default:
		dev_err(state->chip->dev,
			"Cancellation unexpected in state (%u)\n",
			state->status);
		ret = -EPROTO;
		break;
	}

	spin_unlock(&state->lock);
	mutex_unlock(&file_inode(file)->i_mutex);
	wake_up(&state->wq);
	kleave(" = %ld", ret);
	return ret;
}

/*
 * Receive data from the emulator.
 */
static int tpm_user_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
	struct tpm_user_state *state = chip->vendor.priv;
	struct tpm_user_packet *pkt;
	int ret;

	kenter("{%u},,%zu", state->status, count);

	spin_lock(&state->lock);

	pkt = state->from_emulator_q;
	state->from_emulator_q = NULL;
	switch (state->status) {
	case TPM_USER_GOT_REPLY:
		state->status = TPM_USER_IDLE;
		BUG_ON(!pkt);
		ret = pkt->size;
		break;

	case TPM_USER_CANCELLED:
		state->status = TPM_USER_IDLE;
		ret = -ECANCELED;
		break;

	case TPM_USER_EIO:
		ret = -EIO;
		break;

	default:
		dev_err(chip->dev, "TPM data recv in unexpected state (%u)\n",
			state->status);
		ret = -EIO;
		break;
	}

	spin_unlock(&state->lock);

	if (pkt) {
		if (ret > 0) {
			if (pkt->size > count) {
				dev_err(chip->dev, "Received excess data\n");
				ret = -EIO;
			} else {
				memcpy(buf, pkt->buffer, pkt->size);
			}
		}
		kfree(pkt);
	}

	kleave(" = %d", ret);
	return ret;
}

/*
 * Abort the current request.
 */
static void tpm_user_cancel(struct tpm_chip *chip)
{
	struct tpm_user_state *state = chip->vendor.priv;

	kenter("{%u}", state->status);

	spin_lock(&state->lock);

	switch (state->status) {
	case TPM_USER_SENDING:
	case TPM_USER_AWAITING_REPLY:
	case TPM_USER_GOT_REPLY:
		kfree(state->to_emulator_q);
		state->to_emulator_q = NULL;
		kfree(state->from_emulator_q);
		state->from_emulator_q = NULL;
		state->status = TPM_USER_CANCELLING;
		break;
	default:
		break;
	}

	if (state->status == TPM_USER_CANCELLING) {
		DECLARE_WAITQUEUE(waiter, current);

		for (;;) {
			prepare_to_wait(&state->wq,
					&waiter, TASK_UNINTERRUPTIBLE);
			if (state->status == TPM_USER_CANCELLED ||
			    state->status == TPM_USER_EIO)
				break;
			spin_unlock(&state->lock);
			schedule_timeout(10 * HZ);
			spin_lock(&state->lock);
		}
		finish_wait(&state->wq, &waiter);

		if (state->status != TPM_USER_CANCELLED)
			state->status = TPM_USER_EIO;
		else
			state->status = TPM_USER_IDLE;
	}

	spin_unlock(&state->lock);
}

/*
 * Allow the TPM emulator to wait for a request
 */
static unsigned int tpm_user_poll(struct file *file,
				  struct poll_table_struct *poll)
{
	struct tpm_user_state *state = file->private_data;
	enum tpm_user_status status = ACCESS_ONCE(state->status);
	unsigned mask;

	poll_wait(file, &state->wq, poll);
	mask = 0;

	switch (status) {
	case TPM_USER_SENDING:
		return POLLIN;
	case TPM_USER_AWAITING_REPLY:
		return POLLOUT;
	case TPM_USER_CANCELLING:
		return POLLPRI;
	case TPM_USER_EIO:
		return POLLERR;
	default:
		return 0;
	}
}

static const struct tpm_class_ops tpm_user_class = {
	.status			= tpm_user_status,
	.recv			= tpm_user_recv,
	.send			= tpm_user_send,
	.cancel			= tpm_user_cancel,
	.req_complete_mask	= 1,
	.req_complete_val	= 1,
	.req_canceled		= tpm_user_is_req_cancelled,
};

/*
 * Asynchronous initialiser.  We have to do it this way because we get timeouts
 * and run a selftest on the TPM - which means doing reads and writes on the
 * file.
 */
static void tpm_user_initialiser(struct work_struct *work)
{
	struct tpm_user_state *state =
		container_of(work, struct tpm_user_state, initialiser_work);
	struct platform_device *pdev;
	struct tpm_chip *chip;
	int ret = -ENODEV;

	kenter("");

	pdev = platform_device_register_simple("tpm_user", -1, NULL, 0);
	if (IS_ERR(pdev)) {
		ret = PTR_ERR(pdev);
		goto err_dev;
	}
	state->pdev = pdev;

	pr_devel("Registering TPM\n");

	ret = -ENODEV;
	chip = tpm_register_hardware(&pdev->dev, &tpm_user_class);
	if (!chip)
		goto err_reg;

	chip->vendor.priv = state;
	init_waitqueue_head(&chip->vendor.read_queue);
	init_waitqueue_head(&chip->vendor.int_queue);
	INIT_LIST_HEAD(&chip->vendor.list);
	state->chip = chip;

	/* Default timeouts */
	chip->vendor.timeout_a = msecs_to_jiffies(TIS_SHORT_TIMEOUT);
	chip->vendor.timeout_b = msecs_to_jiffies(TIS_LONG_TIMEOUT);
	chip->vendor.timeout_c = msecs_to_jiffies(TIS_SHORT_TIMEOUT);
	chip->vendor.timeout_d = msecs_to_jiffies(TIS_SHORT_TIMEOUT);

	/* We will need to operate the communication channel */
	spin_lock(&state->lock);
	ret = -EIO;
	if (state->status == TPM_USER_EIO)
		goto err_tpm_locked;
	state->status = TPM_USER_IDLE;
	spin_unlock(&state->lock);

	/* Not all variants of the emulator support getting the timeout */
	pr_devel("Getting timeouts\n");
	if (tpm_get_timeouts(chip))
		dev_err(&pdev->dev, "Could not get TPM timeouts and durations\n");

	pr_devel("Performing selftest\n");
	ret = tpm_do_selftest(chip);
	if (ret < 0) {
		dev_err(&pdev->dev, "TPM self test failed\n");
		goto err_tpm;
	}

	ret = 0;
out:
	state->initialiser_error = ret;
	kleave(" = %d", ret);
	complete(&state->initialiser_done);
	return;

err_tpm:
	spin_lock(&state->lock);
	if (state->status != TPM_USER_EIO)
		state->status = TPM_USER_EIO;
err_tpm_locked:
	spin_unlock(&state->lock);
	wake_up(&state->wq);
	tpm_remove_hardware(chip->dev);
err_reg:
	platform_device_unregister(pdev);
err_dev:
	goto out;
}

/*
 * Allow the TPM emulator to create a virtual TPM.
 */
static int tpm_user_open(struct inode *inode, struct file *file)
{
	struct tpm_user_state *state;

	kenter("");

	state = kzalloc(sizeof(struct tpm_user_state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	state->file = file;
	state->status = TPM_USER_INITIALISING;
	spin_lock_init(&state->lock);
	INIT_WORK(&state->initialiser_work, tpm_user_initialiser);
	init_completion(&state->initialiser_done);
	init_waitqueue_head(&state->wq);

	file->private_data = state;

	/* The TPM registration must be done in another thread because the the
	 * process will involve self-testing the TPM and will thus need to
	 * communicate through this file.
	 */
	schedule_work(&state->initialiser_work);
	kleave(" = 0");
	return 0;
}

/*
 * Release and clean up a virtual TPM.
 */
static int tpm_user_release(struct inode *inode, struct file *file)
{
	struct tpm_user_state *state = file->private_data;
	int ret;

	kenter("");

	pr_devel("forcing EIO state\n");
	spin_lock(&state->lock);
	state->status = TPM_USER_EIO;
	spin_unlock(&state->lock);
	wake_up(&state->wq);

	wait_for_completion(&state->initialiser_done);

	ret = state->initialiser_error;
	if (ret == 0) {
		pr_devel("removing bits\n");
		tpm_remove_hardware(state->chip->dev);
		platform_device_unregister(state->pdev);
	}
	kfree(state->to_emulator_q);
	kfree(state->from_emulator_q);
	kfree(state);
	kleave(" = %d", ret);
	return ret;
}

static const struct file_operations tpm_user_fops = {
	.owner		= THIS_MODULE,
	.open		= tpm_user_open,
	.release	= tpm_user_release,
	.read		= tpm_user_read,
	.write		= tpm_user_write,
	.unlocked_ioctl	= tpm_user_ioctl,
	.poll		= tpm_user_poll,
	.llseek		= noop_llseek,
};

static struct miscdevice tpm_user_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "tpm_emul",
	.fops	= &tpm_user_fops,
};

static struct platform_driver tpm_user_drv = {
	.driver = {
		.name	= "tpm_user",
		.owner	= THIS_MODULE,
		/* .pm	= &tpm_user_pm, -- do we need pm since there's no h/w? */
	},
};

/*
 * Initialise a device
 */
static __init int tpm_user_mod_init(void)
{
	int ret;

	ret = platform_driver_register(&tpm_user_drv);
	if (ret < 0)
		return ret;

	ret = misc_register(&tpm_user_dev);
	if (ret < 0)
		goto error_dev;
	return 0;

error_dev:
	platform_driver_unregister(&tpm_user_drv);
	return ret;
}
device_initcall(tpm_user_mod_init);

static __exit void tpm_user_mod_exit(void)
{
	misc_deregister(&tpm_user_dev);
	platform_driver_unregister(&tpm_user_drv);
}
module_exit(tpm_user_mod_exit);
