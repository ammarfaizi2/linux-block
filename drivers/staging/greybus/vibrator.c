// SPDX-License-Identifier: GPL-2.0
/*
 * Greybus Vibrator protocol driver.
 *
 * Copyright 2014 Google Inc.
 * Copyright 2014 Linaro Ltd.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/idr.h>
#include <linux/pm_runtime.h>
#include <linux/input.h>
#include <linux/greybus.h>

struct gb_vibrator_device {
	struct gb_connection	*connection;
	struct input_dev	*input;
	bool			running;
	bool			on;
	struct work_struct	play_work;
};

/* Greybus Vibrator operation types */
#define	GB_VIBRATOR_TYPE_ON			0x02
#define	GB_VIBRATOR_TYPE_OFF			0x03

static int turn_off(struct gb_vibrator_device *vib)
{
	struct gb_bundle *bundle = vib->connection->bundle;
	int ret;

	ret = gb_operation_sync(vib->connection, GB_VIBRATOR_TYPE_OFF,
				NULL, 0, NULL, 0);

	gb_pm_runtime_put_autosuspend(bundle);

	vib->on = false;
	return ret;
}

static int turn_on(struct gb_vibrator_device *vib)
{
	struct gb_bundle *bundle = vib->connection->bundle;
	int ret;

	ret = gb_pm_runtime_get_sync(bundle);
	if (ret)
		return ret;

	ret = gb_operation_sync(vib->connection, GB_VIBRATOR_TYPE_ON,
				NULL, 0, NULL, 0);
	if (ret) {
		gb_pm_runtime_put_autosuspend(bundle);
		return ret;
	}

	vib->on = true;
	return 0;
}

static void gb_vibrator_play_work(struct work_struct *work)
{
	struct gb_vibrator_device *vib =
		container_of(work, struct gb_vibrator_device, play_work);

	if (vib->running)
		turn_off(vib);
	else
		turn_on(vib);
}

static int gb_vibrator_play_effect(struct input_dev *input, void *data,
				   struct ff_effect *effect)
{
	struct gb_vibrator_device *vib = input_get_drvdata(input);
	int level;

	level = effect->u.rumble.strong_magnitude;
	if (!level)
		level = effect->u.rumble.weak_magnitude;

	vib->running = level;
	schedule_work(&vib->play_work);
	return 0;
}

static void gb_vibrator_close(struct input_dev *input)
{
	struct gb_vibrator_device *vib = input_get_drvdata(input);

	cancel_work_sync(&vib->play_work);
	turn_off(vib);
	vib->running = false;
}

static int gb_vibrator_probe(struct gb_bundle *bundle,
			     const struct greybus_bundle_id *id)
{
	struct greybus_descriptor_cport *cport_desc;
	struct gb_connection *connection;
	struct gb_vibrator_device *vib;
	int retval;

	if (bundle->num_cports != 1)
		return -ENODEV;

	cport_desc = &bundle->cport_desc[0];
	if (cport_desc->protocol_id != GREYBUS_PROTOCOL_VIBRATOR)
		return -ENODEV;

	vib = kzalloc(sizeof(*vib), GFP_KERNEL);
	if (!vib)
		return -ENOMEM;

	connection = gb_connection_create(bundle, le16_to_cpu(cport_desc->id),
					  NULL);
	if (IS_ERR(connection)) {
		retval = PTR_ERR(connection);
		goto err_free_vib;
	}
	gb_connection_set_data(connection, vib);

	vib->connection = connection;

	greybus_set_drvdata(bundle, vib);

	retval = gb_connection_enable(connection);
	if (retval)
		goto err_connection_destroy;

	INIT_WORK(&vib->play_work, gb_vibrator_play_work);
	vib->input->name = "greybus-vibrator";
	vib->input->close = gb_vibrator_close;
	vib->input->dev.parent = &bundle->dev;
	vib->input->id.bustype = BUS_HOST;

	input_set_drvdata(vib->input, vib);
	input_set_capability(vib->input, EV_FF, FF_RUMBLE);

	retval = input_ff_create_memless(vib->input, NULL,
					 gb_vibrator_play_effect);
	if (retval)
		goto err_connection_disable;

	gb_pm_runtime_put_autosuspend(bundle);

	return 0;

err_connection_disable:
	gb_connection_disable(connection);
err_connection_destroy:
	gb_connection_destroy(connection);
err_free_vib:
	kfree(vib);

	return retval;
}

static void gb_vibrator_disconnect(struct gb_bundle *bundle)
{
	struct gb_vibrator_device *vib = greybus_get_drvdata(bundle);
	int ret;

	ret = gb_pm_runtime_get_sync(bundle);
	if (ret)
		gb_pm_runtime_get_noresume(bundle);

	turn_off(vib);

	gb_connection_disable(vib->connection);
	gb_connection_destroy(vib->connection);
	kfree(vib);
}

static const struct greybus_bundle_id gb_vibrator_id_table[] = {
	{ GREYBUS_DEVICE_CLASS(GREYBUS_CLASS_VIBRATOR) },
	{ }
};
MODULE_DEVICE_TABLE(greybus, gb_vibrator_id_table);

static struct greybus_driver gb_vibrator_driver = {
	.name		= "vibrator",
	.probe		= gb_vibrator_probe,
	.disconnect	= gb_vibrator_disconnect,
	.id_table	= gb_vibrator_id_table,
};
module_greybus_driver(gb_vibrator_driver);

MODULE_LICENSE("GPL v2");
