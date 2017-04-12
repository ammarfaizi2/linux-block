/*
 * Intel INT0002 "Virtual GPIO" driver
 *
 * Copyright (C) 2017 Hans de Goede <hdegoede@redhat.com>
 *
 * Loosely based on android x86 kernel code which is:
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 * Author: Dyut Kumar Sil <dyut.k.sil@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Some peripherals on Baytrail and Cherrytrail platforms signal PME to the
 * PMC to wakeup the system. When this happens software needs to clear the
 * PME_B0_STS bit in the GPE0a_STS register to avoid an IRQ storm on IRQ 9.
 *
 * This is modelled in ACPI through the INT0002 ACPI device, which is
 * called a "Virtual GPIO controller" in ACPI because it defines the event
 * handler to call when the PME triggers through _AEI and _L02 / _E02
 * methods as would be done for a real GPIO interrupt.
 * 
 * This driver will bind to the INT0002 device, call the ACPI event handler
 * for the wakeup and clear the interrupt source avoiding the irq storm.
 */

#include <asm/cpu_device_id.h>
#include <asm/intel-family.h>
#include <asm/io.h>
#include <linux/acpi.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>

#define GPE0A_PME_STS_BIT               0x2000
#define GPE0A_PME_EN_BIT                0x2000
#define GPE0A_STS_PORT			0x420
#define GPE0A_EN_PORT			0x428

#define ICPU(model)	{ X86_VENDOR_INTEL, 6, model, X86_FEATURE_ANY, }

static const struct x86_cpu_id int0002_cpu_ids[] = {
/*
 * Limit ourselves to Cherry Trail for now, until testing shows we
 * need to handle the INT0002 device on Baytrail too.
 *	ICPU(INTEL_FAM6_ATOM_SILVERMONT1),	 * Valleyview, Bay Trail *
 */
	ICPU(INTEL_FAM6_ATOM_AIRMONT),		/* Braswell, Cherry Trail */
	{}
};

struct int0002_data {
	struct spinlock lock;
	struct device *dev;
	const struct x86_cpu_id *cpu_id;
	acpi_handle handle;
	char ev_name[5];
};

static void int0002_irq_enable(struct int0002_data *data, bool enable)
{
	unsigned long flags;
	u32 gpe_en_reg;
	
	spin_lock_irqsave(&data->lock, flags);

	gpe_en_reg = inl(GPE0A_EN_PORT);
	if (enable)
		gpe_en_reg |= GPE0A_PME_EN_BIT;
	else
		gpe_en_reg &= ~GPE0A_PME_EN_BIT;	
	outl(gpe_en_reg, GPE0A_EN_PORT);

	spin_unlock_irqrestore(&data->lock, flags);
}

static irqreturn_t int0002_irq_handler(int irq, void *handler_data)
{
	struct int0002_data *data = handler_data;
	u32 gpe_sts_reg;

	gpe_sts_reg = inl(GPE0A_STS_PORT);
	if (!(gpe_sts_reg & GPE0A_PME_STS_BIT))
		return IRQ_NONE;

	int0002_irq_enable(data, false);

	return IRQ_WAKE_THREAD;
}

static irqreturn_t int0002_irq_thread(int irq, void *handler_data)
{
	struct int0002_data *data = handler_data;
	acpi_status status;

	/* Don't call ACPI event handler on Baytrail? Taken from Android-x86 */
	if (data->cpu_id->model != INTEL_FAM6_ATOM_SILVERMONT1) {
		status = acpi_evaluate_object(data->handle, data->ev_name,
					      NULL, NULL);
		if (ACPI_FAILURE(status))
			dev_err(data->dev, "Error calling %s\n", data->ev_name);
	}

	/* Ack and then re-enable IRQ */
	outl(GPE0A_PME_STS_BIT, GPE0A_STS_PORT);
	int0002_irq_enable(data, true);

	return IRQ_HANDLED;
}

static int int0002_probe(struct platform_device *pdev)
{
	struct acpi_buffer buf = { ACPI_ALLOCATE_BUFFER, NULL };
	struct device *dev = &pdev->dev;
	struct int0002_data *data;
	struct acpi_resource *res;
	acpi_status status;
	acpi_handle hdl;
	int irq, ret;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data) {
		dev_err(dev, "can't allocate memory for int0002\n");
		return -ENOMEM;
	}

	spin_lock_init(&data->lock);
	data->dev = dev; 

	/* Menlow has a different INT0002 device? <sigh> */
	data->cpu_id = x86_match_cpu(int0002_cpu_ids);
	if (!data->cpu_id)
		return -ENODEV;

	data->handle = ACPI_HANDLE(dev);
	if (!data->handle)
		return -ENODEV;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(dev, "Error getting IRQ: %d\n", irq);
		return irq;
	}

	status = acpi_get_event_resources(data->handle, &buf);
	if (ACPI_FAILURE(status)) {
		dev_err(dev, "Error getting acpi event resources\n");
		return -ENODEV;
	}

	/* Find the "GPIO interrupt" event handler to call upon PME */
	ret = -ENODEV;
	for (res = buf.pointer;
	     res && (res->type != ACPI_RESOURCE_TYPE_END_TAG);
	     res = ACPI_NEXT_RESOURCE(res)) {

		if (res->type != ACPI_RESOURCE_TYPE_GPIO ||
		    res->data.gpio.connection_type !=
		    ACPI_RESOURCE_GPIO_TYPE_INT)
			continue;

		snprintf(data->ev_name, sizeof(data->ev_name), "_%c%02X",
			res->data.gpio.triggering ? 'E' : 'L',
			res->data.gpio.pin_table[0]);

		status = acpi_get_handle(data->handle, data->ev_name, &hdl);
		if (ACPI_SUCCESS(status)) {
			ret = 0;
			break;
		}
	}

	ACPI_FREE(buf.pointer);

	if (ret) {
		dev_err(dev, "Error could not find event handler\n");
		return ret;
	}

	ret = devm_request_threaded_irq(dev, irq,
					int0002_irq_handler, int0002_irq_thread,
					IRQF_SHARED, "INT0002", data);
	if (ret) {
		dev_err(dev, "Error requesting IRQ %d: %d\n", irq, ret);
		return ret;
	}

	int0002_irq_enable(data, true);

	return 0;
}

static int int0002_runtime_suspend(struct device *dev)
{
	return 0;
}

static int int0002_runtime_resume(struct device *dev)
{
	return 0;
}

static const struct dev_pm_ops int0002_pm_ops = {
	.runtime_suspend = int0002_runtime_suspend,
	.runtime_resume = int0002_runtime_resume,
};

static const struct acpi_device_id int0002_acpi_ids[] = {
	{ "INT0002", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, int0002_acpi_ids);

static struct platform_driver int0002_driver = {
	.driver = {
		.name			= "Intel INT0002 Virtual GPIO",
		.pm			= &int0002_pm_ops,
		.acpi_match_table	= ACPI_PTR(int0002_acpi_ids),
	},
	.probe	= int0002_probe,
};

module_platform_driver(int0002_driver);

MODULE_AUTHOR("Hans de Goede <hdegoede@redhat.com>");
MODULE_DESCRIPTION("Intel INT0002 Virtual GPIO driver");
MODULE_LICENSE("GPL");
