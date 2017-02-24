/*
 * Power button driver for dollar cove
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/input.h>
#include <linux/mfd/intel_soc_pmic.h>

#define DC_TI_SIRQ_REG		0x3
#define SIRQ_PWRBTN_REL		(1 << 0)

#define DRIVER_NAME "dollar_cove_ti_power_button"

static struct input_dev *pwrbtn_input;
static int pwrbtn_irq;

static irqreturn_t dc_ti_powerbtn_interrupt(int irq, void *dev_id)
{
	struct platform_device *pdev = dev_id;
	struct regmap *regmap = platform_get_drvdata(pdev);
	int state;

	if (!regmap_read(regmap, DC_TI_SIRQ_REG, &state)) {
		dev_dbg(&pdev->dev, "SIRQ_REG=0x%x\n", state);
		state &= SIRQ_PWRBTN_REL;
		input_event(pwrbtn_input, EV_KEY, KEY_POWER, !state);
		input_sync(pwrbtn_input);
	}

	return IRQ_HANDLED;
}

static int dc_ti_powerbtn_probe(struct platform_device *pdev)
{
	struct device *dev = pdev->dev.parent;
	struct intel_soc_pmic *pmic = dev_get_drvdata(dev);
	int ret;

	pwrbtn_irq = platform_get_irq(pdev, 0);
	if (pwrbtn_irq < 0)
		return -EINVAL;
	pwrbtn_input = devm_input_allocate_device(&pdev->dev);
	if (!pwrbtn_input)
		return -ENOMEM;
	pwrbtn_input->name = pdev->name;
	pwrbtn_input->phys = "dc-ti-power/input0";
	pwrbtn_input->id.bustype = BUS_HOST;
	pwrbtn_input->dev.parent = &pdev->dev;
	input_set_capability(pwrbtn_input, EV_KEY, KEY_POWER);
	ret = input_register_device(pwrbtn_input);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, pmic->regmap);

	ret = devm_request_threaded_irq(&pdev->dev, pwrbtn_irq, NULL,
					dc_ti_powerbtn_interrupt,
					0, KBUILD_MODNAME, pdev);
	if (ret)
		return ret;

	return 0;
}

static int dc_ti_powerbtn_remove(struct platform_device *pdev)
{
	return 0;
}

static int dc_ti_powerbtn_resume(struct device *dev)
{
	/* FIXME: an ad hoc workaround -- we re-setup IRQ after resume;
	 * otherwise the stalling irq isn't acked and the power button
	 * no longer works.
	 */
	disable_irq(pwrbtn_irq);
	enable_irq(pwrbtn_irq);
	return 0;
}

static const struct dev_pm_ops dc_ti_powerbtn_pm_ops = {
	.resume	= dc_ti_powerbtn_resume,
};

static struct platform_driver dc_ti_powerbtn_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.pm = &dc_ti_powerbtn_pm_ops,
	},
	.probe	= dc_ti_powerbtn_probe,
	.remove	= dc_ti_powerbtn_remove,
};

module_platform_driver(dc_ti_powerbtn_driver);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRIVER_NAME);
