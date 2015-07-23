/* Firmware load test module */

#define pr_fmt(fmt) "FWTEST: "fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <linux/delay.h>

static struct platform_device *pdev;

static int __init test_init(void)
{
	int ret;
	const struct firmware *config;

	pr_notice("Registering device\n");

	pdev = platform_device_register_simple("fake-dev", 0, NULL, 0);
	if (IS_ERR(pdev)) {
		pr_notice("Registration failed (%d)\n", ret);
		return PTR_ERR(pdev);
	}

	/* You can just do ls / > /lib/firmware/fake.bin to fake the fw */

	pr_notice("Requesting firmware\n");
	ret = request_firmware(&config, "fake.bin", &pdev->dev);
	if (ret < 0) {
		pr_notice("Request failed (%d)\n", ret);
		dev_set_uevent_suppress(&pdev->dev, true);
		platform_device_unregister(pdev);
		return ret;
	}

	ssleep(3);

	pr_notice("Releasing firmware\n");
	release_firmware(config);

	pr_notice("Done\n");
	return 0;
}

static void __exit test_exit(void)
{
	pr_notice("Unregistering\n");
	dev_set_uevent_suppress(&pdev->dev, true);
	platform_device_unregister(pdev);
	pr_notice("Removing\n");
}

module_init(test_init)
module_exit(test_exit)

MODULE_AUTHOR("Luis R. Rodriguez");
MODULE_DESCRIPTION("Firmware loader test");
MODULE_LICENSE("GPL");
