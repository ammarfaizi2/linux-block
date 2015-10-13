/*
 * Copyright (c) 2015, The Linux foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License rev 2 and
 * only rev 2 as published by the free Software foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or fITNESS fOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/msm-bus.h>
#include <linux/mfd/qcom-smd-rpm.h>

struct qcom_rpm_msm_bus_info {
	struct qcom_smd_rpm *rpm;
};

static struct qcom_rpm_msm_bus_info rpm_bus_info;

int qcom_rpm_bus_send_message(int ctx, int rsc_type, int id,
	struct qcom_msm_bus_req *req)
{
	return qcom_rpm_smd_write(rpm_bus_info.rpm, ctx, rsc_type, id, req,
				  sizeof(*req));
}
EXPORT_SYMBOL(qcom_rpm_bus_send_message);

static int rpm_msm_bus_probe(struct platform_device *pdev)
{
	rpm_bus_info.rpm = dev_get_drvdata(pdev->dev.parent);
	if (!rpm_bus_info.rpm) {
		dev_err(&pdev->dev, "unable to retrieve handle to rpm\n");
		return -ENODEV;
	}

	return 0;
}

static const struct of_device_id rpm_msm_bus_dt_match[] = {
	{ .compatible = "qcom,rpm-msm-bus", },
	{ },
};

MODULE_DEVICE_TABLE(of, rpm_msm_bus_dt_match);

static struct platform_driver rpm_msm_bus_driver = {
	.driver = {
		.name		= "rpm-msm-bus",
		.of_match_table	= rpm_msm_bus_dt_match,
	},
	.probe = rpm_msm_bus_probe,
};

module_platform_driver(rpm_msm_bus_driver);

MODULE_AUTHOR("Andy Gross <agross@codeaurora.org>");
MODULE_DESCRIPTION("QCOM RPM msm bus driver");
MODULE_LICENSE("GPL v2");
