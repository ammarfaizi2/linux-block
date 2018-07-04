// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2018, Mellanox Technologies inc. All rights reserved. */

#include <devlink.h>

int mlx5_devlink_register(struct devlink *devlink, struct device *dev)
{
	return devlink_register(devlink, dev);
}

void mlx5_devlink_unregister(struct devlink *devlink)
{
	devlink_unregister(devlink);
}
