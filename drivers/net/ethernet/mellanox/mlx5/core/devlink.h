/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2018, Mellanox Technologies inc. All rights reserved. */

#ifndef __MLX5_DEVLINK_H__
#define __MLX5_DEVLINK_H__

#include <net/devlink.h>

int mlx5_devlink_register(struct devlink *devlink, struct device *dev);
void mlx5_devlink_unregister(struct devlink *devlink);

#endif /* __MLX5_DEVLINK_H__ */
