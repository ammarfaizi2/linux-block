// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2013-2019, Mellanox Technologies. All rights reserved.

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/cmd.h>

#include "mlx5_core.h"
#include "lib/mlx5.h"

int mlx5_core_alloc_pd(struct mlx5_core_dev *dev, u32 *pdn)
{
	u32 out[MLX5_ST_SZ_DW(alloc_pd_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(alloc_pd_in)]   = {0};
	int err;

	MLX5_SET(alloc_pd_in, in, opcode, MLX5_CMD_OP_ALLOC_PD);
	err = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (!err)
		*pdn = MLX5_GET(alloc_pd_out, out, pd);
	return err;
}

int mlx5_core_dealloc_pd(struct mlx5_core_dev *dev, u32 pdn)
{
	u32 out[MLX5_ST_SZ_DW(dealloc_pd_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(dealloc_pd_in)]   = {0};

	MLX5_SET(dealloc_pd_in, in, opcode, MLX5_CMD_OP_DEALLOC_PD);
	MLX5_SET(dealloc_pd_in, in, pd, pdn);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}
