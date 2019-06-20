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

int mlx5_create_mkey(struct mlx5_core_dev *dev, u32 *in, int inlen, u32 *mkey)
{
	u32 out[MLX5_ST_SZ_DW(create_mkey_out)] = {};
	u8 key_var;
	void *mkc;
	int err;

	MLX5_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	err = mlx5_cmd_exec(dev, in, inlen, out, sizeof(out));
	if (err)
		return err;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	key_var = MLX5_GET(mkc, mkc, mkey_7_0);
	*mkey = mlx5_idx_to_mkey(MLX5_GET(create_mkey_out, out, mkey_index)) | key_var;
	return 0;
}

int mlx5_destroy_mkey(struct mlx5_core_dev *dev, u32 mkey)
{
	u32 out[MLX5_ST_SZ_DW(destroy_mkey_out)] = {};
	u32 in[MLX5_ST_SZ_DW(destroy_mkey_in)] = {};

	MLX5_SET(destroy_mkey_in, in, opcode, MLX5_CMD_OP_DESTROY_MKEY);
	MLX5_SET(destroy_mkey_in, in, mkey_index, mlx5_mkey_to_idx(mkey));
	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}
