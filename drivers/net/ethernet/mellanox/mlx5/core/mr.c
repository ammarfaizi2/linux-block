/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/cmd.h>
#include "mlx5_core.h"

static inline u32 mlx5_get_psv(u32 *out, int psv_index)
{
	switch (psv_index) {
	case 1: return MLX5_GET(create_psv_out, out, psv1_index);
	case 2: return MLX5_GET(create_psv_out, out, psv2_index);
	case 3: return MLX5_GET(create_psv_out, out, psv3_index);
	default: return MLX5_GET(create_psv_out, out, psv0_index);
	}
}

int mlx5_core_create_psv(struct mlx5_core_dev *dev, u32 pdn,
			 int npsvs, u32 *sig_index)
{
	u32 out[MLX5_ST_SZ_DW(create_psv_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(create_psv_in)]   = {0};
	int i, err;

	if (npsvs > MLX5_MAX_PSVS)
		return -EINVAL;

	MLX5_SET(create_psv_in, in, opcode, MLX5_CMD_OP_CREATE_PSV);
	MLX5_SET(create_psv_in, in, pd, pdn);
	MLX5_SET(create_psv_in, in, num_psv, npsvs);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (err)
		return err;

	for (i = 0; i < npsvs; i++)
		sig_index[i] = mlx5_get_psv(out, i);

	return err;
}
EXPORT_SYMBOL(mlx5_core_create_psv);

int mlx5_core_destroy_psv(struct mlx5_core_dev *dev, int psv_num)
{
	u32 out[MLX5_ST_SZ_DW(destroy_psv_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(destroy_psv_in)]   = {0};

	MLX5_SET(destroy_psv_in, in, opcode, MLX5_CMD_OP_DESTROY_PSV);
	MLX5_SET(destroy_psv_in, in, psvn, psv_num);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}
EXPORT_SYMBOL(mlx5_core_destroy_psv);
