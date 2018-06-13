// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2018, Mellanox Technologies inc. All rights reserved. */

#include <devlink.h>

enum {
	MLX5_DEVLINK_MPEGC_FIELD_SELECT_TX_OVERFLOW_DROP_EN = BIT(0),
	MLX5_DEVLINK_MPEGC_FIELD_SELECT_TX_OVERFLOW_SENSE = BIT(3),
	MLX5_DEVLINK_MPEGC_FIELD_SELECT_MARK_TX_ACTION_CQE = BIT(4),
	MLX5_DEVLINK_MPEGC_FIELD_SELECT_MARK_TX_ACTION_CNP = BIT(5),
};

enum {
	MLX5_DEVLINK_CONGESTION_ACTION_DISABLED,
	MLX5_DEVLINK_CONGESTION_ACTION_DROP,
	MLX5_DEVLINK_CONGESTION_ACTION_MARK,
	__MLX5_DEVLINK_CONGESTION_ACTION_MAX,
	MLX5_DEVLINK_CONGESTION_ACTION_MAX = __MLX5_DEVLINK_CONGESTION_ACTION_MAX - 1,
};

enum {
	MLX5_DEVLINK_CONGESTION_MODE_AGGRESSIVE,
	MLX5_DEVLINK_CONGESTION_MODE_DYNAMIC_ADJUSTMENT,
	__MLX5_DEVLINK_CONGESTION_MODE_MAX,
	MLX5_DEVLINK_CONGESTION_MODE_MAX = __MLX5_DEVLINK_CONGESTION_MODE_MAX - 1,
};

static int mlx5_devlink_set_mpegc(struct mlx5_core_dev *mdev, u32 *in,
				  int size_in)
{
	u32 out[MLX5_ST_SZ_DW(mpegc_reg)] = {0};

	if (!MLX5_CAP_MCAM_REG(mdev, mpegc))
		return -EOPNOTSUPP;

	return mlx5_core_access_reg(mdev, in, size_in, out,
				    sizeof(out), MLX5_REG_MPEGC, 0, 1);
}

static int mlx5_devlink_set_tx_lossy_overflow(struct mlx5_core_dev *mdev,
					      u8 tx_lossy_overflow)
{
	u32 in[MLX5_ST_SZ_DW(mpegc_reg)] = {0};
	u8 field_select = 0;

	if (tx_lossy_overflow == MLX5_DEVLINK_CONGESTION_ACTION_MARK) {
		if (MLX5_CAP_MCAM_FEATURE(mdev, mark_tx_action_cqe))
			field_select |=
				MLX5_DEVLINK_MPEGC_FIELD_SELECT_MARK_TX_ACTION_CQE;

		if (MLX5_CAP_MCAM_FEATURE(mdev, mark_tx_action_cnp))
			field_select |=
				MLX5_DEVLINK_MPEGC_FIELD_SELECT_MARK_TX_ACTION_CNP;

		if (!field_select)
			return -EOPNOTSUPP;
	}

	MLX5_SET(mpegc_reg, in, field_select,
		 field_select |
		 MLX5_DEVLINK_MPEGC_FIELD_SELECT_TX_OVERFLOW_DROP_EN);
	MLX5_SET(mpegc_reg, in, tx_lossy_overflow_oper, tx_lossy_overflow);
	MLX5_SET(mpegc_reg, in, mark_cqe, 0x1);
	MLX5_SET(mpegc_reg, in, mark_cnp, 0x1);

	return mlx5_devlink_set_mpegc(mdev, in, sizeof(in));
}

static int mlx5_devlink_set_tx_overflow_sense(struct mlx5_core_dev *mdev,
					      u8 tx_overflow_sense)
{
	u32 in[MLX5_ST_SZ_DW(mpegc_reg)] = {0};

	if (!MLX5_CAP_MCAM_FEATURE(mdev, dynamic_tx_overflow))
		return -EOPNOTSUPP;

	MLX5_SET(mpegc_reg, in, field_select,
		 MLX5_DEVLINK_MPEGC_FIELD_SELECT_TX_OVERFLOW_SENSE);
	MLX5_SET(mpegc_reg, in, tx_overflow_sense, tx_overflow_sense);

	return mlx5_devlink_set_mpegc(mdev, in, sizeof(in));
}

static int mlx5_devlink_query_mpegc(struct mlx5_core_dev *mdev, u32 *out,
				    int size_out)
{
	u32 in[MLX5_ST_SZ_DW(mpegc_reg)] = {0};

	if (!MLX5_CAP_MCAM_REG(mdev, mpegc))
		return -EOPNOTSUPP;

	return mlx5_core_access_reg(mdev, in, sizeof(in), out,
				    size_out, MLX5_REG_MPEGC, 0, 0);
}

static int mlx5_devlink_query_tx_lossy_overflow(struct mlx5_core_dev *mdev,
						u8 *tx_lossy_overflow)
{
	u32 out[MLX5_ST_SZ_DW(mpegc_reg)] = {0};
	int err;

	err = mlx5_devlink_query_mpegc(mdev, out, sizeof(out));
	if (err)
		return err;

	*tx_lossy_overflow = MLX5_GET(mpegc_reg, out, tx_lossy_overflow_oper);

	return 0;
}

static int mlx5_devlink_query_tx_overflow_sense(struct mlx5_core_dev *mdev,
						u8 *tx_overflow_sense)
{
	u32 out[MLX5_ST_SZ_DW(mpegc_reg)] = {0};
	int err;

	if (!MLX5_CAP_MCAM_FEATURE(mdev, dynamic_tx_overflow))
		return -EOPNOTSUPP;

	err = mlx5_devlink_query_mpegc(mdev, out, sizeof(out));
	if (err)
		return err;

	*tx_overflow_sense = MLX5_GET(mpegc_reg, out, tx_overflow_sense);

	return 0;
}

int mlx5_devlink_register(struct devlink *devlink, struct device *dev)
{
	return devlink_register(devlink, dev);
}

void mlx5_devlink_unregister(struct devlink *devlink)
{
	devlink_unregister(devlink);
}
