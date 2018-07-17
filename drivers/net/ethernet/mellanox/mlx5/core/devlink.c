// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2018, Mellanox Technologies inc. All rights reserved. */

#include <devlink.h>
#include "lib/mlx5.h"

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

static const char *const action_to_str[] = {
	[MLX5_DEVLINK_CONGESTION_ACTION_DISABLED] = "disabled",
	[MLX5_DEVLINK_CONGESTION_ACTION_DROP] = "drop",
	[MLX5_DEVLINK_CONGESTION_ACTION_MARK] = "mark"
};

static const char *mlx5_devlink_congestion_action_to_str(int action)
{
	if (action > MLX5_DEVLINK_CONGESTION_ACTION_MAX) {
		WARN_ON(1);
		return ERR_PTR(-EINVAL);
	}

	return action_to_str[action];
}

static int mlx5_devlink_str_to_congestion_action(const char *str, u8 *action)
{
	int i;

	for (i = 0; i <= MLX5_DEVLINK_CONGESTION_ACTION_MAX; i++) {
		if (!strcmp(str, action_to_str[i])) {
			*action = i;
			return 0;
		}
	}

	return -EINVAL;
}

static int mlx5_devlink_set_congestion_action(struct devlink *devlink, u32 id,
					      struct devlink_param_gset_ctx *ctx,
					      struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	u8 max = MLX5_DEVLINK_CONGESTION_ACTION_MAX;
	u8 congestion_action;
	u8 sense;
	int err;

	if (!MLX5_CAP_MCAM_FEATURE(dev, mark_tx_action_cqe) &&
	    !MLX5_CAP_MCAM_FEATURE(dev, mark_tx_action_cnp))
		max = MLX5_DEVLINK_CONGESTION_ACTION_MARK - 1;

	err = mlx5_devlink_str_to_congestion_action(ctx->val.vstr,
						    &congestion_action);
	if (err)
		return err;

	if (congestion_action > max) {
		NL_SET_ERR_MSG(extack, "Requested congestion action is not supported on current device/FW");
		return -EINVAL;
	}

	err = mlx5_devlink_query_tx_overflow_sense(dev, &sense);
	if (err)
		return err;

	if (congestion_action == MLX5_DEVLINK_CONGESTION_ACTION_DISABLED &&
	    sense != MLX5_DEVLINK_CONGESTION_MODE_AGGRESSIVE) {
		NL_SET_ERR_MSG(extack, "Congestion action \"disabled\" is allowed only while mode is configured to aggressive");
		return -EINVAL;
	}

	return mlx5_devlink_set_tx_lossy_overflow(dev, congestion_action);
}

static int mlx5_devlink_get_congestion_action(struct devlink *devlink, u32 id,
					      struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	u8 congestion_action;
	const char *val;
	int err;

	err = mlx5_devlink_query_tx_lossy_overflow(dev, &congestion_action);
	if (err)
		return err;

	val = mlx5_devlink_congestion_action_to_str(congestion_action);
	if (IS_ERR(val))
		return PTR_ERR(val);

	devlink_param_value_str_fill(&ctx->val, val);
	return 0;
}

static const char *const mode_to_str[] = {
	[MLX5_DEVLINK_CONGESTION_MODE_AGGRESSIVE] = "aggressive",
	[MLX5_DEVLINK_CONGESTION_MODE_DYNAMIC_ADJUSTMENT] = "dynamic"
};

static const char *mlx5_devlink_congestion_mode_to_str(int mode)
{
	if (mode > MLX5_DEVLINK_CONGESTION_MODE_MAX) {
		WARN_ON(1);
		return ERR_PTR(-EINVAL);
	}

	return mode_to_str[mode];
}

static int mlx5_devlink_str_to_congestion_mode(const char *str, u8 *mode)
{
	int i;

	for (i = 0; i <= MLX5_DEVLINK_CONGESTION_MODE_MAX; i++) {
		if (!strcmp(str, mode_to_str[i])) {
			*mode = i;
			return 0;
		}
	}

	return -EINVAL;
}

static int mlx5_devlink_set_congestion_mode(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx,
					    struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	u8 tx_lossy_overflow, congestion_mode;
	int err;

	err = mlx5_devlink_str_to_congestion_mode(ctx->val.vstr,
						  &congestion_mode);
	if (err)
		return err;

	err = mlx5_devlink_query_tx_lossy_overflow(dev, &tx_lossy_overflow);
	if (err)
		return err;

	if (congestion_mode != MLX5_DEVLINK_CONGESTION_MODE_AGGRESSIVE &&
	    tx_lossy_overflow == MLX5_DEVLINK_CONGESTION_ACTION_DISABLED) {
		NL_SET_ERR_MSG(extack, "Congestion mode must be aggressive while congestion action is configured to \"disabled\"");
		return -EINVAL;
	}

	return mlx5_devlink_set_tx_overflow_sense(dev, congestion_mode);
}

static int mlx5_devlink_get_congestion_mode(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	u8 congestion_mode;
	const char *val;
	int err;

	err = mlx5_devlink_query_tx_overflow_sense(dev, &congestion_mode);
	if (err)
		return err;

	val = mlx5_devlink_congestion_mode_to_str(congestion_mode);
	if (IS_ERR(val))
		return PTR_ERR(val);

	devlink_param_value_str_fill(&ctx->val, val);
	return 0;
}

static int mlx5_devlink_get_crdump_snapshot(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	ctx->val.vbool = mlx5_crdump_is_snapshot_enabled(dev);
	return 0;
}

static int mlx5_devlink_set_crdump_snapshot(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx,
					    struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	return mlx5_crdump_set_snapshot_enabled(dev, ctx->val.vbool);
}

enum mlx5_devlink_param_id {
	MLX5_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	MLX5_DEVLINK_PARAM_ID_CONGESTION_ACTION,
	MLX5_DEVLINK_PARAM_ID_CONGESTION_MODE,
};

static const struct devlink_param mlx5_devlink_params[] = {
	DEVLINK_PARAM_GENERIC(REGION_SNAPSHOT,
			      BIT(DEVLINK_PARAM_CMODE_RUNTIME) |
			      BIT(DEVLINK_PARAM_CMODE_DRIVERINIT),
			      mlx5_devlink_get_crdump_snapshot,
			      mlx5_devlink_set_crdump_snapshot, NULL),
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_CONGESTION_ACTION,
			     "congestion_action",
			     DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_get_congestion_action,
			     mlx5_devlink_set_congestion_action, NULL),
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_CONGESTION_MODE,
			     "congestion_mode",
			     DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_get_congestion_mode,
			     mlx5_devlink_set_congestion_mode, NULL),
};

static void mlx5_devlink_set_init_value(struct devlink *devlink, u32 param_id,
					union devlink_param_value init_val)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	int err;

	err = devlink_param_driverinit_value_set(devlink, param_id, init_val);
	if (err)
		dev_warn(&dev->pdev->dev,
			 "devlink set parameter %u value failed (err = %d)",
			 param_id, err);
}

static void mlx5_devlink_set_params_init_values(struct devlink *devlink)
{
	union devlink_param_value value;

	value.vbool = false;
	mlx5_devlink_set_init_value(devlink,
				    DEVLINK_PARAM_GENERIC_ID_REGION_SNAPSHOT,
				    value);
}

int mlx5_devlink_register(struct devlink *devlink, struct device *dev)
{
	int err;

	err = devlink_register(devlink, dev);
	if (err)
		return err;

	err = devlink_params_register(devlink, mlx5_devlink_params,
				      ARRAY_SIZE(mlx5_devlink_params));
	if (err) {
		dev_err(dev, "devlink_params_register failed\n");
		goto unregister;
	}

	mlx5_devlink_set_params_init_values(devlink);

	return 0;

unregister:
	devlink_unregister(devlink);
	return err;
}

void mlx5_devlink_unregister(struct devlink *devlink)
{
	devlink_params_unregister(devlink, mlx5_devlink_params,
				  ARRAY_SIZE(mlx5_devlink_params));
	devlink_unregister(devlink);
}
