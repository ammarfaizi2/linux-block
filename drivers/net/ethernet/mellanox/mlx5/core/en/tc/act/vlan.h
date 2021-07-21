/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_EN_TC_ACT_VLAN_H__
#define __MLX5_EN_TC_ACT_VLAN_H__

#include <net/flow_offload.h>
#include "en/tc_priv.h"

int
mlx5e_tc_act_vlan_add_push_action(struct mlx5e_priv *priv,
				  struct mlx5_flow_attr *attr,
				  struct net_device **out_dev,
				  struct netlink_ext_ack *extack);

int
mlx5e_tc_act_vlan_add_pop_action(struct mlx5e_priv *priv,
				 struct mlx5_flow_attr *attr,
				 struct netlink_ext_ack *extack);

#endif /* __MLX5_EN_TC_ACT_VLAN_H__ */
