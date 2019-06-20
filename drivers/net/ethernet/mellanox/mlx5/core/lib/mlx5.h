/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2017, Mellanox Technologies. All rights reserved. */

#ifndef __LIB_MLX5_H__
#define __LIB_MLX5_H__

#include "mlx5_core.h"

int mlx5_core_alloc_pd(struct mlx5_core_dev *dev, u32 *pdn);
int mlx5_core_dealloc_pd(struct mlx5_core_dev *dev, u32 pdn);

int mlx5_create_mkey(struct mlx5_core_dev *dev, u32 *in, int inlen, u32 *mkey);
int mlx5_destroy_mkey(struct mlx5_core_dev *dev, u32 mkey);

void mlx5_init_reserved_gids(struct mlx5_core_dev *dev);
void mlx5_cleanup_reserved_gids(struct mlx5_core_dev *dev);
int  mlx5_core_reserve_gids(struct mlx5_core_dev *dev, unsigned int count);
void mlx5_core_unreserve_gids(struct mlx5_core_dev *dev, unsigned int count);
int  mlx5_core_reserved_gid_alloc(struct mlx5_core_dev *dev, int *gid_index);
void mlx5_core_reserved_gid_free(struct mlx5_core_dev *dev, int gid_index);
int mlx5_crdump_enable(struct mlx5_core_dev *dev);
void mlx5_crdump_disable(struct mlx5_core_dev *dev);
int mlx5_crdump_collect(struct mlx5_core_dev *dev, u32 *cr_data);

/* TODO move to lib/events.h */

#define PORT_MODULE_EVENT_MODULE_STATUS_MASK 0xF
#define PORT_MODULE_EVENT_ERROR_TYPE_MASK    0xF

enum port_module_event_status_type {
	MLX5_MODULE_STATUS_PLUGGED   = 0x1,
	MLX5_MODULE_STATUS_UNPLUGGED = 0x2,
	MLX5_MODULE_STATUS_ERROR     = 0x3,
	MLX5_MODULE_STATUS_DISABLED  = 0x4,
	MLX5_MODULE_STATUS_NUM,
};

enum  port_module_event_error_type {
	MLX5_MODULE_EVENT_ERROR_POWER_BUDGET_EXCEEDED    = 0x0,
	MLX5_MODULE_EVENT_ERROR_LONG_RANGE_FOR_NON_MLNX  = 0x1,
	MLX5_MODULE_EVENT_ERROR_BUS_STUCK                = 0x2,
	MLX5_MODULE_EVENT_ERROR_NO_EEPROM_RETRY_TIMEOUT  = 0x3,
	MLX5_MODULE_EVENT_ERROR_ENFORCE_PART_NUMBER_LIST = 0x4,
	MLX5_MODULE_EVENT_ERROR_UNKNOWN_IDENTIFIER       = 0x5,
	MLX5_MODULE_EVENT_ERROR_HIGH_TEMPERATURE         = 0x6,
	MLX5_MODULE_EVENT_ERROR_BAD_CABLE                = 0x7,
	MLX5_MODULE_EVENT_ERROR_PCIE_POWER_SLOT_EXCEEDED = 0xc,
	MLX5_MODULE_EVENT_ERROR_NUM,
};

struct mlx5_pme_stats {
	u64 status_counters[MLX5_MODULE_STATUS_NUM];
	u64 error_counters[MLX5_MODULE_EVENT_ERROR_NUM];
};

void mlx5_get_pme_stats(struct mlx5_core_dev *dev, struct mlx5_pme_stats *stats);
int mlx5_notifier_call_chain(struct mlx5_events *events, unsigned int event, void *data);

/* Crypto */
int mlx5_create_encryption_key(struct mlx5_core_dev *mdev,
			       void *key, u32 sz_bytes, u32 *p_key_id);
void mlx5_destroy_encryption_key(struct mlx5_core_dev *mdev, u32 key_id);

#endif
