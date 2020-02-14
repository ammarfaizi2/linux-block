// SPDX-License-Identifier: GPL-2.0
/* Filesystem information for ext4
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/mount.h>
#include "ext4.h"

static int ext4_fsinfo_get_volume_name(struct path *path, struct fsinfo_context *ctx)
{
	const struct ext4_sb_info *sbi = EXT4_SB(path->mnt->mnt_sb);
	const struct ext4_super_block *es = sbi->s_es;

	memcpy(ctx->buffer, es->s_volume_name, sizeof(es->s_volume_name));
	return strlen(ctx->buffer);
}

static int ext4_fsinfo_get_timestamps(struct path *path, struct fsinfo_context *ctx)
{
	const struct ext4_sb_info *sbi = EXT4_SB(path->mnt->mnt_sb);
	const struct ext4_super_block *es = sbi->s_es;
	struct fsinfo_ext4_timestamps *ts = ctx->buffer;

#define Z(R,S) R = S | (((u64)S##_hi) << 32)
	Z(ts->mkfs_time,	es->s_mkfs_time);
	Z(ts->mount_time,	es->s_mtime);
	Z(ts->write_time,	es->s_wtime);
	Z(ts->last_check_time,	es->s_lastcheck);
	Z(ts->first_error_time,	es->s_first_error_time);
	Z(ts->last_error_time,	es->s_last_error_time);
	return sizeof(*ts);
}

static const struct fsinfo_attribute ext4_fsinfo_attributes[] = {
	FSINFO_STRING	(FSINFO_ATTR_VOLUME_NAME,	ext4_fsinfo_get_volume_name),
	FSINFO_VSTRUCT	(FSINFO_ATTR_EXT4_TIMESTAMPS,	ext4_fsinfo_get_timestamps),
	{}
};

int ext4_fsinfo(struct path *path, struct fsinfo_context *ctx)
{
	return fsinfo_get_attribute(path, ctx, ext4_fsinfo_attributes);
}
