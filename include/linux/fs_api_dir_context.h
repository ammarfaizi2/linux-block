/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_API_DIR_CONTEXT_H
#define _LINUX_FS_API_DIR_CONTEXT_H

#include <linux/fs_api.h>

#include <linux/fs_entry_types.h>

static inline bool dir_emit(struct dir_context *ctx,
			    const char *name, int namelen,
			    u64 ino, unsigned type)
{
	return ctx->actor(ctx, name, namelen, ctx->pos, ino, type) == 0;
}

static inline bool dir_emit_dot(struct file *file, struct dir_context *ctx)
{
	return ctx->actor(ctx, ".", 1, ctx->pos,
			  file->f_path.dentry->d_inode->i_ino, DT_DIR) == 0;
}

static inline bool dir_emit_dotdot(struct file *file, struct dir_context *ctx)
{
	return ctx->actor(ctx, "..", 2, ctx->pos,
			  parent_ino(file->f_path.dentry), DT_DIR) == 0;
}

static inline bool dir_emit_dots(struct file *file, struct dir_context *ctx)
{
	if (ctx->pos == 0) {
		if (!dir_emit_dot(file, ctx))
			return false;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		if (!dir_emit_dotdot(file, ctx))
			return false;
		ctx->pos = 2;
	}
	return true;
}

#endif /* _LINUX_FS_API_DIR_CONTEXT_H */
