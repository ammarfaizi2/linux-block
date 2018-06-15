/* Provide a way to create a superblock configuration context within the kernel
 * that allows a superblock to be set up prior to mounting.
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/fs_context.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include <linux/security.h>
#include <linux/parser.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
#include <asm/sections.h>
#include "mount.h"

enum legacy_fs_param {
	LEGACY_FS_UNSET_PARAMS,
	LEGACY_FS_NO_PARAMS,
	LEGACY_FS_MONOLITHIC_PARAMS,
	LEGACY_FS_INDIVIDUAL_PARAMS,
	LEGACY_FS_MAGIC_PARAMS,
};

struct legacy_fs_context {
	struct fs_context	fc;
	char			*legacy_data;	/* Data page for legacy filesystems */
	char			*secdata;
	size_t			data_size;
	enum legacy_fs_param	param_type;
};

static const struct fs_context_operations legacy_fs_context_ops;

static const match_table_t common_set_sb_flag = {
	{ SB_DIRSYNC,		"dirsync" },
	{ SB_LAZYTIME,		"lazytime" },
	{ SB_MANDLOCK,		"mand" },
	{ SB_POSIXACL,		"posixacl" },
	{ SB_RDONLY,		"ro" },
	{ SB_SYNCHRONOUS,	"sync" },
	{ },
};

static const match_table_t common_clear_sb_flag = {
	{ SB_LAZYTIME,		"nolazytime" },
	{ SB_MANDLOCK,		"nomand" },
	{ SB_RDONLY,		"rw" },
	{ SB_SILENT,		"silent" },
	{ SB_SYNCHRONOUS,	"async" },
	{ },
};

static const match_table_t forbidden_sb_flag = {
	{ 0,	"bind" },
	{ 0,	"move" },
	{ 0,	"private" },
	{ 0,	"remount" },
	{ 0,	"shared" },
	{ 0,	"slave" },
	{ 0,	"unbindable" },
	{ 0,	"rec" },
	{ 0,	"noatime" },
	{ 0,	"relatime" },
	{ 0,	"norelatime" },
	{ 0,	"strictatime" },
	{ 0,	"nostrictatime" },
	{ 0,	"nodiratime" },
	{ 0,	"dev" },
	{ 0,	"nodev" },
	{ 0,	"exec" },
	{ 0,	"noexec" },
	{ 0,	"suid" },
	{ 0,	"nosuid" },
	{ },
};

/*
 * Check for a common mount option that manipulates s_flags.
 */
static int vfs_parse_sb_flag_option(struct fs_context *fc, char *data)
{
	substring_t args[MAX_OPT_ARGS];
	unsigned int token;

	token = match_token(data, common_set_sb_flag, args);
	if (token) {
		fc->sb_flags |= token;
		return 1;
	}

	token = match_token(data, common_clear_sb_flag, args);
	if (token) {
		fc->sb_flags &= ~token;
		return 1;
	}

	token = match_token(data, forbidden_sb_flag, args);
	if (token)
		return -EINVAL;

	return 0;
}

/**
 * vfs_parse_fs_option - Add a single mount option to a superblock config
 * @fc: The filesystem context to modify
 * @opt: The option to apply.
 * @len: The length of the option.
 *
 * A single mount option in string form is applied to the filesystem context
 * being set up.  Certain standard options (for example "ro") are translated
 * into flag bits without going to the filesystem.  The active security module
 * is allowed to observe and poach options.  Any other options are passed over
 * to the filesystem to parse.
 *
 * This may be called multiple times for a context.
 *
 * Returns 0 on success and a negative error code on failure.  In the event of
 * failure, supplementary error information may have been set.
 */
int vfs_parse_fs_option(struct fs_context *fc, char *opt, size_t len)
{
	int ret;

	ret = vfs_parse_sb_flag_option(fc, opt);
	if (ret < 0)
		return ret;
	if (ret == 1)
		return 0;

	ret = security_fs_context_parse_option(fc, opt, len);
	if (ret < 0)
		return ret;
	if (ret == 1)
		return 0;

	if (fc->ops->parse_option)
		return fc->ops->parse_option(fc, opt, len);

	return -EINVAL;
}
EXPORT_SYMBOL(vfs_parse_fs_option);

/**
 * vfs_set_fs_source - Set the source/device name in a filesystem context
 * @fc: The filesystem context to alter
 * @source: The name of the source
 * @slen: Length of @source string
 */
int vfs_set_fs_source(struct fs_context *fc, const char *source, size_t slen)
{
	char *src;
	int ret;

	if (fc->source)
		return -EINVAL;
	src = kmemdup_nul(source, slen, GFP_KERNEL);
	if (!src)
		return -ENOMEM;

	ret = security_fs_context_parse_source(fc, src);
	if (ret < 0)
		goto error;

	if (fc->ops->parse_source) {
		ret = fc->ops->parse_source(fc, src);
		if (ret < 0)
			goto error;
	}

	fc->source = src;
	return 0;

error:
	kfree(src);
	return ret;
}
EXPORT_SYMBOL(vfs_set_fs_source);

/**
 * generic_parse_monolithic - Parse key[=val][,key[=val]]* mount data
 * @ctx: The superblock configuration to fill in.
 * @data: The data to parse
 * @data_size: The amount of data
 *
 * Parse a blob of data that's in key[=val][,key[=val]]* form.  This can be
 * called from the ->monolithic_mount_data() fs_context operation.
 *
 * Returns 0 on success or the error returned by the ->parse_option() fs_context
 * operation on failure.
 */
int generic_parse_monolithic(struct fs_context *fc, void *data, size_t data_size)
{
	char *options = data, *opt;
	int ret;

	if (!options)
		return 0;

	while ((opt = strsep(&options, ",")) != NULL) {
		if (*opt) {
			ret = vfs_parse_fs_option(fc, opt, strlen(opt));
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}
EXPORT_SYMBOL(generic_parse_monolithic);

/**
 * vfs_new_fs_context - Create a filesystem context.
 * @fs_type: The filesystem type.
 * @reference: The dentry from which this one derives (or NULL)
 * @sb_flags: Filesystem/superblock flags (SB_*)
 * @purpose: The purpose that this configuration shall be used for.
 *
 * Open a filesystem and create a mount context.  The mount context is
 * initialised with the supplied flags and, if a submount/automount from
 * another superblock (referred to by @reference) is supplied, may have
 * parameters such as namespaces copied across from that superblock.
 */
struct fs_context *vfs_new_fs_context(struct file_system_type *fs_type,
				      struct dentry *reference,
				      unsigned int sb_flags,
				      enum fs_context_purpose purpose)
{
	struct fs_context *fc;
	int ret;

	fc = kzalloc(sizeof(struct legacy_fs_context), GFP_KERNEL);
	if (!fc)
		return ERR_PTR(-ENOMEM);

	fc->purpose	= purpose;
	fc->sb_flags	= sb_flags;
	fc->fs_type	= get_filesystem(fs_type);
	fc->cred	= get_current_cred();

	mutex_init(&fc->uapi_mutex);

	switch (purpose) {
	case FS_CONTEXT_FOR_KERNEL_MOUNT:
		fc->sb_flags |= SB_KERNMOUNT;
		/* Fallthrough */
	case FS_CONTEXT_FOR_USER_MOUNT:
		fc->user_ns = get_user_ns(fc->cred->user_ns);
		fc->net_ns = get_net(current->nsproxy->net_ns);
		break;
	case FS_CONTEXT_FOR_SUBMOUNT:
		fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
		fc->net_ns = get_net(current->nsproxy->net_ns);
		break;
	case FS_CONTEXT_FOR_RECONFIGURE:
		/* We don't pin any namespaces as the superblock's
		 * subscriptions cannot be changed at this point.
		 */
		atomic_inc(&reference->d_sb->s_active);
		fc->root = dget(reference);
		break;
	}


	/* TODO: Make all filesystems support this unconditionally */
	if (fc->fs_type->init_fs_context) {
		ret = fc->fs_type->init_fs_context(fc, reference);
		if (ret < 0)
			goto err_fc;
	} else {
		fc->ops = &legacy_fs_context_ops;
	}

	/* Do the security check last because ->init_fs_context may change the
	 * namespace subscriptions.
	 */
	ret = security_fs_context_alloc(fc, reference);
	if (ret < 0)
		goto err_fc;

	return fc;

err_fc:
	put_fs_context(fc);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(vfs_new_fs_context);

/**
 * vfs_sb_reconfig - Create a filesystem context for remount/reconfiguration
 * @mountpoint: The mountpoint to open
 * @sb_flags: Filesystem/superblock flags (SB_*)
 *
 * Open a mounted filesystem and create a filesystem context such that a
 * remount can be effected.
 */
struct fs_context *vfs_sb_reconfig(struct path *mountpoint,
				   unsigned int sb_flags)
{
	struct fs_context *fc;

	fc = vfs_new_fs_context(mountpoint->dentry->d_sb->s_type,
				mountpoint->dentry,
				sb_flags, FS_CONTEXT_FOR_RECONFIGURE);
	if (IS_ERR(fc))
		return fc;

	return fc;
}

/**
 * vfs_dup_fc_config: Duplicate a filesytem context.
 * @src_fc: The context to copy.
 */
struct fs_context *vfs_dup_fs_context(struct fs_context *src_fc)
{
	struct fs_context *fc;
	int ret;

	if (!src_fc->ops->dup)
		return ERR_PTR(-EOPNOTSUPP);

	fc = kmemdup(src_fc, sizeof(struct legacy_fs_context), GFP_KERNEL);
	if (!fc)
		return ERR_PTR(-ENOMEM);

	mutex_init(&fc->uapi_mutex);

	fc->fs_private	= NULL;
	fc->s_fs_info	= NULL;
	fc->source	= NULL;
	fc->security	= NULL;
	get_filesystem(fc->fs_type);
	get_net(fc->net_ns);
	get_user_ns(fc->user_ns);
	get_cred(fc->cred);
	if (fc->log)
		refcount_inc(&fc->log->usage);

	/* Can't call put until we've called ->dup */
	ret = fc->ops->dup(fc, src_fc);
	if (ret < 0)
		goto err_fc;

	ret = security_fs_context_dup(fc, src_fc);
	if (ret < 0)
		goto err_fc;
	return fc;

err_fc:
	put_fs_context(fc);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(vfs_dup_fs_context);

/**
 * logfc - Log a message to a filesystem context
 * @fc: The filesystem context to log to.
 * @fmt: The format of the buffer.
 */
void logfc(struct fs_context *fc, const char *fmt, ...)
{
	static const char store_failure[] = "OOM: Can't store error string";
	struct fc_log *log = fc->log;
	unsigned int logsize = ARRAY_SIZE(log->buffer);
	const char *p;
	va_list va;
	char *q;
	u8 freeable, index;

	if (!log)
		return;

	va_start(va, fmt);
	if (!strchr(fmt, '%')) {
		p = fmt;
		goto unformatted_string;
	}
	if (strcmp(fmt, "%s") == 0) {
		p = va_arg(va, const char *);
		goto unformatted_string;
	}

	q = kvasprintf(GFP_KERNEL, fmt, va);
copied_string:
	if (!q)
		goto store_failure;
	freeable = 1;
	goto store_string;

unformatted_string:
	if ((unsigned long)p >= (unsigned long)__start_rodata &&
	    (unsigned long)p <  (unsigned long)__end_rodata)
		goto const_string;
	if (within_module_core((unsigned long)p, log->owner))
		goto const_string;
	q = kstrdup(p, GFP_KERNEL);
	goto copied_string;

store_failure:
	p = store_failure;
const_string:
	q = (char *)p;
	freeable = 0;
store_string:
	index = log->head & (logsize - 1);
	if ((int)log->head - (int)log->tail == 8) {
		/* The buffer is full, discard the oldest message */
		if (log->need_free & (1 << index))
			kfree(log->buffer[index]);
		log->tail++;
	}

	log->buffer[index] = q;
	log->need_free &= ~(1 << index);
	log->need_free |= freeable << index;
	log->head++;
	va_end(va);
}
EXPORT_SYMBOL(logfc);

/*
 * Free a logging structure.
 */
static void put_fc_log(struct fs_context *fc)
{
	struct fc_log *log = fc->log;
	int i;

	if (log) {
		if (refcount_dec_and_test(&log->usage)) {
			fc->log = NULL;
			for (i = 0; i <= 7; i++)
				if (log->need_free & (1 << i))
					kfree(log->buffer[i]);
			kfree(log);
		}
	}
}

/**
 * put_fs_context - Dispose of a superblock configuration context.
 * @fc: The context to dispose of.
 */
void put_fs_context(struct fs_context *fc)
{
	struct super_block *sb;

	if (fc->root) {
		sb = fc->root->d_sb;
		dput(fc->root);
		fc->root = NULL;
		deactivate_super(sb);
	}

	if (fc->ops && fc->ops->free)
		fc->ops->free(fc);

	security_fs_context_free(fc);
	if (fc->net_ns)
		put_net(fc->net_ns);
	put_user_ns(fc->user_ns);
	if (fc->cred)
		put_cred(fc->cred);
	kfree(fc->subtype);
	put_fc_log(fc);
	put_filesystem(fc->fs_type);
	kfree(fc->source);
	kfree(fc);
}
EXPORT_SYMBOL(put_fs_context);

/*
 * Free the config for a filesystem that doesn't support fs_context.
 */
static void legacy_fs_context_free(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = container_of(fc, struct legacy_fs_context, fc);

	free_secdata(ctx->secdata);
	switch (ctx->param_type) {
	case LEGACY_FS_UNSET_PARAMS:
	case LEGACY_FS_NO_PARAMS:
		break;
	case LEGACY_FS_MAGIC_PARAMS:
		break; /* ctx->data is a weird pointer */
	default:
		kfree(ctx->legacy_data);
		break;
	}
}

/*
 * Duplicate a legacy config.
 */
static int legacy_fs_context_dup(struct fs_context *fc, struct fs_context *src_fc)
{
	struct legacy_fs_context *ctx = container_of(fc, struct legacy_fs_context, fc);
	struct legacy_fs_context *src_ctx = container_of(src_fc, struct legacy_fs_context, fc);

	switch (ctx->param_type) {
	case LEGACY_FS_MONOLITHIC_PARAMS:
	case LEGACY_FS_INDIVIDUAL_PARAMS:
		ctx->legacy_data = kmemdup(src_ctx->legacy_data,
					   src_ctx->data_size, GFP_KERNEL);
		if (!ctx->legacy_data)
			return -ENOMEM;
		/* Fall through */
	default:
		break;
	}
	return 0;
}

/*
 * Add an option to a legacy config.  We build up a comma-separated list of
 * options.
 */
static int legacy_parse_option(struct fs_context *fc, char *opt, size_t len)
{
	struct legacy_fs_context *ctx = container_of(fc, struct legacy_fs_context, fc);
	unsigned int size = ctx->data_size;

	if (ctx->param_type != LEGACY_FS_UNSET_PARAMS &&
	    ctx->param_type != LEGACY_FS_INDIVIDUAL_PARAMS) {
		pr_warn("VFS: Can't mix monolithic and individual options\n");
		return -EINVAL;
	}

	if (len > PAGE_SIZE - 2 - size)
		return -EINVAL;
	if (memchr(opt, ',', len) != NULL)
		return -EINVAL;
	if (!ctx->legacy_data) {
		ctx->legacy_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!ctx->legacy_data)
			return -ENOMEM;
	}

	ctx->legacy_data[size++] = ',';
	memcpy(ctx->legacy_data + size, opt, len);
	size += len;
	ctx->legacy_data[size] = '\0';
	ctx->data_size = size;
	ctx->param_type = LEGACY_FS_INDIVIDUAL_PARAMS;
	return 0;
}

/*
 * Add monolithic mount data.
 */
static int legacy_parse_monolithic(struct fs_context *fc, void *data, size_t data_size)
{
	struct legacy_fs_context *ctx = container_of(fc, struct legacy_fs_context, fc);

	if (ctx->param_type != LEGACY_FS_UNSET_PARAMS) {
		pr_warn("VFS: Can't mix monolithic and individual options\n");
		return -EINVAL;
	}

	if (!data) {
		ctx->param_type = LEGACY_FS_NO_PARAMS;
		return 0;
	}

	ctx->data_size = data_size;
	if (data_size > 0) {
		ctx->legacy_data = kmemdup(data, data_size, GFP_KERNEL);
		if (!ctx->legacy_data)
			return -ENOMEM;
		ctx->param_type = LEGACY_FS_MONOLITHIC_PARAMS;
	} else {
		/* Some filesystems pass weird pointers through that we don't
		 * want to copy.  They can indicate this by setting data_size
		 * to 0.
		 */
		ctx->legacy_data = data;
		ctx->param_type = LEGACY_FS_MAGIC_PARAMS;
	}

	return 0;
}

/*
 * Use the legacy mount validation step to strip out and process security
 * config options.
 */
static int legacy_validate(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = container_of(fc, struct legacy_fs_context, fc);

	switch (ctx->param_type) {
	case LEGACY_FS_UNSET_PARAMS:
		ctx->param_type = LEGACY_FS_NO_PARAMS;
		/* Fall through */
	case LEGACY_FS_NO_PARAMS:
	case LEGACY_FS_MAGIC_PARAMS:
		return 0;
	default:
		break;
	}

	if (ctx->fc.fs_type->fs_flags & FS_BINARY_MOUNTDATA)
		return 0;

	ctx->secdata = alloc_secdata();
	if (!ctx->secdata)
		return -ENOMEM;

	return security_sb_copy_data(ctx->legacy_data, ctx->data_size,
				     ctx->secdata);
}

/*
 * Determine the superblock subtype.
 */
static int legacy_set_subtype(struct fs_context *fc)
{
	const char *subtype = strchr(fc->fs_type->name, '.');

	if (subtype) {
		subtype++;
		if (!subtype[0])
			return -EINVAL;
	} else {
		subtype = "";
	}

	fc->subtype = kstrdup(subtype, GFP_KERNEL);
	if (!fc->subtype)
		return -ENOMEM;
	return 0;
}

/*
 * Get a mountable root with the legacy mount command.
 */
static int legacy_get_tree(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = container_of(fc, struct legacy_fs_context, fc);
	struct super_block *sb;
	struct dentry *root;
	int ret;

	root = ctx->fc.fs_type->mount(ctx->fc.fs_type, ctx->fc.sb_flags,
				      ctx->fc.source, ctx->legacy_data,
				      ctx->data_size);
	if (IS_ERR(root))
		return PTR_ERR(root);

	sb = root->d_sb;
	BUG_ON(!sb);

	if ((ctx->fc.fs_type->fs_flags & FS_HAS_SUBTYPE) &&
	    !fc->subtype) {
		ret = legacy_set_subtype(fc);
		if (ret < 0)
			goto err_sb;
	}

	ctx->fc.root = root;
	return 0;

err_sb:
	dput(root);
	deactivate_locked_super(sb);
	return ret;
}

static const struct fs_context_operations legacy_fs_context_ops = {
	.free			= legacy_fs_context_free,
	.dup			= legacy_fs_context_dup,
	.parse_option		= legacy_parse_option,
	.parse_monolithic	= legacy_parse_monolithic,
	.validate		= legacy_validate,
	.get_tree		= legacy_get_tree,
};
