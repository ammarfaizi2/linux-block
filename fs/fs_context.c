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
#include <linux/fs_parser.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include <linux/security.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/bsearch.h>
#include <net/net_namespace.h>
#include <asm/sections.h>
#include "mount.h"
#include "internal.h"

enum legacy_fs_param {
	LEGACY_FS_UNSET_PARAMS,
	LEGACY_FS_NO_PARAMS,
	LEGACY_FS_MONOLITHIC_PARAMS,
	LEGACY_FS_INDIVIDUAL_PARAMS,
	LEGACY_FS_MAGIC_PARAMS,
};

struct legacy_fs_context {
	char			*legacy_data;	/* Data page for legacy filesystems */
	char			*secdata;
	size_t			data_size;
	enum legacy_fs_param	param_type;
};

static int legacy_init_fs_context(struct fs_context *fc, struct dentry *dentry);

static const struct constant_table common_set_sb_flag[] = {
	{ "dirsync",	SB_DIRSYNC },
	{ "lazytime",	SB_LAZYTIME },
	{ "mand",	SB_MANDLOCK },
	{ "posixacl",	SB_POSIXACL },
	{ "ro",		SB_RDONLY },
	{ "sync",	SB_SYNCHRONOUS },
};

static const struct constant_table common_clear_sb_flag[] = {
	{ "async",	SB_SYNCHRONOUS },
	{ "nolazytime",	SB_LAZYTIME },
	{ "nomand",	SB_MANDLOCK },
	{ "rw",		SB_RDONLY },
	{ "silent",	SB_SILENT },
};

static const char *forbidden_sb_flag[] = {
	"bind",
	"dev",
	"exec",
	"move",
	"noatime",
	"nodev",
	"nodiratime",
	"noexec",
	"norelatime",
	"nostrictatime",
	"nosuid",
	"private",
	"rec",
	"relatime",
	"remount",
	"shared",
	"slave",
	"strictatime",
	"suid",
	"unbindable",
};

static int cmp_flag_name(const void *name, const void *entry)
{
	const char **e = (const char **)entry;
	return strcmp(name, *e);
}

/*
 * Check for a common mount option that manipulates s_flags.
 */
static int vfs_parse_sb_flag(struct fs_context *fc, const char *key)
{
	unsigned int token;

	if (bsearch(key, forbidden_sb_flag, ARRAY_SIZE(forbidden_sb_flag),
		    sizeof(forbidden_sb_flag[0]), cmp_flag_name))
		return -EINVAL;

	token = lookup_constant(common_set_sb_flag, key, 0);
	if (token) {
		fc->sb_flags |= token;
		return 1;
	}

	token = lookup_constant(common_clear_sb_flag, key, 0);
	if (token) {
		fc->sb_flags &= ~token;
		return 1;
	}

	return 0;
}

/**
 * vfs_parse_fs_param - Add a single parameter to a superblock config
 * @fc: The filesystem context to modify
 * @param: The parameter
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
int vfs_parse_fs_param(struct fs_context *fc, struct fs_parameter *param)
{
	int ret;

	if (!param->key) {
		pr_err("Unnamed parameter\n");
		return -EINVAL;
	}

	ret = vfs_parse_sb_flag(fc, param->key);
	if (ret < 0)
		goto out;
	if (ret == 1)
		return 0;

	ret = security_fs_context_parse_param(fc, param);
	if (ret != 0) {
		if (ret == 1)
			/* Param belongs to the LSM; don't pass to the FS */
			ret = 0;
		goto out;
	}

	ret = -EINVAL;
	if (fc->ops->parse_param)
		ret = fc->ops->parse_param(fc, param);
	else if (strcmp(param->key, "source") == 0)
		ret = 0; /* Ignore the source spec */

out:
	return ret;
}
EXPORT_SYMBOL(vfs_parse_fs_param);

/**
 * vfs_parse_fs_string - Convenience function to just parse a string.
 */
int vfs_parse_fs_string(struct fs_context *fc, const char *key,
			const char *value, size_t v_size)
{
	int ret;

	struct fs_parameter param = {
		.key	= key,
		.type	= fs_value_is_string,
		.size	= v_size,
	};

	if (v_size > 0) {
		param.string = kmemdup_nul(value, v_size, GFP_KERNEL);
		if (!param.string)
			return -ENOMEM;
	}

	ret = vfs_parse_fs_param(fc, &param);
	kfree(param.string);
	return ret;
}
EXPORT_SYMBOL(vfs_parse_fs_string);

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
	char *options = data, *key;
	int ret = 0;

	if (!options)
		return 0;

	while ((key = strsep(&options, ",")) != NULL) {
		if (*key) {
			size_t v_len = 0;
			char *value = strchr(key, '=');

			if (value) {
				if (value == key)
					continue;
				*value++ = 0;
				v_len = strlen(value);
			}
			ret = vfs_parse_fs_string(fc, key, value, v_len);
			if (ret < 0)
				break;
		}
	}

	return ret;
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
	int (*init_fs_context)(struct fs_context *, struct dentry *);
	struct fs_context *fc;
	int ret = -ENOMEM;

	fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL);
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
	init_fs_context = fc->fs_type->init_fs_context;
	if (!init_fs_context)
		init_fs_context = legacy_init_fs_context;

	ret = (*init_fs_context)(fc, reference);
	if (ret < 0)
		goto err_fc;
	fc->need_free = true;

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
	const char *p;
	va_list va;
	char *q;
	u8 freeable;

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
	if (!log) {
		switch (fmt[0]) {
		case 'w':
			printk(KERN_WARNING "%s\n", q + 2);
			break;
		case 'e':
			printk(KERN_ERR "%s\n", q + 2);
			break;
		default:
			printk(KERN_NOTICE "%s\n", q + 2);
			break;
		}
		if (freeable)
			kfree(q);
	} else {
		unsigned int logsize = ARRAY_SIZE(log->buffer);
		u8 index;

		index = log->head & (logsize - 1);
		BUILD_BUG_ON(sizeof(log->head) != sizeof(u8) ||
			     sizeof(log->tail) != sizeof(u8));
		if ((u8)(log->head - log->tail) == logsize) {
			/* The buffer is full, discard the oldest message */
			if (log->need_free & (1 << index))
				kfree(log->buffer[index]);
			log->tail++;
		}

		log->buffer[index] = q;
		log->need_free &= ~(1 << index);
		log->need_free |= freeable << index;
		log->head++;
	}
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

	if (fc->need_free && fc->ops && fc->ops->free)
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
	struct legacy_fs_context *ctx = fc->fs_private;

	if (ctx) {
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

		kfree(ctx);
	}
}

/*
 * Duplicate a legacy config.
 */
static int legacy_fs_context_dup(struct fs_context *fc, struct fs_context *src_fc)
{
	struct legacy_fs_context *ctx;
	struct legacy_fs_context *src_ctx = src_fc->fs_private;

	ctx = kmemdup(src_ctx, sizeof(*src_ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	switch (ctx->param_type) {
	case LEGACY_FS_MONOLITHIC_PARAMS:
	case LEGACY_FS_INDIVIDUAL_PARAMS:
		ctx->legacy_data = kmemdup(src_ctx->legacy_data,
					   src_ctx->data_size, GFP_KERNEL);
		if (!ctx->legacy_data) {
			kfree(ctx);
			return -ENOMEM;
		}
		/* Fall through */
	default:
		break;
	}

	fc->fs_private = ctx;
	return 0;
}

/*
 * Add a parameter to a legacy config.  We build up a comma-separated list of
 * options.
 */
static int legacy_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	unsigned int size = ctx->data_size;
	size_t len = 0;

	if (strcmp(param->key, "source") == 0) {
		if (param->type != fs_value_is_string)
			return invalf(fc, "VFS: Legacy: Non-string source");
		if (fc->source)
			return invalf(fc, "VFS: Legacy: Multiple sources");
		fc->source = param->string;
		param->string = NULL;
		return 0;
	}

	if (ctx->param_type != LEGACY_FS_UNSET_PARAMS &&
	    ctx->param_type != LEGACY_FS_INDIVIDUAL_PARAMS)
		return invalf(fc, "VFS: Legacy: Can't mix monolithic and individual options");

	switch (param->type) {
	case fs_value_is_string:
		len = 1 + param->size;
		/* Fall through */
	case fs_value_is_flag:
		len += strlen(param->key);
		break;
	default:
		return invalf(fc, "VFS: Legacy: Parameter type for '%s' not supported",
			      param->key);
	}

	if (len > PAGE_SIZE - 2 - size)
		return invalf(fc, "VFS: Legacy: Cumulative options too large");
	if (strchr(param->key, ',') ||
	    (param->type == fs_value_is_string &&
	     memchr(param->string, ',', param->size)))
		return invalf(fc, "VFS: Legacy: Option '%s' contained comma",
			      param->key);
	if (!ctx->legacy_data) {
		ctx->legacy_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!ctx->legacy_data)
			return -ENOMEM;
	}

	ctx->legacy_data[size++] = ',';
	len = strlen(param->key);
	memcpy(ctx->legacy_data + size, param->key, len);
	size += len;
	if (param->type == fs_value_is_string) {
		ctx->legacy_data[size++] = '=';
		memcpy(ctx->legacy_data + size, param->string, param->size);
		size += param->size;
	}
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
	struct legacy_fs_context *ctx = fc->fs_private;

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
	struct legacy_fs_context *ctx = fc->fs_private;

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

	if (fc->fs_type->fs_flags & FS_BINARY_MOUNTDATA)
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
	struct legacy_fs_context *ctx = fc->fs_private;
	struct super_block *sb;
	struct dentry *root;
	int ret;

	root = fc->fs_type->mount(fc->fs_type, fc->sb_flags,
				      fc->source, ctx->legacy_data,
				      ctx->data_size);
	if (IS_ERR(root))
		return PTR_ERR(root);

	sb = root->d_sb;
	BUG_ON(!sb);

	if ((fc->fs_type->fs_flags & FS_HAS_SUBTYPE) &&
	    !fc->subtype) {
		ret = legacy_set_subtype(fc);
		if (ret < 0)
			goto err_sb;
	}

	fc->root = root;
	return 0;

err_sb:
	dput(root);
	deactivate_locked_super(sb);
	return ret;
}

const struct fs_context_operations legacy_fs_context_ops = {
	.free			= legacy_fs_context_free,
	.dup			= legacy_fs_context_dup,
	.parse_param		= legacy_parse_param,
	.parse_monolithic	= legacy_parse_monolithic,
	.validate		= legacy_validate,
	.get_tree		= legacy_get_tree,
};

/*
 * Initialise a legacy context for a filesystem that doesn't support
 * fs_context.
 */
static int legacy_init_fs_context(struct fs_context *fc, struct dentry *dentry)
{

	fc->fs_private = kzalloc(sizeof(struct legacy_fs_context), GFP_KERNEL);
	if (!fc->fs_private)
		return -ENOMEM;

	fc->ops = &legacy_fs_context_ops;
	return 0;
}
