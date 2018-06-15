/* Filesystem superblock creation and reconfiguration context.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_FS_CONTEXT_H
#define _LINUX_FS_CONTEXT_H

#include <linux/kernel.h>
#include <linux/errno.h>

struct cred;
struct dentry;
struct file_operations;
struct file_system_type;
struct mnt_namespace;
struct net;
struct pid_namespace;
struct super_block;
struct user_namespace;
struct vfsmount;
struct path;

enum fs_context_purpose {
	FS_CONTEXT_FOR_USER_MOUNT,	/* New superblock for user-specified mount */
	FS_CONTEXT_FOR_KERNEL_MOUNT,	/* New superblock for kernel-internal mount */
	FS_CONTEXT_FOR_SUBMOUNT,	/* New superblock for automatic submount */
	FS_CONTEXT_FOR_RECONFIGURE,	/* Superblock reconfiguration (remount) */
};

/*
 * Userspace usage phase for fsopen/fspick.
 */
enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS,	/* Loading params for sb creation */
	FS_CONTEXT_CREATING,		/* A superblock is being created */
	FS_CONTEXT_AWAITING_MOUNT,	/* Superblock created, awaiting fsmount() */
	FS_CONTEXT_AWAITING_RECONF,	/* Awaiting initialisation for reconfiguration */
	FS_CONTEXT_RECONF_PARAMS,	/* Loading params for reconfiguration */
	FS_CONTEXT_RECONFIGURING,	/* Reconfiguring the superblock */
	FS_CONTEXT_FAILED,		/* Failed to correctly transition a context */
};

/*
 * Filesystem context for holding the parameters used in the creation or
 * reconfiguration of a superblock.
 *
 * Superblock creation fills in ->root whereas reconfiguration begins with this
 * already set.
 *
 * See Documentation/filesystems/mounting.txt
 */
struct fs_context {
	const struct fs_context_operations *ops;
	struct file_system_type	*fs_type;
	void			*fs_private;	/* The filesystem's context */
	struct dentry		*root;		/* The root and superblock */
	struct user_namespace	*user_ns;	/* The user namespace for this mount */
	struct net		*net_ns;	/* The network namespace for this mount */
	const struct cred	*cred;		/* The mounter's credentials */
	char			*source;	/* The source name (eg. dev path) */
	char			*subtype;	/* The subtype to set on the superblock */
	void			*security;	/* The LSM context */
	void			*s_fs_info;	/* Proposed s_fs_info */
	unsigned int		sb_flags;	/* Proposed superblock flags (SB_*) */
	enum fs_context_purpose	purpose:8;
	enum fs_context_phase	phase:8;	/* The phase the context is in */
	bool			sloppy:1;	/* T if unrecognised options are okay */
	bool			silent:1;	/* T if "o silent" specified */
};

struct fs_context_operations {
	void (*free)(struct fs_context *fc);
	int (*dup)(struct fs_context *fc, struct fs_context *src_fc);
	int (*parse_source)(struct fs_context *fc, char *source);
	int (*parse_option)(struct fs_context *fc, char *opt, size_t len);
	int (*parse_monolithic)(struct fs_context *fc, void *data, size_t data_size);
	int (*validate)(struct fs_context *fc);
	int (*get_tree)(struct fs_context *fc);
};

/*
 * fs_context manipulation functions.
 */
extern struct fs_context *vfs_new_fs_context(struct file_system_type *fs_type,
					     struct dentry *reference,
					     unsigned int ms_flags,
					     enum fs_context_purpose purpose);
extern struct fs_context *vfs_sb_reconfig(struct path *path, unsigned int ms_flags);
extern struct fs_context *vfs_dup_fs_context(struct fs_context *src);
extern int vfs_set_fs_source(struct fs_context *fc, const char *source, size_t len);
extern int vfs_parse_fs_option(struct fs_context *fc, char *key, void *value, size_t v_len);
extern int generic_parse_monolithic(struct fs_context *fc, void *data, size_t data_size);
extern int vfs_get_tree(struct fs_context *fc);
extern void put_fs_context(struct fs_context *fc);

/*
 * sget() wrapper to be called from the ->get_tree() op.
 */
enum vfs_get_super_keying {
	vfs_get_single_super,	/* Only one such superblock may exist */
	vfs_get_keyed_super,	/* Superblocks with different s_fs_info keys may exist */
	vfs_get_independent_super, /* Multiple independent superblocks may exist */
};
extern int vfs_get_super(struct fs_context *fc,
			 enum vfs_get_super_keying keying,
			 int (*fill_super)(struct super_block *sb,
					   struct fs_context *fc));

#endif /* _LINUX_FS_CONTEXT_H */
