/*
 *  inode.c - part of tracefs, a pseudo file system for activating tracing
 *
 * Based on debugfs by: Greg Kroah-Hartman <greg@kroah.com>
 *
 *  Copyright (C) 2014 Red Hat Inc, author: Steven Rostedt <srostedt@redhat.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License version
 *	2 as published by the Free Software Foundation.
 *
 * tracefs is the file system that is used by the tracing infrastructure.
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/tracefs.h>
#include <linux/fsnotify.h>
#include <linux/seq_file.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>

#define TRACEFS_DEFAULT_MODE	0700

static struct vfsmount *tracefs_mount;
static int tracefs_mount_count;
static bool tracefs_registered;

static ssize_t default_read_file(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t default_write_file(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	return count;
}

static const struct file_operations tracefs_file_operations = {
	.read =		default_read_file,
	.write =	default_write_file,
	.open =		simple_open,
	.llseek =	noop_llseek,
};

static int tracefs_syscall_mkdir(struct inode *inode, struct dentry *dentry, umode_t mode)
{
	struct tracefs_dir_ops *ops = inode ? inode->i_private : NULL;
	int ret;

	if (!ops)
		return -EPERM;

	/*
	 * The mkdir call can call the generic functions that create
	 * the files within the tracefs system. Do not relock the parent,
	 * it was locked by the caller of this function.
	 */
	ops->lock_owner = current;
	ret = ops->mkdir(dentry->d_iname);
	ops->lock_owner = NULL;

	return ret;
}

static int tracefs_syscall_rmdir(struct inode *inode, struct dentry *dentry)
{
	struct tracefs_dir_ops *ops = inode->i_private;
	int ret;

	if (!ops)
		return -EPERM;

	/*
	 * The rmdir call can call the generic functions that remove
	 * the files within the tracefs system. Do not relock the parent,
	 * it was locked by the caller of this function.
	 */
	ops->lock_owner = current;
	/* The caller also locked the dentry, do not lock that again either */
	dentry->d_inode->i_private = ops;
	ret = ops->rmdir(dentry->d_iname);
	dentry->d_inode->i_private = NULL;
	ops->lock_owner = NULL;

	return ret;
}

const struct inode_operations tracefs_dir_inode_operations = {
	.lookup		= simple_lookup,
	.mkdir		= tracefs_syscall_mkdir,
	.rmdir		= tracefs_syscall_rmdir,
};

static struct inode *tracefs_get_inode(struct super_block *sb, umode_t mode, dev_t dev,
				      void *data, const struct file_operations *fops)

{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode->i_mode = mode;
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			inode->i_fop = fops ? fops : &tracefs_file_operations;
			inode->i_private = data;
			break;
		case S_IFDIR:
			inode->i_op = &tracefs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2
			 * (for "." entry) */
			inc_nlink(inode);
			break;
		}
	}
	return inode;
}

/* SMP-safe */
static int tracefs_mknod(struct inode *dir, struct dentry *dentry,
			 umode_t mode, dev_t dev, void *data,
			 const struct file_operations *fops)
{
	struct inode *inode;
	int error = -EPERM;

	if (dentry->d_inode)
		return -EEXIST;

	inode = tracefs_get_inode(dir->i_sb, mode, dev, data, fops);
	if (inode) {
		d_instantiate(dentry, inode);
		dget(dentry);
		error = 0;
	}
	return error;
}

static int tracefs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int res;

	mode = (mode & (S_IRWXUGO | S_ISVTX)) | S_IFDIR;
	res = tracefs_mknod(dir, dentry, mode, 0, NULL, NULL);
	if (!res) {
		inc_nlink(dir);
		fsnotify_mkdir(dir, dentry);
	}
	return res;
}

static int tracefs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			  void *data, const struct file_operations *fops)
{
	int res;

	mode = (mode & S_IALLUGO) | S_IFREG;
	res = tracefs_mknod(dir, dentry, mode, 0, data, fops);
	if (!res)
		fsnotify_create(dir, dentry);
	return res;
}

void tracefs_add_dir_ops(struct dentry *dentry, struct tracefs_dir_ops *ops)
{
	struct inode *inode = dentry->d_inode;

	if (!inode)
		return;

	inode->i_private = ops;
}

struct tracefs_mount_opts {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
};

enum {
	Opt_uid,
	Opt_gid,
	Opt_mode,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_err, NULL}
};

struct tracefs_fs_info {
	struct tracefs_mount_opts mount_opts;
};

static int tracefs_parse_options(char *data, struct tracefs_mount_opts *opts)
{
	substring_t args[MAX_OPT_ARGS];
	int option;
	int token;
	kuid_t uid;
	kgid_t gid;
	char *p;

	opts->mode = TRACEFS_DEFAULT_MODE;

	while ((p = strsep(&data, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_uid:
			if (match_int(&args[0], &option))
				return -EINVAL;
			uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(uid))
				return -EINVAL;
			opts->uid = uid;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return -EINVAL;
			gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(gid))
				return -EINVAL;
			opts->gid = gid;
			break;
		case Opt_mode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->mode = option & S_IALLUGO;
			break;
		/*
		 * We might like to report bad mount options here;
		 * but traditionally tracefs has ignored all mount options
		 */
		}
	}

	return 0;
}

static int tracefs_apply_options(struct super_block *sb)
{
	struct tracefs_fs_info *fsi = sb->s_fs_info;
	struct inode *inode = sb->s_root->d_inode;
	struct tracefs_mount_opts *opts = &fsi->mount_opts;

	inode->i_mode &= ~S_IALLUGO;
	inode->i_mode |= opts->mode;

	inode->i_uid = opts->uid;
	inode->i_gid = opts->gid;

	return 0;
}

static int tracefs_remount(struct super_block *sb, int *flags, char *data)
{
	int err;
	struct tracefs_fs_info *fsi = sb->s_fs_info;

	sync_filesystem(sb);
	err = tracefs_parse_options(data, &fsi->mount_opts);
	if (err)
		goto fail;

	tracefs_apply_options(sb);

fail:
	return err;
}

static int tracefs_show_options(struct seq_file *m, struct dentry *root)
{
	struct tracefs_fs_info *fsi = root->d_sb->s_fs_info;
	struct tracefs_mount_opts *opts = &fsi->mount_opts;

	if (!uid_eq(opts->uid, GLOBAL_ROOT_UID))
		seq_printf(m, ",uid=%u",
			   from_kuid_munged(&init_user_ns, opts->uid));
	if (!gid_eq(opts->gid, GLOBAL_ROOT_GID))
		seq_printf(m, ",gid=%u",
			   from_kgid_munged(&init_user_ns, opts->gid));
	if (opts->mode != TRACEFS_DEFAULT_MODE)
		seq_printf(m, ",mode=%o", opts->mode);

	return 0;
}

static const struct super_operations tracefs_super_operations = {
	.statfs		= simple_statfs,
	.remount_fs	= tracefs_remount,
	.show_options	= tracefs_show_options,
};

static int trace_fill_super(struct super_block *sb, void *data, int silent)
{
	static struct tree_descr trace_files[] = {{""}};
	struct tracefs_fs_info *fsi;
	int err;

	save_mount_options(sb, data);

	fsi = kzalloc(sizeof(struct tracefs_fs_info), GFP_KERNEL);
	sb->s_fs_info = fsi;
	if (!fsi) {
		err = -ENOMEM;
		goto fail;
	}

	err = tracefs_parse_options(data, &fsi->mount_opts);
	if (err)
		goto fail;

	err  =  simple_fill_super(sb, TRACEFS_MAGIC, trace_files);
	if (err)
		goto fail;

	sb->s_op = &tracefs_super_operations;

	tracefs_apply_options(sb);

	return 0;

fail:
	kfree(fsi);
	sb->s_fs_info = NULL;
	return err;
}

static struct dentry *trace_mount(struct file_system_type *fs_type,
			int flags, const char *dev_name,
			void *data)
{
	return mount_single(fs_type, flags, data, trace_fill_super);
}

static struct file_system_type trace_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"tracefs",
	.mount =	trace_mount,
	.kill_sb =	kill_litter_super,
};
MODULE_ALIAS_FS("tracefs");

static struct dentry *__create_file(const char *name, umode_t mode,
				    struct dentry *parent, void *data,
				    const struct file_operations *fops)
{
	struct tracefs_dir_ops *ops;
	struct dentry *dentry = NULL;
	struct inode *parent_inode;
	int error;

	pr_debug("tracefs: creating file '%s'\n",name);

	error = simple_pin_fs(&trace_fs_type, &tracefs_mount,
			      &tracefs_mount_count);
	if (error)
		goto exit;

	/* If the parent is not specified, we create it in the root.
	 * We need the root dentry to do this, which is in the super
	 * block. A pointer to that is in the struct vfsmount that we
	 * have around.
	 */
	if (!parent)
		parent = tracefs_mount->mnt_root;

	parent_inode = parent->d_inode;
	ops = parent_inode->i_private;

	if (!ops || ops->lock_owner != current)
		mutex_lock(&parent->d_inode->i_mutex);

	dentry = lookup_one_len(name, parent, strlen(name));
	if (!IS_ERR(dentry)) {
		switch (mode & S_IFMT) {
		case S_IFDIR:
			error = tracefs_mkdir(parent->d_inode, dentry, mode);

			break;
		default:
			error = tracefs_create(parent->d_inode, dentry, mode,
					       data, fops);
			break;
		}
		dput(dentry);
	} else
		error = PTR_ERR(dentry);
	if (!ops || ops->lock_owner != current)
		mutex_unlock(&parent->d_inode->i_mutex);

	if (error) {
		dentry = NULL;
		simple_release_fs(&tracefs_mount, &tracefs_mount_count);
	}
exit:
	return dentry;
}

/**
 * tracefs_create_file - create a file in the tracefs filesystem
 * @name: a pointer to a string containing the name of the file to create.
 * @mode: the permission that the file should have.
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is NULL, then the
 *          file will be created in the root of the tracefs filesystem.
 * @data: a pointer to something that the caller will want to get to later
 *        on.  The inode.i_private pointer will point to this value on
 *        the open() call.
 * @fops: a pointer to a struct file_operations that should be used for
 *        this file.
 *
 * This is the basic "create a file" function for tracefs.  It allows for a
 * wide range of flexibility in creating a file, or a directory (if you want
 * to create a directory, the tracefs_create_dir() function is
 * recommended to be used instead.)
 *
 * This function will return a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the tracefs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here.)  If an error occurs, %NULL will be returned.
 *
 * If tracefs is not enabled in the kernel, the value -%ENODEV will be
 * returned.
 */
struct dentry *tracefs_create_file(const char *name, umode_t mode,
				   struct dentry *parent, void *data,
				   const struct file_operations *fops)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case 0:
		break;
	default:
		BUG();
	}

	return __create_file(name, mode, parent, data, fops);
}

/**
 * tracefs_create_dir - create a directory in the tracefs filesystem
 * @name: a pointer to a string containing the name of the directory to
 *        create.
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is NULL, then the
 *          directory will be created in the root of the tracefs filesystem.
 *
 * This function creates a directory in tracefs with the given name.
 *
 * This function will return a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the tracefs_remove() function when the file is
 * to be removed. If an error occurs, %NULL will be returned.
 *
 * If tracing is not enabled in the kernel, the value -%ENODEV will be
 * returned.
 */
struct dentry *tracefs_create_dir(const char *name, struct dentry *parent)
{
	return __create_file(name, S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
				   parent, NULL, NULL);
}

static inline int tracefs_positive(struct dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

static int __tracefs_remove(struct dentry *dentry, struct dentry *parent)
{
	int ret = 0;

	if (tracefs_positive(dentry)) {
		if (dentry->d_inode) {
			dget(dentry);
			switch (dentry->d_inode->i_mode & S_IFMT) {
			case S_IFDIR:
				ret = simple_rmdir(parent->d_inode, dentry);
				break;
			default:
				simple_unlink(parent->d_inode, dentry);
				break;
			}
			if (!ret)
				d_delete(dentry);
			dput(dentry);
		}
	}
	return ret;
}

/**
 * tracefs_remove - removes a file or directory from the tracefs filesystem
 * @dentry: a pointer to a the dentry of the file or directory to be
 *          removed.
 *
 * This function removes a file or directory in tracefs that was previously
 * created with a call to another tracefs function (like
 * tracefs_create_file() or variants thereof.)
 */
void tracefs_remove(struct dentry *dentry)
{
	struct tracefs_dir_ops *ops;
	struct dentry *parent;
	struct inode *inode;
	int ret;

	if (IS_ERR_OR_NULL(dentry))
		return;

	parent = dentry->d_parent;
	if (!parent || !parent->d_inode)
		return;

	inode = parent->d_inode;
	ops = inode->i_private;
	if (!ops || ops->lock_owner != current)
		mutex_lock(&parent->d_inode->i_mutex);
	ret = __tracefs_remove(dentry, parent);
	if (!ops || ops->lock_owner != current)
		mutex_unlock(&parent->d_inode->i_mutex);
	if (!ret)
		simple_release_fs(&tracefs_mount, &tracefs_mount_count);
}

/**
 * tracefs_remove_recursive - recursively removes a directory
 * @dentry: a pointer to a the dentry of the directory to be removed.
 *
 * This function recursively removes a directory tree in tracefs that
 * was previously created with a call to another tracefs function
 * (like tracefs_create_file() or variants thereof.)
 */
void tracefs_remove_recursive(struct dentry *dentry)
{
	struct tracefs_dir_ops *ops;
	struct dentry *child, *parent;

	if (IS_ERR_OR_NULL(dentry))
		return;

	parent = dentry->d_parent;
	if (!parent || !parent->d_inode)
		return;

	parent = dentry;
 down:
	ops = parent->d_inode->i_private;
	if (!ops || ops->lock_owner != current)
		mutex_lock(&parent->d_inode->i_mutex);
 loop:
	/*
	 * The parent->d_subdirs is protected by the d_lock. Outside that
	 * lock, the child can be unlinked and set to be freed which can
	 * use the d_u.d_child as the rcu head and corrupt this list.
	 */
	spin_lock(&parent->d_lock);
	list_for_each_entry(child, &parent->d_subdirs, d_child) {
		if (!tracefs_positive(child))
			continue;

		/* perhaps simple_empty(child) makes more sense */
		if (!list_empty(&child->d_subdirs)) {
			spin_unlock(&parent->d_lock);
			if (!ops || ops->lock_owner != current)
				mutex_unlock(&parent->d_inode->i_mutex);
			parent = child;
			goto down;
		}

		spin_unlock(&parent->d_lock);

		if (!__tracefs_remove(child, parent))
			simple_release_fs(&tracefs_mount, &tracefs_mount_count);

		/*
		 * The parent->d_lock protects agaist child from unlinking
		 * from d_subdirs. When releasing the parent->d_lock we can
		 * no longer trust that the next pointer is valid.
		 * Restart the loop. We'll skip this one with the
		 * tracefs_positive() check.
		 */
		goto loop;
	}
	spin_unlock(&parent->d_lock);

	if (!ops || ops->lock_owner != current)
		mutex_unlock(&parent->d_inode->i_mutex);
	child = parent;
	parent = parent->d_parent;
	ops = parent->d_inode->i_private;
	if (!ops || ops->lock_owner != current)
		mutex_lock(&parent->d_inode->i_mutex);

	if (child != dentry)
		/* go up */
		goto loop;

	if (!__tracefs_remove(child, parent))
		simple_release_fs(&tracefs_mount, &tracefs_mount_count);
	if (!ops || ops->lock_owner != current)
		mutex_unlock(&parent->d_inode->i_mutex);
}

/**
 * tracefs_initialized - Tells whether tracefs has been registered
 */
bool tracefs_initialized(void)
{
	return tracefs_registered;
}

static int __init tracefs_init(void)
{
	int retval;

	retval = register_filesystem(&trace_fs_type);
	if (!retval)
		tracefs_registered = true;

	return retval;
}
core_initcall(tracefs_init);
