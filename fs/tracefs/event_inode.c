// SPDX-License-Identifier: GPL-2.0-only
/*
 *  event_inode.c - part of tracefs, a pseudo file system for activating tracing
 *
 *  Copyright (C) 2020 VMware Inc, author: Steven Rostedt <srostedt@vmware.com>
 *
 * eventfs is used to show trace events with one set of dentries
 */
#include <linux/fsnotify.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/tracefs.h>
#include "internal.h"

#define FILE_NOT_CREATED	1
#define FILE_CREATED		2

struct eventfs_file {
	struct list_head		list;
	umode_t				mode;
	const char			*name;
	const struct file_operations	*fops;
	void				*data;
	int 				status;
};

struct eventfs_inode {
	struct list_head		e_top_files;
};

/**
 * eventfs_create_file - create a file in the tracefs filesystem
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
struct dentry *eventfs_create_file(const char *name, umode_t mode,
				   struct dentry *parent, void *data,
				   const struct file_operations *fops)
{
	struct dentry *dentry;
	struct inode *inode;

	if (security_locked_down(LOCKDOWN_TRACEFS))
		return NULL;

	if (!(mode & S_IFMT))
		mode |= S_IFREG;
	BUG_ON(!S_ISREG(mode));
	dentry = eventfs_start_creating(name, parent);

	if (IS_ERR(dentry))
		return NULL;

	inode = tracefs_get_inode(dentry->d_sb);
	if (unlikely(!inode))
		return eventfs_failed_creating(dentry);

	inode->i_mode = mode;
	inode->i_fop = fops; // todo ? fops : &tracefs_file_operations;
	inode->i_private = data;
	d_instantiate(dentry, inode);
	fsnotify_create(dentry->d_parent->d_inode, dentry);
	return eventfs_end_creating(dentry);
}


void eventfs_free_inode(struct tracefs_inode *ti)
{
	struct eventfs_inode *ei = ti->private;
	struct eventfs_file *n, *f;

	list_for_each_entry_safe(f, n, &ei->e_top_files, list) {
		kfree(f->name);
		kfree(f);
	}
	kfree(ei);
}

static int eventfs_root_getattr(const struct path *path, struct kstat *stat,
				u32 request_mask, unsigned int query_flags)
{
	generic_fillattr(d_inode(path->dentry), stat);
	stat->nlink = 1;
	return 0;
}

typedef struct dentry *instantiate_t(struct dentry *,
				     struct task_struct *, const void *);

static bool eventfs_fill_cache(struct file *file, struct dir_context *ctx,
	const char *name, unsigned int len,
	instantiate_t instantiate, struct task_struct *task, const void *ptr)
{
	struct dentry *child, *dir = file->f_path.dentry;
	struct qstr qname = QSTR_INIT(name, len);
	struct inode *inode;
	unsigned type = DT_UNKNOWN;
	ino_t ino = 1;

	child = d_hash_and_lookup(dir, &qname);
	if (!child) {
		DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);
		child = d_alloc_parallel(dir, &qname, &wq);
		if (IS_ERR(child))
			goto end_instantiate;
		if (d_in_lookup(child)) {
			struct dentry *res;
			res = instantiate(child, task, ptr);
			d_lookup_done(child);
			if (unlikely(res)) {
				dput(child);
				child = res;
				if (IS_ERR(child))
					goto end_instantiate;
			}
		}
	}
	inode = d_inode(child);
	ino = inode->i_ino;
	type = inode->i_mode >> 12;
	dput(child);
end_instantiate:
	return dir_emit(ctx, name, len, ino, type);
}

static struct dentry *eventfs_lookup(struct inode *dir, struct dentry *dentry,
			      unsigned int flags)
{
	return NULL;
#if 0
	struct proc_fs_info *fs_info = proc_sb_info(dir->i_sb);

	if (fs_info->pidonly == PROC_PIDONLY_ON)
		return ERR_PTR(-ENOENT);

	return proc_lookup_de(dir, dentry, PDE(dir));
#endif
}

static struct dentry *eventfs_root_lookup(struct inode * dir,
					  struct dentry * dentry,
					  unsigned int flags)
{
	return simple_lookup(dir, dentry, flags);
}

static int eventfs_top_readdir(struct file *file, struct dir_context *ctx)
{

	struct tracefs_inode *ti;
	struct eventfs_inode *ei;
	struct eventfs_file *ef, *n;
	struct inode *inode = file_inode(file);
	struct dentry *dentry = file_dentry(file);

	ti = get_tracefs(inode);
	if (!(ti->flags & TRACEFS_EVENT_INODE))
		return -EINVAL;

	ei = ti->private;

	list_for_each_entry_safe(ef, n, &ei->e_top_files, list) {
		if (ef->status == FILE_NOT_CREATED) {
			eventfs_create_file(ef->name, ef->mode, dentry, ef->data, ef->fops);
			ef->status = FILE_CREATED;
		}
	}
	return dcache_readdir(file, ctx);
}

static const struct file_operations eventfs_file_operations = {
	.open           = dcache_dir_open,
	.read		= generic_read_dir,
//	.iterate_shared = dcache_readdir,
	.iterate_shared	= eventfs_top_readdir,
	.llseek		= generic_file_llseek,
};

static const struct inode_operations eventfs_root_inode_operations = {
	.lookup		= eventfs_root_lookup,
	.getattr	= eventfs_root_getattr,
};


const struct inode_operations eventfs_root_dir_inode_operations = {
	.lookup		= eventfs_root_lookup,
};

int eventfs_create_top_file(const char *name, umode_t mode,
			    struct dentry *parent, void *data,
			    const struct file_operations *fops)
{
	struct tracefs_inode *ti;
	struct eventfs_inode *ei;
	struct eventfs_file *ef;

	if (!parent)
		return -EINVAL;

	if (!(mode & S_IFMT))
		mode |= S_IFREG;

	if (!parent->d_inode)
		return -EINVAL;

	ti = get_tracefs(parent->d_inode);
	if (!(ti->flags & TRACEFS_EVENT_INODE))
		return -EINVAL;

	ei = ti->private;

	ef = kmalloc(sizeof(*ef), GFP_KERNEL);
	if (!ef)
		return -ENOMEM;

	ef->name = kstrdup(name, GFP_KERNEL);
	if (!ef->name) {
		kfree(ef);
		return -ENOMEM;
	}

	ef->mode = mode;
	ef->data = data;
	ef->fops = fops;
	ef->status = FILE_NOT_CREATED;

	list_add_tail(&ef->list, &ei->e_top_files);
	return 1;
}

/**
 * eventfs_create_dir - create the trace event structure
 * @name: a pointer to a string containing the name of the directory to
 *        create.
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is NULL, then the
 *          directory will be created in the root of the tracefs filesystem.
 * @events: A pointer to the list of events to use.
 *
 * This function creates the top of the trace event directory.
 * All the files are created on the fly when they are looked up,
 * and the dentry and inodes will be removed when they are done.
 */
struct dentry *eventfs_create_dir(const char *name, struct dentry *parent)
{
	struct dentry *dentry = tracefs_start_creating(name, parent);
	struct eventfs_inode *ei;
	struct tracefs_inode *ti;
	struct inode *inode;

	if (IS_ERR(dentry))
		return NULL;

	ei = kzalloc(sizeof(*ei), GFP_KERNEL);
	if (!ei)
		return NULL;
	inode = tracefs_get_inode(dentry->d_sb);
	if (unlikely(!inode)) {
		kfree(ei);
		return tracefs_failed_creating(dentry);
	}

	INIT_LIST_HEAD(&ei->e_top_files);

	ti = get_tracefs(inode);
	ti->flags |= TRACEFS_EVENT_INODE;
	ti->private = ei;

	inode->i_mode = S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO | S_IWUGO;
	inode->i_op = &eventfs_root_dir_inode_operations;
	inode->i_fop = &eventfs_file_operations;

	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	inc_nlink(inode);
	d_instantiate(dentry, inode);
	inc_nlink(dentry->d_parent->d_inode);
	fsnotify_mkdir(dentry->d_parent->d_inode, dentry);
	return tracefs_end_creating(dentry);
}
