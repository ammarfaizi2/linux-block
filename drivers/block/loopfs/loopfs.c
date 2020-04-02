/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/fs.h>
#include <linux/fs_parser.h>
#include <linux/fsnotify.h>
#include <linux/genhd.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>

#include "../loop.h"
#include "loopfs.h"

#define FIRST_INODE 1
#define SECOND_INODE 2
#define INODE_OFFSET 3

struct loopfs_info {
	kuid_t root_uid;
	kgid_t root_gid;
	struct dentry *control_dentry;
	struct user_namespace *user_ns;
	atomic_t users;
};

static inline struct loopfs_info *LOOPFS_SB(const struct super_block *sb)
{
	return sb->s_fs_info;
}

struct super_block *loopfs_i_sb(const struct inode *inode)
{
	if (inode && inode->i_sb->s_magic == LOOPFS_SUPER_MAGIC)
		return inode->i_sb;

	return NULL;
}

bool loopfs_device(const struct loop_device *lo)
{
	return lo->lo_info != NULL;
}

struct user_namespace *loopfs_ns(const struct loop_device *lo)
{
	if (loopfs_device(lo))
		return lo->lo_info->sbi->user_ns;
	return &init_user_ns;
}

bool loopfs_access(const struct inode *first, struct loop_device *lo)
{
	struct inode *second = NULL;

	if (loopfs_device(lo)) {
		second = lo->lo_info->lo_inode;
		if (!second)
			return false; /* loopfs already gone */
	}
	return loopfs_i_sb(first) == loopfs_i_sb(second);
}

bool loopfs_wants_remove(const struct loop_device *lo)
{
	return loopfs_device(lo) &&
	       (lo->lo_info->lo_flags & LOOPFS_FLAGS_INACTIVE);
}

void loopfs_init(struct gendisk *disk, struct inode *inode)
{
	if (loopfs_i_sb(inode)) {
		disk->user_ns = loopfs_i_sb(inode)->s_user_ns;
		disk_to_dev(disk)->no_devnode = true;
	}
}

/**
 * loopfs_add - allocate inode from super block of a loopfs mount
 * @lo:		loop device for which we are creating a new device entry
 * @ref_inode:	inode from wich the super block will be taken
 * @device_nr:  device number of the associated disk device
 *
 * This function creates a new device node for @lo.
 * Minor numbers are limited and tracked globally. The
 * function will stash a struct loop_device for the specific loop
 * device in i_private of the inode.
 * It will go on to allocate a new inode from the super block of the
 * filesystem mount, stash a struct loop_device in its i_private field
 * and attach a dentry to that inode.
 *
 * Return: 0 on success, negative errno on failure
 */
int loopfs_add(struct loop_device *lo, struct inode *ref_inode, dev_t device_nr)
{
	int ret;
	char name[DISK_NAME_LEN];
	struct super_block *sb;
	struct loopfs_info *info;
	struct dentry *root, *dentry;
	struct inode *inode;
	struct lo_loopfs *lo_info;

	sb = loopfs_i_sb(ref_inode);
	if (!sb)
		return 0;

	if (MAJOR(device_nr) != LOOP_MAJOR)
		return -EINVAL;

	lo_info = kzalloc(sizeof(struct lo_loopfs), GFP_KERNEL);
	if (!lo_info) {
		ret = -ENOMEM;
		goto err;
	}

	info = LOOPFS_SB(sb);
	lo_info->lo_ucount = inc_ucount(sb->s_user_ns,
					info->root_uid, UCOUNT_LOOP_DEVICES);
	if (!lo_info->lo_ucount) {
		ret = -ENOSPC;
		goto err;
	}

	if (snprintf(name, sizeof(name), "loop%d", lo->lo_number) >= sizeof(name)) {
		ret = -EINVAL;
		goto err;
	}

	inode = new_inode(sb);
	if (!inode) {
		ret = -ENOMEM;
		goto err;
	}

	/*
	 * The i_fop field will be set to the correct fops by the device layer
	 * when the loop device in this loopfs instance is opened.
	 */
	inode->i_ino = MINOR(device_nr) + INODE_OFFSET;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_uid = info->root_uid;
	inode->i_gid = info->root_gid;
	init_special_inode(inode, S_IFBLK | 0600, device_nr);

	root = sb->s_root;
	inode_lock(d_inode(root));
	/* look it up */
	dentry = lookup_one_len(name, root, strlen(name));
	if (IS_ERR(dentry)) {
		inode_unlock(d_inode(root));
		iput(inode);
		ret = PTR_ERR(dentry);
		goto err;
	}

	if (d_really_is_positive(dentry)) {
		/* already exists */
		dput(dentry);
		inode_unlock(d_inode(root));
		iput(inode);
		ret = -EEXIST;
		goto err;
	}

	d_instantiate(dentry, inode);
	fsnotify_create(d_inode(root), dentry);
	inode_unlock(d_inode(root));

	lo_info->lo_inode = inode;
	lo->lo_info = lo_info;
	atomic_inc(&info->users);
	lo->lo_info->sbi = info;
	inode->i_private = lo;

	return 0;

err:
	if (lo_info->lo_ucount)
		dec_ucount(lo_info->lo_ucount, UCOUNT_LOOP_DEVICES);
	kfree(lo_info);
	return ret;
}

void loopfs_remove(struct loop_device *lo)
{
	struct lo_loopfs *lo_info = lo->lo_info;
	struct loopfs_info *sbi;
	struct inode *inode;
	struct super_block *sb;
	struct dentry *root, *dentry;

	if (!lo_info)
		return;

	inode = lo_info->lo_inode;
	if (!inode || !S_ISBLK(inode->i_mode) || imajor(inode) != LOOP_MAJOR)
		goto out;

	sb = loopfs_i_sb(inode);
	lo_info->lo_inode = NULL;

	/*
	 * The root dentry is always the parent dentry since we don't allow
	 * creation of directories.
	 */
	root = sb->s_root;

	inode_lock(d_inode(root));
	dentry = d_find_any_alias(inode);
	if (dentry && simple_positive(dentry)) {
		simple_unlink(d_inode(root), dentry);
		d_delete(dentry);
	}
	dput(dentry);
	inode_unlock(d_inode(root));

out:
	if (lo_info->lo_ucount)
		dec_ucount(lo_info->lo_ucount, UCOUNT_LOOP_DEVICES);
	sbi = lo_info->sbi;
	if (atomic_dec_and_test(&sbi->users)) {
		put_user_ns(sbi->user_ns);
		kfree(sbi);
	}
	kfree(lo->lo_info);
	lo->lo_info = NULL;
}

/**
 * loopfs_loop_ctl_create - create a new loop-control device
 * @sb: super block of the loopfs mount
 *
 * This function creates a new loop-control device node in the loopfs mount
 * referred to by @sb.
 *
 * Return: 0 on success, negative errno on failure
 */
static int loopfs_loop_ctl_create(struct super_block *sb)
{
	struct dentry *dentry;
	struct inode *inode = NULL;
	struct dentry *root = sb->s_root;
	struct loopfs_info *info = sb->s_fs_info;

	if (info->control_dentry)
		return 0;

	inode = new_inode(sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = SECOND_INODE;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	init_special_inode(inode, S_IFCHR | 0600,
			   MKDEV(MISC_MAJOR, LOOP_CTRL_MINOR));
	/*
	 * The i_fop field will be set to the correct fops by the device layer
	 * when the loop-control device in this loopfs instance is opened.
	 */
	inode->i_uid = info->root_uid;
	inode->i_gid = info->root_gid;

	dentry = d_alloc_name(root, "loop-control");
	if (!dentry) {
		iput(inode);
		return -ENOMEM;
	}

	info->control_dentry = dentry;
	d_add(dentry, inode);

	return 0;
}

static inline bool is_loopfs_control_device(const struct dentry *dentry)
{
	return LOOPFS_SB(dentry->d_sb)->control_dentry == dentry;
}

static int loopfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	if (is_loopfs_control_device(old_dentry) ||
	    is_loopfs_control_device(new_dentry))
		return -EPERM;

	return simple_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

static int loopfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int ret;
	struct loop_device *lo;

	if (is_loopfs_control_device(dentry))
		return -EPERM;

	lo = d_inode(dentry)->i_private;
	ret = loopfs_rundown_locked(lo);
	if (ret)
		return ret;

	return simple_unlink(dir, dentry);
}

static const struct inode_operations loopfs_dir_inode_operations = {
	.lookup = simple_lookup,
	.rename = loopfs_rename,
	.unlink = loopfs_unlink,
};

static void loopfs_evict_inode(struct inode *inode)
{
	struct loop_device *lo = inode->i_private;

	clear_inode(inode);

	if (lo && S_ISBLK(inode->i_mode) && imajor(inode) == LOOP_MAJOR) {
		loopfs_evict_locked(lo);
		inode->i_private = NULL;
	}
}

static const struct super_operations loopfs_super_ops = {
	.evict_inode    = loopfs_evict_inode,
	.statfs         = simple_statfs,
};

static int loopfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct loopfs_info *info;
	struct inode *inode = NULL;

	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;

	sb->s_iflags &= ~SB_I_NODEV;
	sb->s_iflags |= SB_I_NOEXEC;
	sb->s_magic = LOOPFS_SUPER_MAGIC;
	sb->s_op = &loopfs_super_ops;
	sb->s_time_gran = 1;

	sb->s_fs_info = kzalloc(sizeof(struct loopfs_info), GFP_KERNEL);
	if (!sb->s_fs_info)
		return -ENOMEM;
	info = sb->s_fs_info;

	info->root_gid = make_kgid(sb->s_user_ns, 0);
	if (!gid_valid(info->root_gid))
		info->root_gid = GLOBAL_ROOT_GID;
	info->root_uid = make_kuid(sb->s_user_ns, 0);
	if (!uid_valid(info->root_uid))
		info->root_uid = GLOBAL_ROOT_UID;
	info->user_ns = get_user_ns(sb->s_user_ns);
	atomic_set(&info->users, 1);

	inode = new_inode(sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = FIRST_INODE;
	inode->i_fop = &simple_dir_operations;
	inode->i_mode = S_IFDIR | 0755;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_op = &loopfs_dir_inode_operations;
	set_nlink(inode, 2);

	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	return loopfs_loop_ctl_create(sb);
}

static int loopfs_fs_context_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, loopfs_fill_super);
}

static void loopfs_fs_context_free(struct fs_context *fc)
{
	struct loopfs_info *sbi = fc->s_fs_info;

	fc->s_fs_info = NULL;
	if (sbi && atomic_dec_and_test(&sbi->users)) {
		put_user_ns(sbi->user_ns);
		kfree(sbi);
	}
}

static const struct fs_context_operations loopfs_fs_context_ops = {
	.free		= loopfs_fs_context_free,
	.get_tree	= loopfs_fs_context_get_tree,
};

static int loopfs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &loopfs_fs_context_ops;
	return 0;
}

static void loopfs_kill_sb(struct super_block *sb)
{
	struct loopfs_info *sbi = sb->s_fs_info;

	sb->s_fs_info = NULL;
	if (atomic_dec_and_test(&sbi->users)) {
		put_user_ns(sbi->user_ns);
		kfree(sbi);
	}

	kill_litter_super(sb);
}

static struct file_system_type loop_fs_type = {
	.name			= "loop",
	.init_fs_context	= loopfs_init_fs_context,
	.kill_sb		= loopfs_kill_sb,
	.fs_flags		= FS_USERNS_MOUNT,
};

int __init init_loopfs(void)
{
	init_user_ns.ucount_max[UCOUNT_LOOP_DEVICES] = 255;
	return register_filesystem(&loop_fs_type);
}

module_init(init_loopfs);
MODULE_AUTHOR("Christian Brauner <christian.brauner@ubuntu.com>");
MODULE_DESCRIPTION("Loop device filesystem");
