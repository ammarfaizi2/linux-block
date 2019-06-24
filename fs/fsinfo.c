// SPDX-License-Identifier: GPL-2.0
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/fsinfo.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <uapi/linux/mount.h>
#include "internal.h"

static u32 calc_mount_attrs(u32 mnt_flags)
{
	u32 attrs = 0;

	if (mnt_flags & MNT_READONLY)
		attrs |= MOUNT_ATTR_RDONLY;
	if (mnt_flags & MNT_NOSUID)
		attrs |= MOUNT_ATTR_NOSUID;
	if (mnt_flags & MNT_NODEV)
		attrs |= MOUNT_ATTR_NODEV;
	if (mnt_flags & MNT_NOEXEC)
		attrs |= MOUNT_ATTR_NOEXEC;
	if (mnt_flags & MNT_NODIRATIME)
		attrs |= MOUNT_ATTR_NODIRATIME;

	if (mnt_flags & MNT_NOATIME)
		attrs |= MOUNT_ATTR_NOATIME;
	else if (mnt_flags & MNT_RELATIME)
		attrs |= MOUNT_ATTR_RELATIME;
	else
		attrs |= MOUNT_ATTR_STRICTATIME;
	return attrs;
}

/*
 * Get basic filesystem stats from statfs.
 */
static int fsinfo_generic_statfs(struct path *path, struct fsinfo_statfs *p)
{
	struct kstatfs buf;
	int ret;

	ret = vfs_statfs(path, &buf);
	if (ret < 0)
		return ret;

	p->f_blocks.hi	= 0;
	p->f_blocks.lo	= buf.f_blocks;
	p->f_bfree.hi	= 0;
	p->f_bfree.lo	= buf.f_bfree;
	p->f_bavail.hi	= 0;
	p->f_bavail.lo	= buf.f_bavail;
	p->f_files.hi	= 0;
	p->f_files.lo	= buf.f_files;
	p->f_ffree.hi	= 0;
	p->f_ffree.lo	= buf.f_ffree;
	p->f_favail.hi	= 0;
	p->f_favail.lo	= buf.f_ffree;
	p->f_bsize	= buf.f_bsize;
	p->f_frsize	= buf.f_frsize;

	p->mnt_attrs	= calc_mount_attrs(path->mnt->mnt_flags);
	return sizeof(*p);
}

static int fsinfo_generic_ids(struct path *path, struct fsinfo_ids *p)
{
	struct super_block *sb;
	struct kstatfs buf;
	int ret;

	ret = vfs_statfs(path, &buf);
	if (ret < 0 && ret != -ENOSYS)
		return ret;

	sb = path->dentry->d_sb;
	p->f_fstype	= sb->s_magic;
	p->f_dev_major	= MAJOR(sb->s_dev);
	p->f_dev_minor	= MINOR(sb->s_dev);
	p->f_sb_id	= sb->s_unique_id;

	memcpy(&p->f_fsid, &buf.f_fsid, sizeof(p->f_fsid));
	strlcpy(p->f_fs_name, path->dentry->d_sb->s_type->name,
		sizeof(p->f_fs_name));
	return sizeof(*p);
}

static int fsinfo_generic_limits(struct path *path, struct fsinfo_limits *lim)
{
	struct super_block *sb = path->dentry->d_sb;

	lim->max_file_size.hi = 0;
	lim->max_file_size.lo = sb->s_maxbytes;
	lim->max_hard_links = sb->s_max_links;
	lim->max_uid = UINT_MAX;
	lim->max_gid = UINT_MAX;
	lim->max_projid = UINT_MAX;
	lim->max_filename_len = NAME_MAX;
	lim->max_symlink_len = PAGE_SIZE;
	lim->max_xattr_name_len = XATTR_NAME_MAX;
	lim->max_xattr_body_len = XATTR_SIZE_MAX;
	lim->max_dev_major = 0xffffff;
	lim->max_dev_minor = 0xff;
	return sizeof(*lim);
}

static int fsinfo_generic_supports(struct path *path, struct fsinfo_supports *c)
{
	struct super_block *sb = path->dentry->d_sb;

	c->stx_mask = STATX_BASIC_STATS;
	if (sb->s_d_op && sb->s_d_op->d_automount)
		c->stx_attributes |= STATX_ATTR_AUTOMOUNT;
	return sizeof(*c);
}

static int fsinfo_generic_capabilities(struct path *path,
				       struct fsinfo_capabilities *c)
{
	struct super_block *sb = path->dentry->d_sb;

	if (sb->s_mtd)
		fsinfo_set_cap(c, FSINFO_CAP_IS_FLASH_FS);
	else if (sb->s_bdev)
		fsinfo_set_cap(c, FSINFO_CAP_IS_BLOCK_FS);

	if (sb->s_quota_types & QTYPE_MASK_USR)
		fsinfo_set_cap(c, FSINFO_CAP_USER_QUOTAS);
	if (sb->s_quota_types & QTYPE_MASK_GRP)
		fsinfo_set_cap(c, FSINFO_CAP_GROUP_QUOTAS);
	if (sb->s_quota_types & QTYPE_MASK_PRJ)
		fsinfo_set_cap(c, FSINFO_CAP_PROJECT_QUOTAS);
	if (sb->s_d_op && sb->s_d_op->d_automount)
		fsinfo_set_cap(c, FSINFO_CAP_AUTOMOUNTS);
	if (sb->s_id[0])
		fsinfo_set_cap(c, FSINFO_CAP_VOLUME_ID);

	fsinfo_set_cap(c, FSINFO_CAP_HAS_ATIME);
	fsinfo_set_cap(c, FSINFO_CAP_HAS_CTIME);
	fsinfo_set_cap(c, FSINFO_CAP_HAS_MTIME);
	return sizeof(*c);
}

static const struct fsinfo_timestamp_info fsinfo_default_timestamp_info = {
	.atime = {
		.minimum	= S64_MIN,
		.maximum	= S64_MAX,
		.gran_mantissa	= 1,
		.gran_exponent	= 0,
	},
	.mtime = {
		.minimum	= S64_MIN,
		.maximum	= S64_MAX,
		.gran_mantissa	= 1,
		.gran_exponent	= 0,
	},
	.ctime = {
		.minimum	= S64_MIN,
		.maximum	= S64_MAX,
		.gran_mantissa	= 1,
		.gran_exponent	= 0,
	},
	.btime = {
		.minimum	= S64_MIN,
		.maximum	= S64_MAX,
		.gran_mantissa	= 1,
		.gran_exponent	= 0,
	},
};

static int fsinfo_generic_timestamp_info(struct path *path,
					 struct fsinfo_timestamp_info *ts)
{
	struct super_block *sb = path->dentry->d_sb;
	s8 exponent;

	*ts = fsinfo_default_timestamp_info;


	if (sb->s_time_gran < 1000000000) {
		if (sb->s_time_gran < 1000)
			exponent = -9;
		else if (sb->s_time_gran < 1000000)
			exponent = -6;
		else
			exponent = -3;

		ts->atime.gran_exponent = exponent;
		ts->mtime.gran_exponent = exponent;
		ts->ctime.gran_exponent = exponent;
		ts->btime.gran_exponent = exponent;
	}

	return sizeof(*ts);
}

static int fsinfo_generic_volume_uuid(struct path *path,
				      struct fsinfo_volume_uuid *vu)
{
	struct super_block *sb = path->dentry->d_sb;

	memcpy(vu, &sb->s_uuid, sizeof(*vu));
	return sizeof(*vu);
}

static int fsinfo_generic_volume_id(struct path *path, char *buf)
{
	struct super_block *sb = path->dentry->d_sb;
	size_t len = strlen(sb->s_id);

	memcpy(buf, sb->s_id, len + 1);
	return len;
}

static int fsinfo_generic_name_encoding(struct path *path, char *buf)
{
	static const char encoding[] = "utf8";

	memcpy(buf, encoding, sizeof(encoding) - 1);
	return sizeof(encoding) - 1;
}

static int fsinfo_generic_param_description(struct file_system_type *f,
					    struct fsinfo_kparams *params)
{
	const struct fs_parameter_description *desc = f->parameters;
	const struct fs_parameter_spec *s;
	const struct fs_parameter_enum *e;
	struct fsinfo_param_description *p = params->buffer;

	if (desc && desc->specs) {
		for (s = desc->specs; s->name; s++) {}
		p->nr_params = s - desc->specs;
		if (desc->enums) {
			for (e = desc->enums; e->name[0]; e++) {}
			p->nr_enum_names = e - desc->enums;
		}
	}

	return sizeof(*p);
}

static int fsinfo_generic_param_specification(struct file_system_type *f,
					      struct fsinfo_kparams *params)
{
	const struct fs_parameter_description *desc = f->parameters;
	const struct fs_parameter_spec *s;
	struct fsinfo_param_specification *p = params->buffer;
	unsigned int nth = params->Nth;

	if (!desc || !desc->specs)
		return -ENODATA;

	for (s = desc->specs; s->name; s++) {
		if (nth == 0)
			goto found;
		nth--;
	}

	return -ENODATA;

found:
	p->type = s->type;
	p->flags = s->flags;
	p->opt = s->opt;
	strlcpy(p->name, s->name, sizeof(p->name));
	return sizeof(*p);
}

static int fsinfo_generic_param_enum(struct file_system_type *f,
				     struct fsinfo_kparams *params)
{
	const struct fs_parameter_description *desc = f->parameters;
	const struct fs_parameter_enum *e;
	struct fsinfo_param_enum *p = params->buffer;
	unsigned int nth = params->Nth;

	if (!desc || !desc->enums)
		return -ENODATA;

	for (e = desc->enums; e->name; e++) {
		if (nth == 0)
			goto found;
		nth--;
	}

	return -ENODATA;

found:
	p->opt = e->opt;
	strlcpy(p->name, e->name, sizeof(p->name));
	return sizeof(*p);
}

void fsinfo_note_sb_params(struct fsinfo_kparams *params, unsigned int s_flags)
{
	if (s_flags & SB_DIRSYNC)
		fsinfo_note_param(params, "dirsync", NULL);
	if (s_flags & SB_LAZYTIME)
		fsinfo_note_param(params, "lazytime", NULL);
	if (s_flags & SB_MANDLOCK)
		fsinfo_note_param(params, "mand", NULL);
	if (s_flags & SB_POSIXACL)
		fsinfo_note_param(params, "posixacl", NULL);
	if (s_flags & SB_RDONLY)
		fsinfo_note_param(params, "ro", NULL);
	else
		fsinfo_note_param(params, "rw", NULL);
	if (s_flags & SB_SYNCHRONOUS)
		fsinfo_note_param(params, "sync", NULL);
}
EXPORT_SYMBOL(fsinfo_note_sb_params);

static int fsinfo_generic_sb_notifications(struct path *path,
					   struct fsinfo_sb_notifications *p)
{
	struct super_block *sb = path->dentry->d_sb;

	p->watch_id		= sb->s_unique_id;
	p->notify_counter	= atomic_read(&sb->s_notify_counter);
	return sizeof(*p);
}

static int fsinfo_generic_parameters(struct path *path,
				     struct fsinfo_kparams *params)
{
	fsinfo_note_sb_params(params, READ_ONCE(path->dentry->d_sb->s_flags));
	return params->usage;
}

/*
 * Implement some queries generically from stuff in the superblock.
 */
int generic_fsinfo(struct path *path, struct fsinfo_kparams *params)
{
	struct file_system_type *fs = path->dentry->d_sb->s_type;

#define _gen(X, Y) FSINFO_ATTR_##X: return fsinfo_generic_##Y(path, params->buffer)
#define _genp(X, Y) FSINFO_ATTR_##X: return fsinfo_generic_##Y(path, params)
#define _genf(X, Y) FSINFO_ATTR_##X: return fsinfo_generic_##Y(fs, params)

	switch (params->request) {
	case _gen(STATFS,		statfs);
	case _gen(IDS,			ids);
	case _gen(LIMITS,		limits);
	case _gen(SUPPORTS,		supports);
	case _gen(CAPABILITIES,		capabilities);
	case _gen(TIMESTAMP_INFO,	timestamp_info);
	case _gen(VOLUME_UUID,		volume_uuid);
	case _gen(VOLUME_ID,		volume_id);
	case _gen(NAME_ENCODING,	name_encoding);
	case _genf(PARAM_DESCRIPTION,	param_description);
	case _genf(PARAM_SPECIFICATION,	param_specification);
	case _genf(PARAM_ENUM,		param_enum);
	case _genp(PARAMETERS,		parameters);
	case _genp(MOUNT_INFO,		mount_info);
	case _genp(MOUNT_DEVNAME,	mount_devname);
	case _genp(MOUNT_CHILDREN,	mount_children);
	case _genp(MOUNT_SUBMOUNT,	mount_submount);
	case _gen(SB_NOTIFICATIONS,	sb_notifications);
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(generic_fsinfo);

/*
 * Retrieve the filesystem info.  We make some stuff up if the operation is not
 * supported.
 */
static int vfs_fsinfo(struct path *path, struct fsinfo_kparams *params)
{
	struct dentry *dentry = path->dentry;
	int (*fsinfo)(struct path *, struct fsinfo_kparams *);
	int ret;

	switch (params->request) {
	case FSINFO_ATTR_FSINFO: {
		struct fsinfo_fsinfo *info = params->buffer;

		info->max_attr	= FSINFO_ATTR__NR;
		info->max_cap	= FSINFO_CAP__NR;
		return sizeof(*info);
	}

	case FSINFO_ATTR_LSM_PARAMETERS:
		fsinfo = security_sb_fsinfo;
		break;

	default:
		fsinfo = dentry->d_sb->s_op->fsinfo;
		if (!fsinfo) {
			if (!dentry->d_sb->s_op->statfs)
				return -EOPNOTSUPP;
			fsinfo = generic_fsinfo;
		}
		break;
	}

	ret = security_sb_statfs(dentry);
	if (ret)
		return ret;

	if (!params->overlarge)
		return fsinfo(path, params);

	while (!signal_pending(current)) {
		if (params->request == FSINFO_ATTR_PARAMETERS) {
			if (down_read_killable(&dentry->d_sb->s_umount) < 0)
				return -ERESTARTSYS;
		}

		params->usage = 0;
		ret = fsinfo(path, params);
		if (params->request == FSINFO_ATTR_PARAMETERS)
			up_read(&dentry->d_sb->s_umount);

		if (ret <= (int)params->buf_size)
			return ret; /* Error or it fitted */
		kvfree(params->buffer);
		params->buffer = NULL;
		params->buf_size = roundup(ret, PAGE_SIZE);
		if (params->buf_size > INT_MAX)
			return -ETOOSMALL;
		params->buffer = kvmalloc(params->buf_size, GFP_KERNEL);
		if (!params->buffer)
			return -ENOMEM;
	}

	return -ERESTARTSYS;
}

static int vfs_fsinfo_path(int dfd, const char __user *filename,
			   struct fsinfo_kparams *params)
{
	struct path path;
	unsigned lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
	int ret = -EINVAL;

	if ((params->at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
				 AT_EMPTY_PATH)) != 0)
		return -EINVAL;

	if (params->at_flags & AT_SYMLINK_NOFOLLOW)
		lookup_flags &= ~LOOKUP_FOLLOW;
	if (params->at_flags & AT_NO_AUTOMOUNT)
		lookup_flags &= ~LOOKUP_AUTOMOUNT;
	if (params->at_flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

retry:
	ret = user_path_at(dfd, filename, lookup_flags, &path);
	if (ret)
		goto out;

	ret = vfs_fsinfo(&path, params);
	path_put(&path);
	if (retry_estale(ret, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return ret;
}

static int vfs_fsinfo_fd(unsigned int fd, struct fsinfo_kparams *params)
{
	struct fd f = fdget_raw(fd);
	int ret = -EBADF;

	if (f.file) {
		ret = vfs_fsinfo(&f.file->f_path, params);
		fdput(f);
	}
	return ret;
}

/*
 * Allow an fs_context object as created by fsopen() or fspick() to be queried.
 */
static int vfs_fsinfo_fscontext(int fd, struct fsinfo_kparams *params)
{
	struct file_system_type *fs;
	struct fs_context *fc;
	struct fd f = fdget(fd);
	int ret;

	if (!f.file)
		return -EBADF;

	ret = -EINVAL;
	if (f.file->f_op != &fscontext_fops)
		goto out_f;
	fc = f.file->private_data;
	fs = fc->fs_type;

	ret = -EOPNOTSUPP;
	if (fc->ops == &legacy_fs_context_ops)
		goto out_f;

	/* Filesystem parameter query is static information and doesn't need a
	 * lock to read it, nor even a dentry or superblock.
	 */
	switch (params->request) {
	case _genf(PARAM_DESCRIPTION,	param_description);
	case _genf(PARAM_SPECIFICATION,	param_specification);
	case _genf(PARAM_ENUM,		param_enum);
	default:
		break;
	}

	ret = mutex_lock_interruptible(&fc->uapi_mutex);
	if (ret == 0) {
		ret = -EIO;
		if (fc->root) {
			struct path path = { .dentry = fc->root };

			ret = vfs_fsinfo(&path, params);
		}

		mutex_unlock(&fc->uapi_mutex);
	}

out_f:
	fdput(f);
	return ret;
}

/*
 * Look up the root of a mount object.  This allows access to mount objects
 * (and their attached superblocks) that can't be retrieved by path because
 * they're entirely covered.
 *
 * We only permit access to a mount that has a direct path between either the
 * dentry pointed to by dfd or to our chroot (if dfd is AT_FDCWD).
 */
static int vfs_fsinfo_mount(int dfd, const char __user *filename,
			    struct fsinfo_kparams *params)
{
	struct path path;
	struct fd f = {};
	char *name;
	long mnt_id;
	int ret;

	if ((params->at_flags & ~AT_FSINFO_MOUNTID_PATH) ||
	    !filename)
		return -EINVAL;

	name = strndup_user(filename, 32);
	if (IS_ERR(name))
		return PTR_ERR(name);
	ret = kstrtoul(name, 0, &mnt_id);
	if (ret < 0)
		goto out_name;
	if (mnt_id > INT_MAX)
		goto out_name;

	if (dfd != AT_FDCWD) {
		ret = -EBADF;
		f = fdget_raw(dfd);
		if (!f.file)
			goto out_name;
	}

	ret = lookup_mount_object(f.file ? &f.file->f_path : NULL,
				  mnt_id, &path);
	if (ret < 0)
		goto out_fd;

	ret = vfs_fsinfo(&path, params);
	path_put(&path);
out_fd:
	fdput(f);
out_name:
	kfree(name);
	return ret;
}

/*
 * Return buffer information by requestable attribute.
 *
 * STRUCT indicates a fixed-size structure with only one instance.
 * STRUCT_N indicates a 1D array of STRUCT, indexed by Nth
 * STRUCT_NM indicates a 2D-array of STRUCT, indexed by Nth, Mth
 * STRING indicates a string with only one instance.
 * STRING_N indicates a 1D array of STRING, indexed by Nth
 * STRING_NM indicates a 2D-array of STRING, indexed by Nth, Mth
 * OPAQUE indicates a blob that can be larger than 4K.
 * STRUCT_ARRAY indicates an array of structs that can be larger than 4K
 *
 * If an entry is marked STRUCT, STRUCT_N or STRUCT_NM then if no buffer is
 * supplied to sys_fsinfo(), sys_fsinfo() will handle returning the buffer size
 * without calling vfs_fsinfo() and the filesystem.
 *
 * No struct may have more than 4K bytes.
 */
struct fsinfo_attr_info {
	u8 type;
	u8 flags;
	u16 size;
};

#define __FSINFO_STRUCT		0
#define __FSINFO_STRING		1
#define __FSINFO_OPAQUE		2
#define __FSINFO_STRUCT_ARRAY	3
#define __FSINFO_0		0
#define __FSINFO_N		0x0001
#define __FSINFO_NM		0x0002

#define _Z(T, F, S) { .type = __FSINFO_##T, .flags = __FSINFO_##F, .size = S }
#define FSINFO_STRING(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRING, 0, 0)
#define FSINFO_STRUCT(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRUCT, 0, sizeof(struct fsinfo_##Y))
#define FSINFO_STRING_N(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRING, N, 0)
#define FSINFO_STRUCT_N(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRUCT, N, sizeof(struct fsinfo_##Y))
#define FSINFO_STRING_NM(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRING, NM, 0)
#define FSINFO_STRUCT_NM(X,Y)	 [FSINFO_ATTR_##X] = _Z(STRUCT, NM, sizeof(struct fsinfo_##Y))
#define FSINFO_OPAQUE(X,Y)	 [FSINFO_ATTR_##X] = _Z(OPAQUE, 0, 0)
#define FSINFO_STRUCT_ARRAY(X,Y) [FSINFO_ATTR_##X] = _Z(STRUCT_ARRAY, 0, sizeof(struct fsinfo_##Y))

static const struct fsinfo_attr_info fsinfo_buffer_info[FSINFO_ATTR__NR] = {
	FSINFO_STRUCT		(STATFS,		statfs),
	FSINFO_STRUCT		(FSINFO,		fsinfo),
	FSINFO_STRUCT		(IDS,			ids),
	FSINFO_STRUCT		(LIMITS,		limits),
	FSINFO_STRUCT		(CAPABILITIES,		capabilities),
	FSINFO_STRUCT		(SUPPORTS,		supports),
	FSINFO_STRUCT		(TIMESTAMP_INFO,	timestamp_info),
	FSINFO_STRING		(VOLUME_ID,		volume_id),
	FSINFO_STRUCT		(VOLUME_UUID,		volume_uuid),
	FSINFO_STRING		(VOLUME_NAME,		-),
	FSINFO_STRING		(NAME_ENCODING,		-),
	FSINFO_STRING		(NAME_CODEPAGE,		-),
	FSINFO_STRUCT		(PARAM_DESCRIPTION,	param_description),
	FSINFO_STRUCT_N		(PARAM_SPECIFICATION,	param_specification),
	FSINFO_STRUCT_N		(PARAM_ENUM,		param_enum),
	FSINFO_OPAQUE		(PARAMETERS,		-),
	FSINFO_OPAQUE		(LSM_PARAMETERS,	-),
	FSINFO_STRUCT		(MOUNT_INFO,		mount_info),
	FSINFO_STRING		(MOUNT_DEVNAME,		mount_devname),
	FSINFO_STRUCT_ARRAY	(MOUNT_CHILDREN,	mount_child),
	FSINFO_STRING_N		(MOUNT_SUBMOUNT,	mount_submount),
	FSINFO_STRING_N		(SERVER_NAME,		server_name),
	FSINFO_STRUCT_NM	(SERVER_ADDRESS,	server_address),
	FSINFO_STRING		(CELL_NAME,		cell_name),
	FSINFO_STRUCT		(SB_NOTIFICATIONS,	sb_notifications),
};

/**
 * sys_fsinfo - System call to get filesystem information
 * @dfd: Base directory to pathwalk from or fd referring to filesystem.
 * @filename: Filesystem to query or NULL.
 * @_params: Parameters to define request (or NULL for enhanced statfs).
 * @user_buffer: Result buffer.
 * @user_buf_size: Size of result buffer.
 *
 * Get information on a filesystem.  The filesystem attribute to be queried is
 * indicated by @_params->request, and some of the attributes can have multiple
 * values, indexed by @_params->Nth and @_params->Mth.  If @_params is NULL,
 * then the 0th fsinfo_attr_statfs attribute is queried.  If an attribute does
 * not exist, EOPNOTSUPP is returned; if the Nth,Mth value does not exist,
 * ENODATA is returned.
 *
 * On success, the size of the attribute's value is returned.  If
 * @user_buf_size is 0 or @user_buffer is NULL, only the size is returned.  If
 * the size of the value is larger than @user_buf_size, it will be truncated by
 * the copy.  If the size of the value is smaller than @user_buf_size then the
 * excess buffer space will be cleared.  The full size of the value will be
 * returned, irrespective of how much data is actually placed in the buffer.
 */
SYSCALL_DEFINE5(fsinfo,
		int, dfd, const char __user *, filename,
		struct fsinfo_params __user *, _params,
		void __user *, user_buffer, size_t, user_buf_size)
{
	struct fsinfo_attr_info info;
	struct fsinfo_params user_params;
	struct fsinfo_kparams params;
	unsigned int result_size;
	int ret;

	memset(&params, 0, sizeof(params));

	if (_params) {
		if (copy_from_user(&user_params, _params, sizeof(user_params)))
			return -EFAULT;
		if (user_params.__reserved[0] ||
		    user_params.__reserved[1] ||
		    user_params.__reserved[2])
			return -EINVAL;
		if (user_params.request >= FSINFO_ATTR__NR)
			return -EOPNOTSUPP;
		params.at_flags = user_params.at_flags;
		params.request = user_params.request;
		params.Nth = user_params.Nth;
		params.Mth = user_params.Mth;

		if ((params.at_flags & AT_FSINFO_FROM_FSOPEN) && filename)
			return -EINVAL;
		if ((params.at_flags & (AT_FSINFO_FROM_FSOPEN | AT_FSINFO_MOUNTID_PATH)) ==
		    (AT_FSINFO_FROM_FSOPEN | AT_FSINFO_MOUNTID_PATH))
			return -EINVAL;
	} else {
		params.request = FSINFO_ATTR_STATFS;
	}

	if (!user_buffer || !user_buf_size) {
		user_buf_size = 0;
		user_buffer = NULL;
	}
	if ((params.at_flags & AT_FSINFO_FROM_FSOPEN) && filename)
		return -EINVAL;

	/* Allocate an appropriately-sized buffer.  We will truncate the
	 * contents when we write the contents back to userspace.
	 */
	info = fsinfo_buffer_info[params.request];
	if (params.Nth != 0 && !(info.flags & (__FSINFO_N | __FSINFO_NM)))
		return -ENODATA;
	if (params.Mth != 0 && !(info.flags & __FSINFO_NM))
		return -ENODATA;

	switch (info.type) {
	case __FSINFO_STRUCT:
		params.buf_size = info.size;
		if (user_buf_size == 0)
			return info.size; /* We know how big the buffer should be */
		break;

	case __FSINFO_STRING:
		params.buf_size = 4096;
		break;

	case __FSINFO_OPAQUE:
	case __FSINFO_STRUCT_ARRAY:
		/* Opaque blob or array of struct elements.  We also create a
		 * buffer that can be used for scratch space.
		 */
		ret = -ENOMEM;
		params.scratch_buffer = kmalloc(4096, GFP_KERNEL);
		if (!params.scratch_buffer)
			goto error;
		params.overlarge = true;
		params.buf_size = 4096;
		break;

	default:
		return -ENOBUFS;
	}

	/* We always allocate a buffer for a string, even if buf_size == 0 and
	 * we're not going to return any data.  This means that the filesystem
	 * code needn't care about whether the buffer actually exists or not.
	 */
	ret = -ENOMEM;
	params.buffer = kvzalloc(params.buf_size, GFP_KERNEL);
	if (!params.buffer)
		goto error_scratch;

	if (params.at_flags & AT_FSINFO_FROM_FSOPEN)
		ret = vfs_fsinfo_fscontext(dfd, &params);
	else if (params.at_flags & AT_FSINFO_MOUNTID_PATH)
		ret = vfs_fsinfo_mount(dfd, filename, &params);
	else if (filename)
		ret = vfs_fsinfo_path(dfd, filename, &params);
	else
		ret = vfs_fsinfo_fd(dfd, &params);
	if (ret < 0)
		goto error_buffer;

	result_size = ret;
	if (result_size > user_buf_size)
		result_size = user_buf_size;

	if (result_size > 0 &&
	    copy_to_user(user_buffer, params.buffer, result_size)) {
		ret = -EFAULT;
		goto error_buffer;
	}

	/* Clear any part of the buffer that we won't fill if we're putting a
	 * struct in there.  Strings, opaque objects and arrays are expected to
	 * be variable length.
	 */
	if (info.type == __FSINFO_STRUCT &&
	    user_buf_size > result_size &&
	    clear_user(user_buffer + result_size, user_buf_size - result_size) != 0) {
		ret = -EFAULT;
		goto error_buffer;
	}

error_buffer:
	kvfree(params.buffer);
error_scratch:
	kfree(params.scratch_buffer);
error:
	return ret;
}

/*
 * Store a parameter into the user's parameter buffer.  The key is prefixed by
 * a single byte length (1-127) and the value by one (0-0x7f) or two bytes
 * (0x80-0x3fff) or three bytes (0x4000-0x1fffff).
 *
 * Note that we must always make the size determination, even if the buffer is
 * already full, so that we can tell the caller how much buffer we actually
 * need.
 */
static void __fsinfo_note_param(struct fsinfo_kparams *params, const char *key,
				const char *val, unsigned int vlen)
{
	char *p;
	unsigned int usage;
	int klen, total, vmeta;
	u8 x;

	klen = strlen(key);
	BUG_ON(klen < 1 || klen > 127);
	BUG_ON(vlen > (1 << 21) - 1);
	BUG_ON(vlen > 0 && !val);

	vmeta = (vlen <= 127) ? 1 : (vlen <= 127 * 127) ? 2 : 3;

	total = 1 + klen + vmeta + vlen;

	usage = params->usage;
	params->usage = usage + total;
	if (!params->buffer || params->usage > params->buf_size)
		return;

	p = params->buffer + usage;
	*p++ = klen;
	p = memcpy(p, key, klen);
	p += klen;

	/* The more significant groups of 7 bits in the size are included in
	 * most->least order with 0x80 OR'd in.  The least significant 7 bits
	 * are last with the top bit clear.
	 */
	x = vlen >> 14;
	if (x & 0x7f)
		*p++ = 0x80 | x;

	x = vlen >> 7;
	if (x & 0x7f)
		*p++ = 0x80 | x;

	*p++ = vlen & 0x7f;
	memcpy(p, val, vlen);
}

/**
 * fsinfo_note_param - Store a parameter for FSINFO_ATTR_PARAMETERS
 * @params: The parameter buffer
 * @key: The parameter's key
 * @val: The parameter's value (or NULL)
 */
void fsinfo_note_param(struct fsinfo_kparams *params, const char *key,
		       const char *val)
{
	__fsinfo_note_param(params, key, val, val ? strlen(val) : 0);
}
EXPORT_SYMBOL(fsinfo_note_param);

/**
 * fsinfo_note_paramf - Store a formatted parameter for FSINFO_ATTR_PARAMETERS
 * @params: The parameter buffer
 * @key: The parameter's key
 * @val_fmt: Format string for the parameter's value
 */
void fsinfo_note_paramf(struct fsinfo_kparams *params, const char *key,
			const char *val_fmt, ...)
{
	va_list va;
	int n;

	va_start(va, val_fmt);
	n = vsnprintf(params->scratch_buffer, 4096, val_fmt, va);
	va_end(va);

	__fsinfo_note_param(params, key, params->scratch_buffer, n);
}
EXPORT_SYMBOL(fsinfo_note_paramf);
