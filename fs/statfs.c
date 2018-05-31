// SPDX-License-Identifier: GPL-2.0
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/compat.h>
#include <linux/fsinfo.h>
#include "internal.h"

static int flags_by_mnt(int mnt_flags)
{
	int flags = 0;

	if (mnt_flags & MNT_READONLY)
		flags |= ST_RDONLY;
	if (mnt_flags & MNT_NOSUID)
		flags |= ST_NOSUID;
	if (mnt_flags & MNT_NODEV)
		flags |= ST_NODEV;
	if (mnt_flags & MNT_NOEXEC)
		flags |= ST_NOEXEC;
	if (mnt_flags & MNT_NOATIME)
		flags |= ST_NOATIME;
	if (mnt_flags & MNT_NODIRATIME)
		flags |= ST_NODIRATIME;
	if (mnt_flags & MNT_RELATIME)
		flags |= ST_RELATIME;
	return flags;
}

static int flags_by_sb(int s_flags)
{
	int flags = 0;
	if (s_flags & SB_SYNCHRONOUS)
		flags |= ST_SYNCHRONOUS;
	if (s_flags & SB_MANDLOCK)
		flags |= ST_MANDLOCK;
	if (s_flags & SB_RDONLY)
		flags |= ST_RDONLY;
	return flags;
}

static int calculate_f_flags(struct vfsmount *mnt)
{
	return ST_VALID | flags_by_mnt(mnt->mnt_flags) |
		flags_by_sb(mnt->mnt_sb->s_flags);
}

static int statfs_by_dentry(struct dentry *dentry, struct kstatfs *buf)
{
	int retval;

	if (!dentry->d_sb->s_op->statfs)
		return -ENOSYS;

	memset(buf, 0, sizeof(*buf));
	retval = security_sb_statfs(dentry);
	if (retval)
		return retval;
	retval = dentry->d_sb->s_op->statfs(dentry, buf);
	if (retval == 0 && buf->f_frsize == 0)
		buf->f_frsize = buf->f_bsize;
	return retval;
}

int vfs_statfs(const struct path *path, struct kstatfs *buf)
{
	int error;

	error = statfs_by_dentry(path->dentry, buf);
	if (!error)
		buf->f_flags = calculate_f_flags(path->mnt);
	return error;
}
EXPORT_SYMBOL(vfs_statfs);

int user_statfs(const char __user *pathname, struct kstatfs *st)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (!error) {
		error = vfs_statfs(&path, st);
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return error;
}

int fd_statfs(int fd, struct kstatfs *st)
{
	struct fd f = fdget_raw(fd);
	int error = -EBADF;
	if (f.file) {
		error = vfs_statfs(&f.file->f_path, st);
		fdput(f);
	}
	return error;
}

static int do_statfs_native(struct kstatfs *st, struct statfs __user *p)
{
	struct statfs buf;

	if (sizeof(buf) == sizeof(*st))
		memcpy(&buf, st, sizeof(*st));
	else {
		if (sizeof buf.f_blocks == 4) {
			if ((st->f_blocks | st->f_bfree | st->f_bavail |
			     st->f_bsize | st->f_frsize) &
			    0xffffffff00000000ULL)
				return -EOVERFLOW;
			/*
			 * f_files and f_ffree may be -1; it's okay to stuff
			 * that into 32 bits
			 */
			if (st->f_files != -1 &&
			    (st->f_files & 0xffffffff00000000ULL))
				return -EOVERFLOW;
			if (st->f_ffree != -1 &&
			    (st->f_ffree & 0xffffffff00000000ULL))
				return -EOVERFLOW;
		}

		buf.f_type = st->f_type;
		buf.f_bsize = st->f_bsize;
		buf.f_blocks = st->f_blocks;
		buf.f_bfree = st->f_bfree;
		buf.f_bavail = st->f_bavail;
		buf.f_files = st->f_files;
		buf.f_ffree = st->f_ffree;
		buf.f_fsid = st->f_fsid;
		buf.f_namelen = st->f_namelen;
		buf.f_frsize = st->f_frsize;
		buf.f_flags = st->f_flags;
		memset(buf.f_spare, 0, sizeof(buf.f_spare));
	}
	if (copy_to_user(p, &buf, sizeof(buf)))
		return -EFAULT;
	return 0;
}

static int do_statfs64(struct kstatfs *st, struct statfs64 __user *p)
{
	struct statfs64 buf;
	if (sizeof(buf) == sizeof(*st))
		memcpy(&buf, st, sizeof(*st));
	else {
		buf.f_type = st->f_type;
		buf.f_bsize = st->f_bsize;
		buf.f_blocks = st->f_blocks;
		buf.f_bfree = st->f_bfree;
		buf.f_bavail = st->f_bavail;
		buf.f_files = st->f_files;
		buf.f_ffree = st->f_ffree;
		buf.f_fsid = st->f_fsid;
		buf.f_namelen = st->f_namelen;
		buf.f_frsize = st->f_frsize;
		buf.f_flags = st->f_flags;
		memset(buf.f_spare, 0, sizeof(buf.f_spare));
	}
	if (copy_to_user(p, &buf, sizeof(buf)))
		return -EFAULT;
	return 0;
}

SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
{
	struct kstatfs st;
	int error = user_statfs(pathname, &st);
	if (!error)
		error = do_statfs_native(&st, buf);
	return error;
}

SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
{
	struct kstatfs st;
	int error;
	if (sz != sizeof(*buf))
		return -EINVAL;
	error = user_statfs(pathname, &st);
	if (!error)
		error = do_statfs64(&st, buf);
	return error;
}

SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
{
	struct kstatfs st;
	int error = fd_statfs(fd, &st);
	if (!error)
		error = do_statfs_native(&st, buf);
	return error;
}

SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, size_t, sz, struct statfs64 __user *, buf)
{
	struct kstatfs st;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = fd_statfs(fd, &st);
	if (!error)
		error = do_statfs64(&st, buf);
	return error;
}

static int vfs_ustat(dev_t dev, struct kstatfs *sbuf)
{
	struct super_block *s = user_get_super(dev);
	int err;
	if (!s)
		return -EINVAL;

	err = statfs_by_dentry(s->s_root, sbuf);
	drop_super(s);
	return err;
}

SYSCALL_DEFINE2(ustat, unsigned, dev, struct ustat __user *, ubuf)
{
	struct ustat tmp;
	struct kstatfs sbuf;
	int err = vfs_ustat(new_decode_dev(dev), &sbuf);
	if (err)
		return err;

	memset(&tmp,0,sizeof(struct ustat));
	tmp.f_tfree = sbuf.f_bfree;
	tmp.f_tinode = sbuf.f_ffree;

	return copy_to_user(ubuf, &tmp, sizeof(struct ustat)) ? -EFAULT : 0;
}

#ifdef CONFIG_COMPAT
static int put_compat_statfs(struct compat_statfs __user *ubuf, struct kstatfs *kbuf)
{
	struct compat_statfs buf;
	if (sizeof ubuf->f_blocks == 4) {
		if ((kbuf->f_blocks | kbuf->f_bfree | kbuf->f_bavail |
		     kbuf->f_bsize | kbuf->f_frsize) & 0xffffffff00000000ULL)
			return -EOVERFLOW;
		/* f_files and f_ffree may be -1; it's okay
		 * to stuff that into 32 bits */
		if (kbuf->f_files != 0xffffffffffffffffULL
		 && (kbuf->f_files & 0xffffffff00000000ULL))
			return -EOVERFLOW;
		if (kbuf->f_ffree != 0xffffffffffffffffULL
		 && (kbuf->f_ffree & 0xffffffff00000000ULL))
			return -EOVERFLOW;
	}
	memset(&buf, 0, sizeof(struct compat_statfs));
	buf.f_type = kbuf->f_type;
	buf.f_bsize = kbuf->f_bsize;
	buf.f_blocks = kbuf->f_blocks;
	buf.f_bfree = kbuf->f_bfree;
	buf.f_bavail = kbuf->f_bavail;
	buf.f_files = kbuf->f_files;
	buf.f_ffree = kbuf->f_ffree;
	buf.f_namelen = kbuf->f_namelen;
	buf.f_fsid.val[0] = kbuf->f_fsid.val[0];
	buf.f_fsid.val[1] = kbuf->f_fsid.val[1];
	buf.f_frsize = kbuf->f_frsize;
	buf.f_flags = kbuf->f_flags;
	if (copy_to_user(ubuf, &buf, sizeof(struct compat_statfs)))
		return -EFAULT;
	return 0;
}

/*
 * The following statfs calls are copies of code from fs/statfs.c and
 * should be checked against those from time to time
 */
COMPAT_SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct compat_statfs __user *, buf)
{
	struct kstatfs tmp;
	int error = user_statfs(pathname, &tmp);
	if (!error)
		error = put_compat_statfs(buf, &tmp);
	return error;
}

COMPAT_SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct compat_statfs __user *, buf)
{
	struct kstatfs tmp;
	int error = fd_statfs(fd, &tmp);
	if (!error)
		error = put_compat_statfs(buf, &tmp);
	return error;
}

static int put_compat_statfs64(struct compat_statfs64 __user *ubuf, struct kstatfs *kbuf)
{
	struct compat_statfs64 buf;
	if (sizeof(ubuf->f_bsize) == 4) {
		if ((kbuf->f_type | kbuf->f_bsize | kbuf->f_namelen |
		     kbuf->f_frsize | kbuf->f_flags) & 0xffffffff00000000ULL)
			return -EOVERFLOW;
		/* f_files and f_ffree may be -1; it's okay
		 * to stuff that into 32 bits */
		if (kbuf->f_files != 0xffffffffffffffffULL
		 && (kbuf->f_files & 0xffffffff00000000ULL))
			return -EOVERFLOW;
		if (kbuf->f_ffree != 0xffffffffffffffffULL
		 && (kbuf->f_ffree & 0xffffffff00000000ULL))
			return -EOVERFLOW;
	}
	memset(&buf, 0, sizeof(struct compat_statfs64));
	buf.f_type = kbuf->f_type;
	buf.f_bsize = kbuf->f_bsize;
	buf.f_blocks = kbuf->f_blocks;
	buf.f_bfree = kbuf->f_bfree;
	buf.f_bavail = kbuf->f_bavail;
	buf.f_files = kbuf->f_files;
	buf.f_ffree = kbuf->f_ffree;
	buf.f_namelen = kbuf->f_namelen;
	buf.f_fsid.val[0] = kbuf->f_fsid.val[0];
	buf.f_fsid.val[1] = kbuf->f_fsid.val[1];
	buf.f_frsize = kbuf->f_frsize;
	buf.f_flags = kbuf->f_flags;
	if (copy_to_user(ubuf, &buf, sizeof(struct compat_statfs64)))
		return -EFAULT;
	return 0;
}

COMPAT_SYSCALL_DEFINE3(statfs64, const char __user *, pathname, compat_size_t, sz, struct compat_statfs64 __user *, buf)
{
	struct kstatfs tmp;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = user_statfs(pathname, &tmp);
	if (!error)
		error = put_compat_statfs64(buf, &tmp);
	return error;
}

COMPAT_SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, compat_size_t, sz, struct compat_statfs64 __user *, buf)
{
	struct kstatfs tmp;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = fd_statfs(fd, &tmp);
	if (!error)
		error = put_compat_statfs64(buf, &tmp);
	return error;
}

/*
 * This is a copy of sys_ustat, just dealing with a structure layout.
 * Given how simple this syscall is that apporach is more maintainable
 * than the various conversion hacks.
 */
COMPAT_SYSCALL_DEFINE2(ustat, unsigned, dev, struct compat_ustat __user *, u)
{
	struct compat_ustat tmp;
	struct kstatfs sbuf;
	int err = vfs_ustat(new_decode_dev(dev), &sbuf);
	if (err)
		return err;

	memset(&tmp, 0, sizeof(struct compat_ustat));
	tmp.f_tfree = sbuf.f_bfree;
	tmp.f_tinode = sbuf.f_ffree;
	if (copy_to_user(u, &tmp, sizeof(struct compat_ustat)))
		return -EFAULT;
	return 0;
}
#endif

/*
 * Get basic filesystem stats from statfs.
 */
static int fsinfo_generic_statfs(struct dentry *dentry,
				 struct fsinfo_statfs *p)
{
	struct super_block *sb;
	struct kstatfs buf;
	int ret;

	ret = statfs_by_dentry(dentry, &buf);
	if (ret < 0)
		return ret;

	sb = dentry->d_sb;
	p->f_blocks	= buf.f_blocks;
	p->f_bfree	= buf.f_bfree;
	p->f_bavail	= buf.f_bavail;
	p->f_files	= buf.f_files;
	p->f_ffree	= buf.f_ffree;
	p->f_favail	= buf.f_ffree;
	p->f_bsize	= buf.f_bsize;
	p->f_frsize	= buf.f_frsize;
	return sizeof(*p);
}

static int fsinfo_generic_ids(struct dentry *dentry,
			      struct fsinfo_ids *p)
{
	struct super_block *sb;
	struct kstatfs buf;
	int ret;

	ret = statfs_by_dentry(dentry, &buf);
	if (ret < 0)
		return ret;

	sb = dentry->d_sb;
	p->f_fstype	= sb->s_magic;
	p->f_dev_major	= MAJOR(sb->s_dev);
	p->f_dev_minor	= MINOR(sb->s_dev);
	p->f_flags	= ST_VALID | flags_by_sb(sb->s_flags);

	memcpy(&p->f_fsid, &buf.f_fsid, sizeof(p->f_fsid));
	strcpy(p->f_fs_name, dentry->d_sb->s_type->name);
	return sizeof(*p);
}

static int fsinfo_generic_limits(struct dentry *dentry,
				 struct fsinfo_limits *lim)
{
	struct super_block *sb = dentry->d_sb;

	lim->max_file_size = sb->s_maxbytes;
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

static int fsinfo_generic_supports(struct dentry *dentry,
				   struct fsinfo_supports *c)
{
	struct super_block *sb = dentry->d_sb;

	c->stx_mask = STATX_BASIC_STATS;
	if (sb->s_d_op && sb->s_d_op->d_automount)
		c->stx_attributes |= STATX_ATTR_AUTOMOUNT;
	return sizeof(*c);
}

static int fsinfo_generic_capabilities(struct dentry *dentry,
				       struct fsinfo_capabilities *c)
{
	struct super_block *sb = dentry->d_sb;

	if (sb->s_mtd)
		fsinfo_set_cap(c, fsinfo_cap_is_flash_fs);
	else if (sb->s_bdev)
		fsinfo_set_cap(c, fsinfo_cap_is_block_fs);

	if (sb->s_quota_types & QTYPE_MASK_USR)
		fsinfo_set_cap(c, fsinfo_cap_user_quotas);
	if (sb->s_quota_types & QTYPE_MASK_GRP)
		fsinfo_set_cap(c, fsinfo_cap_group_quotas);
	if (sb->s_quota_types & QTYPE_MASK_PRJ)
		fsinfo_set_cap(c, fsinfo_cap_project_quotas);
	if (sb->s_d_op && sb->s_d_op->d_automount)
		fsinfo_set_cap(c, fsinfo_cap_automounts);
	if (sb->s_id[0])
		fsinfo_set_cap(c, fsinfo_cap_volume_id);

	fsinfo_set_cap(c, fsinfo_cap_has_atime);
	fsinfo_set_cap(c, fsinfo_cap_has_ctime);
	fsinfo_set_cap(c, fsinfo_cap_has_mtime);
	return sizeof(*c);
}

static int fsinfo_generic_timestamp_info(struct dentry *dentry,
					 struct fsinfo_timestamp_info *ts)
{
	struct super_block *sb = dentry->d_sb;

	/* If unset, assume 1s granularity */
	u16 mantissa = 1;
	s8 exponent = 0;

	ts->minimum_timestamp = S64_MIN;
	ts->maximum_timestamp = S64_MAX;
	if (sb->s_time_gran < 1000000000) {
		if (sb->s_time_gran < 1000)
			exponent = -9;
		else if (sb->s_time_gran < 1000000)
			exponent = -6;
		else
			exponent = -3;
	}
#define set_gran(x)				\
	do {					\
		ts->x##_mantissa = mantissa;	\
		ts->x##_exponent = exponent;	\
	} while (0)
	set_gran(atime_gran);
	set_gran(btime_gran);
	set_gran(ctime_gran);
	set_gran(mtime_gran);
	return sizeof(*ts);
}

static int fsinfo_generic_volume_uuid(struct dentry *dentry,
				      struct fsinfo_volume_uuid *vu)
{
	struct super_block *sb = dentry->d_sb;

	memcpy(vu, &sb->s_uuid, sizeof(*vu));
	return sizeof(*vu);
}

static int fsinfo_generic_volume_id(struct dentry *dentry, char *buf)
{
	struct super_block *sb = dentry->d_sb;
	size_t len = strlen(sb->s_id);

	if (buf)
		memcpy(buf, sb->s_id, len + 1);
	return len;
}

static int fsinfo_generic_name_encoding(struct dentry *dentry, char *buf)
{
	static const char encoding[] = "utf8";

	if (buf)
		memcpy(buf, encoding, sizeof(encoding) - 1);
	return sizeof(encoding) - 1;
}

static int fsinfo_generic_io_size(struct dentry *dentry,
				  struct fsinfo_io_size *c)
{
	struct super_block *sb = dentry->d_sb;
	struct kstatfs buf;
	int ret;

	if (sb->s_op->statfs == simple_statfs) {
		c->block_size = PAGE_SIZE;
		c->max_single_read_size = 0;
		c->max_single_write_size = 0;
		c->best_read_size = PAGE_SIZE;
		c->best_write_size = PAGE_SIZE;
	} else {
		ret = statfs_by_dentry(dentry, &buf);
		if (ret < 0)
			return ret;
		c->block_size = buf.f_bsize;
		c->max_single_read_size = buf.f_bsize;
		c->max_single_write_size = buf.f_bsize;
		c->best_read_size = PAGE_SIZE;
		c->best_write_size = PAGE_SIZE;
	}
	return sizeof(*c);
}

/*
 * Implement some queries generically from stuff in the superblock.
 */
int generic_fsinfo(struct dentry *dentry, struct fsinfo_kparams *params)
{
#define _gen(X) fsinfo_attr_##X: return fsinfo_generic_##X(dentry, params->buffer)

	switch (params->request) {
	case _gen(statfs);
	case _gen(ids);
	case _gen(limits);
	case _gen(supports);
	case _gen(capabilities);
	case _gen(timestamp_info);
	case _gen(volume_uuid);
	case _gen(volume_id);
	case _gen(name_encoding);
	case _gen(io_size);
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(generic_fsinfo);

/*
 * Retrieve the filesystem info.  We make some stuff up if the operation is not
 * supported.
 */
int vfs_fsinfo(const struct path *path, struct fsinfo_kparams *params)
{
	struct dentry *dentry = path->dentry;
	int (*get_fsinfo)(struct dentry *, struct fsinfo_kparams *);
	int ret;

	if (params->request == fsinfo_attr_fsinfo) {
		struct fsinfo_fsinfo *info = params->buffer;

		info->max_attr	= fsinfo_attr__nr;
		info->max_cap	= fsinfo_cap__nr;
		return sizeof(*info);
	}

	get_fsinfo = dentry->d_sb->s_op->get_fsinfo;
	if (!get_fsinfo) {
		if (!dentry->d_sb->s_op->statfs)
			return -EOPNOTSUPP;
		get_fsinfo = generic_fsinfo;
	}

	ret = security_sb_statfs(dentry);
	if (ret)
		return ret;

	ret = get_fsinfo(dentry, params);
	if (ret < 0)
		return ret;

	if (params->request == fsinfo_attr_ids &&
	    params->buffer) {
		struct fsinfo_ids *p = params->buffer;

		p->f_flags |= flags_by_mnt(path->mnt->mnt_flags);
	}
	return ret;
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
 * Return buffer information by requestable attribute.
 *
 * STRUCT indicates a fixed-size structure with only one instance.
 * STRUCT_N indicates a fixed-size structure that may have multiple instances.
 * STRING indicates a string with only one instance.
 * STRING_N indicates a string that may have multiple instances.
 * STRUCT_ARRAY indicates an array of fixed-size structs with only one instance.
 * STRUCT_ARRAY_N as above that may have multiple instances.
 *
 * If an entry is marked STRUCT, STRUCT_N or STRUCT_NM then if no buffer is
 * supplied to sys_fsinfo(), sys_fsinfo() will handle returning the buffer size
 * without calling vfs_fsinfo() and the filesystem.
 *
 * No struct may have more than 252 bytes (ie. 0x3f * 4)
 */
#define FSINFO_STRING(N)	 [fsinfo_attr_##N] = 0x0000
#define FSINFO_STRUCT(N)	 [fsinfo_attr_##N] = sizeof(struct fsinfo_##N)
#define FSINFO_STRING_N(N)	 [fsinfo_attr_##N] = 0x4000
#define FSINFO_STRUCT_N(N)	 [fsinfo_attr_##N] = 0x4000 | sizeof(struct fsinfo_##N)
#define FSINFO_STRUCT_NM(N)	 [fsinfo_attr_##N] = 0x8000 | sizeof(struct fsinfo_##N)
static const u16 fsinfo_buffer_sizes[fsinfo_attr__nr] = {
	FSINFO_STRUCT		(statfs),
	FSINFO_STRUCT		(fsinfo),
	FSINFO_STRUCT		(ids),
	FSINFO_STRUCT		(limits),
	FSINFO_STRUCT		(capabilities),
	FSINFO_STRUCT		(supports),
	FSINFO_STRUCT		(timestamp_info),
	FSINFO_STRING		(volume_id),
	FSINFO_STRUCT		(volume_uuid),
	FSINFO_STRING		(volume_name),
	FSINFO_STRING		(cell_name),
	FSINFO_STRING		(domain_name),
	FSINFO_STRING		(realm_name),
	FSINFO_STRING_N		(server_name),
	FSINFO_STRUCT_NM	(server_address),
	FSINFO_STRING_N		(parameter),
	FSINFO_STRING_N		(source),
	FSINFO_STRING		(name_encoding),
	FSINFO_STRING		(name_codepage),
	FSINFO_STRUCT		(io_size),
};

/**
 * sys_fsinfo - System call to get filesystem information
 * @dfd: Base directory to pathwalk from or fd referring to filesystem.
 * @filename: Filesystem to query or NULL.
 * @_params: Parameters to define request (or NULL for enhanced statfs).
 * @_buffer: Result buffer.
 * @buf_size: Size of result buffer.
 *
 * Get information on a filesystem.  The filesystem attribute to be queried is
 * indicated by @_params->request, and some of the attributes can have multiple
 * values, indexed by @_params->Nth and @_params->Mth.  If @_params is NULL,
 * then the 0th fsinfo_attr_statfs attribute is queried.  If an attribute does
 * not exist, EOPNOTSUPP is returned; if the Nth,Mth value does not exist,
 * ENODATA is returned.
 *
 * On success, the size of the attribute's value is returned.  If @buf_size is
 * 0 or @_buffer is NULL, only the size is returned.  If the size of the value
 * is larger than @buf_size, it will be truncated by the copy.  If the size of
 * the value is smaller than @buf_size then the excess buffer space will be
 * cleared.  The full size of the value will be returned, irrespective of how
 * much data is actually placed in the buffer.
 */
SYSCALL_DEFINE5(fsinfo,
		int, dfd, const char __user *, filename,
		struct fsinfo_params __user *, _params,
		void __user *, _buffer, size_t, buf_size)
{
	struct fsinfo_params user_params;
	struct fsinfo_kparams params;
	size_t size;
	int ret;

	if (_params) {
		if (copy_from_user(&user_params, _params, sizeof(user_params)))
			return -EFAULT;
		if (user_params.__reserved[0] ||
		    user_params.__reserved[1] ||
		    user_params.__reserved[2] ||
		    user_params.__reserved[3] ||
		    user_params.__reserved[4] ||
		    user_params.__reserved[5])
			return -EINVAL;
		if (user_params.request >= fsinfo_attr__nr)
			return -EOPNOTSUPP;
		params.at_flags = user_params.at_flags;
		params.request = user_params.request;
		params.Nth = user_params.Nth;
		params.Mth = user_params.Mth;
	} else {
		params.at_flags = 0;
		params.request = fsinfo_attr_statfs;
		params.Nth = 0;
		params.Mth = 0;
	}

	if (!_buffer || !buf_size) {
		buf_size = 0;
		_buffer = NULL;
	}

	/* Allocate an appropriately-sized buffer.  We will truncate the
	 * contents when we write the contents back to userspace.
	 */
	size = fsinfo_buffer_sizes[params.request];
	switch (size & 0xc000) {
	case 0x0000:
		if (params.Nth != 0)
			return -ENODATA;
		/* Fall through */
	case 0x4000:
		if (params.Mth != 0)
			return -ENODATA;
		/* Fall through */
	case 0x8000:
		break;
	case 0xc000:
		return -ENOBUFS;
	}

	size &= ~0xc000;
	if (size == 0) {
		size = 4096; /* String */
	} else {
		if (buf_size == 0)
			return size; /* We know how big the buffer should be */

		/* Clear any part of the buffer that we won't fill. */
		if (buf_size > size &&
		    clear_user(_buffer, buf_size) != 0)
			return -EFAULT;
	}

	if (buf_size > 0) {
		params.buf_size = size;
		params.buffer = kzalloc(size, GFP_KERNEL);
		if (!params.buffer)
			return -ENOMEM;
	} else {
		params.buf_size = 0;
		params.buffer = NULL;
	}

	if (filename)
		ret = vfs_fsinfo_path(dfd, filename, &params);
	else
		ret = vfs_fsinfo_fd(dfd, &params);
	if (ret < 0)
		goto error;

	if (ret == 0) {
		ret = -ENODATA;
		goto error;
	}

	if (buf_size > ret)
		buf_size = ret;

	if (copy_to_user(_buffer, params.buffer, buf_size))
		ret = -EFAULT;
error:
	kfree(params.buffer);
	return ret;
}
