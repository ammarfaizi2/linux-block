// SPDX-License-Identifier: GPL-2.0-only
/*
  File: fs/xattr.c

  Extended attribute handling.

  Copyright (C) 2001 by Andreas Gruenbacher <a.gruenbacher@computer.org>
  Copyright (C) 2001 SGI - Silicon Graphics, Inc <linux-xfs@oss.sgi.com>
  Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 */
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/evm.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fsnotify.h>
#include <linux/audit.h>
#include <linux/vmalloc.h>
#include <linux/posix_acl_xattr.h>
#include <linux/jhash.h>
#include <linux/rhashtable.h>

#include <linux/uaccess.h>

#include "internal.h"

static const char *
strcmp_prefix(const char *a, const char *a_prefix)
{
	while (*a_prefix && *a == *a_prefix) {
		a++;
		a_prefix++;
	}
	return *a_prefix ? NULL : a;
}

/*
 * In order to implement different sets of xattr operations for each xattr
 * prefix, a filesystem should create a null-terminated array of struct
 * xattr_handler (one for each prefix) and hang a pointer to it off of the
 * s_xattr field of the superblock.
 */
#define for_each_xattr_handler(handlers, handler)		\
	if (handlers)						\
		for ((handler) = *(handlers)++;			\
			(handler) != NULL;			\
			(handler) = *(handlers)++)

/*
 * Find the xattr_handler with the matching prefix.
 */
static const struct xattr_handler *
xattr_resolve_name(struct inode *inode, const char **name)
{
	const struct xattr_handler **handlers = inode->i_sb->s_xattr;
	const struct xattr_handler *handler;

	if (!(inode->i_opflags & IOP_XATTR)) {
		if (unlikely(is_bad_inode(inode)))
			return ERR_PTR(-EIO);
		return ERR_PTR(-EOPNOTSUPP);
	}
	for_each_xattr_handler(handlers, handler) {
		const char *n;

		n = strcmp_prefix(*name, xattr_prefix(handler));
		if (n) {
			if (!handler->prefix ^ !*n) {
				if (*n)
					continue;
				return ERR_PTR(-EINVAL);
			}
			*name = n;
			return handler;
		}
	}
	return ERR_PTR(-EOPNOTSUPP);
}

/*
 * Check permissions for extended attribute access.  This is a bit complicated
 * because different namespaces have very different rules.
 */
static int
xattr_permission(struct user_namespace *mnt_userns, struct inode *inode,
		 const char *name, int mask)
{
	/*
	 * We can never set or remove an extended attribute on a read-only
	 * filesystem  or on an immutable / append-only inode.
	 */
	if (mask & MAY_WRITE) {
		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
			return -EPERM;
		/*
		 * Updating an xattr will likely cause i_uid and i_gid
		 * to be writen back improperly if their true value is
		 * unknown to the vfs.
		 */
		if (HAS_UNMAPPED_ID(mnt_userns, inode))
			return -EPERM;
	}

	/*
	 * No restriction for security.* and system.* from the VFS.  Decision
	 * on these is left to the underlying filesystem / security module.
	 */
	if (!strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) ||
	    !strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return 0;

	/*
	 * The trusted.* namespace can only be accessed by privileged users.
	 */
	if (!strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN)) {
		if (!capable(CAP_SYS_ADMIN))
			return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
		return 0;
	}

	/*
	 * In the user.* namespace, only regular files and directories can have
	 * extended attributes. For sticky directories, only the owner and
	 * privileged users can write attributes.
	 */
	if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN)) {
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
		if (S_ISDIR(inode->i_mode) && (inode->i_mode & S_ISVTX) &&
		    (mask & MAY_WRITE) &&
		    !inode_owner_or_capable(mnt_userns, inode))
			return -EPERM;
	}

	return inode_permission(mnt_userns, inode, mask);
}

/*
 * Look for any handler that deals with the specified namespace.
 */
int
xattr_supported_namespace(struct inode *inode, const char *prefix)
{
	const struct xattr_handler **handlers = inode->i_sb->s_xattr;
	const struct xattr_handler *handler;
	size_t preflen;

	if (!(inode->i_opflags & IOP_XATTR)) {
		if (unlikely(is_bad_inode(inode)))
			return -EIO;
		return -EOPNOTSUPP;
	}

	preflen = strlen(prefix);

	for_each_xattr_handler(handlers, handler) {
		if (!strncmp(xattr_prefix(handler), prefix, preflen))
			return 0;
	}

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(xattr_supported_namespace);

int
__vfs_setxattr(struct user_namespace *mnt_userns, struct dentry *dentry,
	       struct inode *inode, const char *name, const void *value,
	       size_t size, int flags)
{
	const struct xattr_handler *handler;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->set)
		return -EOPNOTSUPP;
	if (size == 0)
		value = "";  /* empty EA, do not remove */
	return handler->set(handler, mnt_userns, dentry, inode, name, value,
			    size, flags);
}
EXPORT_SYMBOL(__vfs_setxattr);

/**
 *  __vfs_setxattr_noperm - perform setxattr operation without performing
 *  permission checks.
 *
 *  @mnt_userns: user namespace of the mount the inode was found from
 *  @dentry: object to perform setxattr on
 *  @name: xattr name to set
 *  @value: value to set @name to
 *  @size: size of @value
 *  @flags: flags to pass into filesystem operations
 *
 *  returns the result of the internal setxattr or setsecurity operations.
 *
 *  This function requires the caller to lock the inode's i_mutex before it
 *  is executed. It also assumes that the caller will make the appropriate
 *  permission checks.
 */
int __vfs_setxattr_noperm(struct user_namespace *mnt_userns,
			  struct dentry *dentry, const char *name,
			  const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	int error = -EAGAIN;
	int issec = !strncmp(name, XATTR_SECURITY_PREFIX,
				   XATTR_SECURITY_PREFIX_LEN);

	if (issec)
		inode->i_flags &= ~S_NOSEC;
	if (inode->i_opflags & IOP_XATTR) {
		error = __vfs_setxattr(mnt_userns, dentry, inode, name, value,
				       size, flags);
		if (!error) {
			fsnotify_xattr(dentry);
			security_inode_post_setxattr(dentry, name, value,
						     size, flags);
		}
	} else {
		if (unlikely(is_bad_inode(inode)))
			return -EIO;
	}
	if (error == -EAGAIN) {
		error = -EOPNOTSUPP;

		if (issec) {
			const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;

			error = security_inode_setsecurity(inode, suffix, value,
							   size, flags);
			if (!error)
				fsnotify_xattr(dentry);
		}
	}

	return error;
}

/**
 * __vfs_setxattr_locked - set an extended attribute while holding the inode
 * lock
 *
 *  @mnt_userns: user namespace of the mount of the target inode
 *  @dentry: object to perform setxattr on
 *  @name: xattr name to set
 *  @value: value to set @name to
 *  @size: size of @value
 *  @flags: flags to pass into filesystem operations
 *  @delegated_inode: on return, will contain an inode pointer that
 *  a delegation was broken on, NULL if none.
 */
int
__vfs_setxattr_locked(struct user_namespace *mnt_userns, struct dentry *dentry,
		      const char *name, const void *value, size_t size,
		      int flags, struct inode **delegated_inode)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(mnt_userns, inode, name, MAY_WRITE);
	if (error)
		return error;

	error = security_inode_setxattr(mnt_userns, dentry, name, value, size,
					flags);
	if (error)
		goto out;

	error = try_break_deleg(inode, delegated_inode);
	if (error)
		goto out;

	error = __vfs_setxattr_noperm(mnt_userns, dentry, name, value,
				      size, flags);

out:
	return error;
}
EXPORT_SYMBOL_GPL(__vfs_setxattr_locked);

static inline bool is_posix_acl_xattr(const char *name)
{
	return (strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS) == 0) ||
	       (strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT) == 0);
}

int
vfs_setxattr(struct user_namespace *mnt_userns, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct inode *delegated_inode = NULL;
	const void  *orig_value = value;
	int error;

	if (size && strcmp(name, XATTR_NAME_CAPS) == 0) {
		error = cap_convert_nscap(mnt_userns, dentry, &value, size);
		if (error < 0)
			return error;
		size = error;
	}

retry_deleg:
	inode_lock(inode);
	error = __vfs_setxattr_locked(mnt_userns, dentry, name, value, size,
				      flags, &delegated_inode);
	inode_unlock(inode);

	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	if (value != orig_value)
		kfree(value);

	return error;
}
EXPORT_SYMBOL_GPL(vfs_setxattr);

static ssize_t
xattr_getsecurity(struct user_namespace *mnt_userns, struct inode *inode,
		  const char *name, void *value, size_t size)
{
	void *buffer = NULL;
	ssize_t len;

	if (!value || !size) {
		len = security_inode_getsecurity(mnt_userns, inode, name,
						 &buffer, false);
		goto out_noalloc;
	}

	len = security_inode_getsecurity(mnt_userns, inode, name, &buffer,
					 true);
	if (len < 0)
		return len;
	if (size < len) {
		len = -ERANGE;
		goto out;
	}
	memcpy(value, buffer, len);
out:
	kfree(buffer);
out_noalloc:
	return len;
}

/*
 * vfs_getxattr_alloc - allocate memory, if necessary, before calling getxattr
 *
 * Allocate memory, if not already allocated, or re-allocate correct size,
 * before retrieving the extended attribute.
 *
 * Returns the result of alloc, if failed, or the getxattr operation.
 */
ssize_t
vfs_getxattr_alloc(struct user_namespace *mnt_userns, struct dentry *dentry,
		   const char *name, char **xattr_value, size_t xattr_size,
		   gfp_t flags)
{
	const struct xattr_handler *handler;
	struct inode *inode = dentry->d_inode;
	char *value = *xattr_value;
	int error;

	error = xattr_permission(mnt_userns, inode, name, MAY_READ);
	if (error)
		return error;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->get)
		return -EOPNOTSUPP;
	error = handler->get(handler, dentry, inode, name, NULL, 0);
	if (error < 0)
		return error;

	if (!value || (error > xattr_size)) {
		value = krealloc(*xattr_value, error + 1, flags);
		if (!value)
			return -ENOMEM;
		memset(value, 0, error + 1);
	}

	error = handler->get(handler, dentry, inode, name, value, error);
	*xattr_value = value;
	return error;
}

ssize_t
__vfs_getxattr(struct dentry *dentry, struct inode *inode, const char *name,
	       void *value, size_t size)
{
	const struct xattr_handler *handler;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->get)
		return -EOPNOTSUPP;
	return handler->get(handler, dentry, inode, name, value, size);
}
EXPORT_SYMBOL(__vfs_getxattr);

ssize_t
vfs_getxattr(struct user_namespace *mnt_userns, struct dentry *dentry,
	     const char *name, void *value, size_t size)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(mnt_userns, inode, name, MAY_READ);
	if (error)
		return error;

	error = security_inode_getxattr(dentry, name);
	if (error)
		return error;

	if (!strncmp(name, XATTR_SECURITY_PREFIX,
				XATTR_SECURITY_PREFIX_LEN)) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		int ret = xattr_getsecurity(mnt_userns, inode, suffix, value,
					    size);
		/*
		 * Only overwrite the return value if a security module
		 * is actually active.
		 */
		if (ret == -EOPNOTSUPP)
			goto nolsm;
		return ret;
	}
nolsm:
	error = __vfs_getxattr(dentry, inode, name, value, size);
	if (error > 0 && is_posix_acl_xattr(name))
		posix_acl_getxattr_idmapped_mnt(mnt_userns, inode, value, size);
	return error;
}
EXPORT_SYMBOL_GPL(vfs_getxattr);

ssize_t
vfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct inode *inode = d_inode(dentry);
	ssize_t error;

	error = security_inode_listxattr(dentry);
	if (error)
		return error;
	if (inode->i_op->listxattr && (inode->i_opflags & IOP_XATTR)) {
		error = inode->i_op->listxattr(dentry, list, size);
	} else {
		error = security_inode_listsecurity(inode, list, size);
		if (size && error > size)
			error = -ERANGE;
	}
	return error;
}
EXPORT_SYMBOL_GPL(vfs_listxattr);

int
__vfs_removexattr(struct user_namespace *mnt_userns, struct dentry *dentry,
		  const char *name)
{
	struct inode *inode = d_inode(dentry);
	const struct xattr_handler *handler;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->set)
		return -EOPNOTSUPP;
	return handler->set(handler, mnt_userns, dentry, inode, name, NULL, 0,
			    XATTR_REPLACE);
}
EXPORT_SYMBOL(__vfs_removexattr);

/**
 * __vfs_removexattr_locked - set an extended attribute while holding the inode
 * lock
 *
 *  @mnt_userns: user namespace of the mount of the target inode
 *  @dentry: object to perform setxattr on
 *  @name: name of xattr to remove
 *  @delegated_inode: on return, will contain an inode pointer that
 *  a delegation was broken on, NULL if none.
 */
int
__vfs_removexattr_locked(struct user_namespace *mnt_userns,
			 struct dentry *dentry, const char *name,
			 struct inode **delegated_inode)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(mnt_userns, inode, name, MAY_WRITE);
	if (error)
		return error;

	error = security_inode_removexattr(mnt_userns, dentry, name);
	if (error)
		goto out;

	error = try_break_deleg(inode, delegated_inode);
	if (error)
		goto out;

	error = __vfs_removexattr(mnt_userns, dentry, name);

	if (!error) {
		fsnotify_xattr(dentry);
		evm_inode_post_removexattr(dentry, name);
	}

out:
	return error;
}
EXPORT_SYMBOL_GPL(__vfs_removexattr_locked);

int
vfs_removexattr(struct user_namespace *mnt_userns, struct dentry *dentry,
		const char *name)
{
	struct inode *inode = dentry->d_inode;
	struct inode *delegated_inode = NULL;
	int error;

retry_deleg:
	inode_lock(inode);
	error = __vfs_removexattr_locked(mnt_userns, dentry,
					 name, &delegated_inode);
	inode_unlock(inode);

	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}

	return error;
}
EXPORT_SYMBOL_GPL(vfs_removexattr);

/*
 * Extended attribute SET operations
 */

int setxattr_copy(const char __user *name, struct xattr_ctx *ctx)
{
	int error;

	if (ctx->flags & ~(XATTR_CREATE|XATTR_REPLACE))
		return -EINVAL;

	error = strncpy_from_user(ctx->kname->name, name,
				sizeof(ctx->kname->name));
	if (error == 0 || error == sizeof(ctx->kname->name))
		return  -ERANGE;
	if (error < 0)
		return error;

	error = 0;
	if (ctx->size) {
		if (ctx->size > XATTR_SIZE_MAX)
			return -E2BIG;

		ctx->kvalue = vmemdup_user(ctx->cvalue, ctx->size);
		if (IS_ERR(ctx->kvalue)) {
			error = PTR_ERR(ctx->kvalue);
			ctx->kvalue = NULL;
		}
	}

	return error;
}

static void setxattr_convert(struct user_namespace *mnt_userns,
			     struct dentry *d, struct xattr_ctx *ctx)
{
	if (ctx->size && is_posix_acl_xattr(ctx->kname->name))
		posix_acl_fix_xattr_from_user(ctx->kvalue, ctx->size);
}

int do_setxattr(struct user_namespace *mnt_userns, struct dentry *dentry,
		struct xattr_ctx *ctx)
{
	setxattr_convert(mnt_userns, dentry, ctx);
	return vfs_setxattr(mnt_userns, dentry, ctx->kname->name,
			ctx->kvalue, ctx->size, ctx->flags);
}

static long
setxattr(struct user_namespace *mnt_userns, struct dentry *d,
	const char __user *name, const void __user *value, size_t size,
	int flags)
{
	struct xattr_name kname;
	struct xattr_ctx ctx = {
		.cvalue   = value,
		.kvalue   = NULL,
		.size     = size,
		.kname    = &kname,
		.flags    = flags,
	};
	int error;

	error = setxattr_copy(name, &ctx);
	if (error)
		return error;

	error = do_setxattr(mnt_userns, d, &ctx);

	kvfree(ctx.kvalue);
	return error;
}

static int path_setxattr(const char __user *pathname,
			 const char __user *name, const void __user *value,
			 size_t size, int flags, unsigned int lookup_flags)
{
	struct path path;
	int error;

retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = setxattr(mnt_user_ns(path.mnt), path.dentry, name,
				 value, size, flags);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE5(setxattr, const char __user *, pathname,
		const char __user *, name, const void __user *, value,
		size_t, size, int, flags)
{
	return path_setxattr(pathname, name, value, size, flags, LOOKUP_FOLLOW);
}

SYSCALL_DEFINE5(lsetxattr, const char __user *, pathname,
		const char __user *, name, const void __user *, value,
		size_t, size, int, flags)
{
	return path_setxattr(pathname, name, value, size, flags, 0);
}

SYSCALL_DEFINE5(fsetxattr, int, fd, const char __user *, name,
		const void __user *,value, size_t, size, int, flags)
{
	struct fd f = fdget(fd);
	int error = -EBADF;

	if (!f.file)
		return error;
	audit_file(f.file);
	error = mnt_want_write_file(f.file);
	if (!error) {
		error = setxattr(file_mnt_user_ns(f.file),
				 f.file->f_path.dentry, name,
				 value, size, flags);
		mnt_drop_write_file(f.file);
	}
	fdput(f);
	return error;
}

/*
 * Extended attribute GET operations
 */
ssize_t
do_getxattr(struct user_namespace *mnt_userns, struct dentry *d,
	struct xattr_ctx *ctx)
{
	ssize_t error;
	char *kname = ctx->kname->name;

	if (ctx->size) {
		if (ctx->size > XATTR_SIZE_MAX)
			ctx->size = XATTR_SIZE_MAX;
		ctx->kvalue = kvzalloc(ctx->size, GFP_KERNEL);
		if (!ctx->kvalue)
			return -ENOMEM;
	}

	error = vfs_getxattr(mnt_userns, d, kname, ctx->kvalue, ctx->size);
	if (error > 0) {
		if (is_posix_acl_xattr(kname))
			posix_acl_fix_xattr_to_user(ctx->kvalue, error);
		if (ctx->size && copy_to_user(ctx->value, ctx->kvalue, error))
			error = -EFAULT;
	} else if (error == -ERANGE && ctx->size >= XATTR_SIZE_MAX) {
		/* The file system tried to returned a value bigger
		   than XATTR_SIZE_MAX bytes. Not possible. */
		error = -E2BIG;
	}

	return error;
}

static ssize_t
getxattr(struct user_namespace *mnt_userns, struct dentry *d,
	 const char __user *name, void __user *value, size_t size)
{
	ssize_t error;
	struct xattr_name kname;
	struct xattr_ctx ctx = {
		.value    = value,
		.kvalue   = NULL,
		.size     = size,
		.kname    = &kname,
		.flags    = 0,
	};

	error = strncpy_from_user(kname.name, name, sizeof(kname.name));
	if (error == 0 || error == sizeof(kname.name))
		error = -ERANGE;
	if (error < 0)
		return error;

	error =  do_getxattr(mnt_userns, d, &ctx);

	kvfree(ctx.kvalue);
	return error;
}

static ssize_t path_getxattr(const char __user *pathname,
			     const char __user *name, void __user *value,
			     size_t size, unsigned int lookup_flags)
{
	struct path path;
	ssize_t error;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = getxattr(mnt_user_ns(path.mnt), path.dentry, name, value, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE4(getxattr, const char __user *, pathname,
		const char __user *, name, void __user *, value, size_t, size)
{
	return path_getxattr(pathname, name, value, size, LOOKUP_FOLLOW);
}

SYSCALL_DEFINE4(lgetxattr, const char __user *, pathname,
		const char __user *, name, void __user *, value, size_t, size)
{
	return path_getxattr(pathname, name, value, size, 0);
}

SYSCALL_DEFINE4(fgetxattr, int, fd, const char __user *, name,
		void __user *, value, size_t, size)
{
	struct fd f = fdget(fd);
	ssize_t error = -EBADF;

	if (!f.file)
		return error;
	audit_file(f.file);
	error = getxattr(file_mnt_user_ns(f.file), f.file->f_path.dentry,
			 name, value, size);
	fdput(f);
	return error;
}

/*
 * Extended attribute LIST operations
 */
static ssize_t
listxattr(struct dentry *d, char __user *list, size_t size)
{
	ssize_t error;
	char *klist = NULL;

	if (size) {
		if (size > XATTR_LIST_MAX)
			size = XATTR_LIST_MAX;
		klist = kvmalloc(size, GFP_KERNEL);
		if (!klist)
			return -ENOMEM;
	}

	error = vfs_listxattr(d, klist, size);
	if (error > 0) {
		if (size && copy_to_user(list, klist, error))
			error = -EFAULT;
	} else if (error == -ERANGE && size >= XATTR_LIST_MAX) {
		/* The file system tried to returned a list bigger
		   than XATTR_LIST_MAX bytes. Not possible. */
		error = -E2BIG;
	}

	kvfree(klist);

	return error;
}

static ssize_t path_listxattr(const char __user *pathname, char __user *list,
			      size_t size, unsigned int lookup_flags)
{
	struct path path;
	ssize_t error;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = listxattr(path.dentry, list, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list,
		size_t, size)
{
	return path_listxattr(pathname, list, size, LOOKUP_FOLLOW);
}

SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list,
		size_t, size)
{
	return path_listxattr(pathname, list, size, 0);
}

SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size)
{
	struct fd f = fdget(fd);
	ssize_t error = -EBADF;

	if (!f.file)
		return error;
	audit_file(f.file);
	error = listxattr(f.file->f_path.dentry, list, size);
	fdput(f);
	return error;
}

/*
 * Extended attribute REMOVE operations
 */
static long
removexattr(struct user_namespace *mnt_userns, struct dentry *d,
	    const char __user *name)
{
	int error;
	char kname[XATTR_NAME_MAX + 1];

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	return vfs_removexattr(mnt_userns, d, kname);
}

static int path_removexattr(const char __user *pathname,
			    const char __user *name, unsigned int lookup_flags)
{
	struct path path;
	int error;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = removexattr(mnt_user_ns(path.mnt), path.dentry, name);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE2(removexattr, const char __user *, pathname,
		const char __user *, name)
{
	return path_removexattr(pathname, name, LOOKUP_FOLLOW);
}

SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname,
		const char __user *, name)
{
	return path_removexattr(pathname, name, 0);
}

SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
{
	struct fd f = fdget(fd);
	int error = -EBADF;

	if (!f.file)
		return error;
	audit_file(f.file);
	error = mnt_want_write_file(f.file);
	if (!error) {
		error = removexattr(file_mnt_user_ns(f.file),
				    f.file->f_path.dentry, name);
		mnt_drop_write_file(f.file);
	}
	fdput(f);
	return error;
}

/*
 * Combine the results of the list() operation from every xattr_handler in the
 * list.
 */
ssize_t
generic_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	const struct xattr_handler *handler, **handlers = dentry->d_sb->s_xattr;
	unsigned int size = 0;

	if (!buffer) {
		for_each_xattr_handler(handlers, handler) {
			if (!handler->name ||
			    (handler->list && !handler->list(dentry)))
				continue;
			size += strlen(handler->name) + 1;
		}
	} else {
		char *buf = buffer;
		size_t len;

		for_each_xattr_handler(handlers, handler) {
			if (!handler->name ||
			    (handler->list && !handler->list(dentry)))
				continue;
			len = strlen(handler->name);
			if (len + 1 > buffer_size)
				return -ERANGE;
			memcpy(buf, handler->name, len + 1);
			buf += len + 1;
			buffer_size -= len + 1;
		}
		size = buf - buffer;
	}
	return size;
}
EXPORT_SYMBOL(generic_listxattr);

/**
 * xattr_full_name  -  Compute full attribute name from suffix
 *
 * @handler:	handler of the xattr_handler operation
 * @name:	name passed to the xattr_handler operation
 *
 * The get and set xattr handler operations are called with the remainder of
 * the attribute name after skipping the handler's prefix: for example, "foo"
 * is passed to the get operation of a handler with prefix "user." to get
 * attribute "user.foo".  The full name is still "there" in the name though.
 *
 * Note: the list xattr handler operation when called from the vfs is passed a
 * NULL name; some file systems use this operation internally, with varying
 * semantics.
 */
const char *xattr_full_name(const struct xattr_handler *handler,
			    const char *name)
{
	size_t prefix_len = strlen(xattr_prefix(handler));

	return name - prefix_len;
}
EXPORT_SYMBOL(xattr_full_name);

/**
 * simple_xattr_key_hashfn - hash function for the xattr key
 * @data: the xattr name
 * @len: ignored
 * @seed: the seed to pass to the hash function
 *
 * This is the has function used to generate the key for a simple xattr.
 *
 * Return: hashed key
 */
static u32 simple_xattr_key_hashfn(const void *data, u32 len, u32 seed)
{
	const char *xattr_name = data;

	return jhash(xattr_name, strlen(xattr_name), seed);
}

/**
 * simple_xattr_obj_hashfn - hash function for the xattr object
 * @data: the xattr object
 * @len: ignored
 * @seed: the seed to pass to the hash function
 *
 * This is the has function used to generate the hash for the key based on the
 * corresponding xattr object.
 *
 * Return: hashed key
 */
static u32 simple_xattr_obj_hashfn(const void *data, u32 len, u32 seed)
{
	const struct simple_xattr *xattr = data;

	return jhash(xattr->name, strlen(xattr->name), seed);
}

/**
 * simple_xattr_obj_cmpfn - compare xattr entry and hashed key
 * @arg: rhashtable arguments
 * @ptr: the xattr object
 *
 * This is the has function used to compare the xattr name and the
 * corresponding xattr entry.
 *
 * Return: If the entry matches 0 is returned. If the entry doesn't match 1 is
 * returned.
 */
static int simple_xattr_obj_cmpfn(struct rhashtable_compare_arg *arg,
				  const void *ptr)
{
	const struct simple_xattr *xattr = ptr;
	const char *xattr_name = arg->key;

	if (strcmp(xattr->name, xattr_name))
		return 1;

	return 0;
}

/* We currently don't specify a maximum and minimum size. */
static const struct rhashtable_params rhash_params = {
	.key_offset		= offsetof(struct simple_xattr, name),
	.head_offset		= offsetof(struct simple_xattr, rhash_head),
	.hashfn			= simple_xattr_key_hashfn,
	.obj_hashfn		= simple_xattr_obj_hashfn,
	.obj_cmpfn		= simple_xattr_obj_cmpfn,
	.automatic_shrinking	= true,
};

/**
 * get_simple_xattr - bump refcount on an xattr objects
 * @xattr: the xattr object
 *
 * Bump the reference count of the xattr object if it hasn't gone to zero. If
 * it is zero we know it will be removed the hashtable.
 *
 * Return: If the xattr object is still in the hastable the xattr is returned.
 * If the xattr object will be removed zero is returned.
 */
static inline struct simple_xattr *get_simple_xattr(struct simple_xattr *xattr)
{
	if (likely(refcount_inc_not_zero(&xattr->ref)))
		return xattr;
	return NULL;
}

/**
 * free_simple_xattr - free an xattr object
 * @xattr: the xattr object
 *
 * Free the xattr object. Can handle @xattr being NULL.
 */
static inline void free_simple_xattr(struct simple_xattr *xattr)
{
	if (xattr)
		kfree(xattr->name);
	kvfree(xattr);
}

/**
 * free_simple_xattr_rcu_cb - callback for freeing xattr object through rcu
 * @cb: the rcu callback head
 */
static void free_simple_xattr_rcu_cb(struct callback_head *cb_head)
{
	struct simple_xattr *xattr =
		container_of(cb_head, struct simple_xattr, rcu_head);
	free_simple_xattr(xattr);
}

/**
 * free_simple_xattr_rcu - free an xattr object with rcu semantics
 * @xattr: the xattr object
 */
static void free_simple_xattr_rcu(struct simple_xattr *xattr)
{
	call_rcu(&xattr->rcu_head, free_simple_xattr_rcu_cb);
}

/**
 * put_simple_xattr - decrement refcount for xattr object
 * @xattr: the xattr object
 *
 * Decrement the reference count of an xattr object and free it using rcu
 * semantics if we're the holder of the last reference. Can handle @xattr being
 * NULL.
 */
static inline void put_simple_xattr(struct simple_xattr *xattr)
{
	if (xattr && refcount_dec_and_test(&xattr->ref))
		free_simple_xattr_rcu(xattr);
}

/**
 * simple_xattr_alloc - allocate new xattr object
 * @value: value of the xattr object
 * @size: size of @value
 *
 * Allocate a new xattr object and initialize respective members. The caller is
 * responsible for handling the name of the xattr.
 *
 * The initial reference count belongs to the rhashtable. Note that
 * heap-allocated rcu_heads don't need to be initialized.
 *
 * Return: On success a new xattr object is returned. On failure NULL is
 * returned.
 */
struct simple_xattr *simple_xattr_alloc(const void *value, size_t size)
{
	struct simple_xattr *new_xattr;
	size_t len;

	/* wrap around? */
	len = sizeof(*new_xattr) + size;
	if (len < sizeof(*new_xattr))
		return NULL;

	new_xattr = kvmalloc(len, GFP_KERNEL);
	if (!new_xattr)
		return NULL;

	new_xattr->size = size;
	memcpy(new_xattr->value, value, size);
	refcount_set(&new_xattr->ref, 1);
	return new_xattr;
}

/**
 * simple_xattr_get - get an xattr object
 * @xattrs: the header of the xattr object
 * @name: the name of the xattr to retrieve
 * @buffer: the buffer to store the value into
 * @size: the size of @buffer
 *
 * Try to find and retrieve the xattr object associated with @name. This looks
 * up the xattr object in the rhashtable. If the object is found and still in
 * the rhashtable bump the reference count.
 *
 * If @buffer is provided store the value of @xattr in @buffer.
 *
 * Return: On success zero and on error a negative error code is returned.
 */
int simple_xattr_get(struct simple_xattrs *xattrs, const char *name,
		     void *buffer, size_t size)
{
	struct simple_xattr *xattr;
	int ret = 0;

	rcu_read_lock();
	xattr = rhashtable_lookup(&xattrs->rhash_tbl, name, rhash_params);
	if (!xattr || !get_simple_xattr(xattr))
		ret = -ENODATA;
	rcu_read_unlock();
	if (ret)
		return ret;

	ret = xattr->size;
	if (buffer) {
		if (size < xattr->size)
			ret = -ERANGE;
		else
			memcpy(buffer, xattr->value, xattr->size);
	}

	put_simple_xattr(xattr);
	return ret;
}

/**
 * simple_xattr_set - set an xattr object
 * @xattrs: the header of the xattr object
 * @name: the name of the xattr to retrieve
 * @value: the value to store along the xattr
 * @size: the size of @value
 * @flags: the flags determining how to set the xattr
 * @removed_size: the size of the removed xattr
 *
 * Set a new xattr object.
 * If @value is passed a new xattr object will be allocated. If XATTR_REPLACE
 * is specified in @flags a matching xattr object for @name must already exist.
 * If it does it will be replace with the new xattr object. If it doesn't we
 * fail. If XATTR_CREATE is specified and a matching xattr does already exist
 * we fail. If it doesn't we create a new xattr. If @flags is zero we simply
 * insert the new xattr replacing any existing one.
 *
 * If @value is empty and a matching xattr object is found we delete it if
 * XATTR_REPLACE is specified in @flags or @flags is zero.
 *
 * If @value is empty and no matching xattr object for @name is found we do
 * nothing if XATTR_CREATE is specified in @flags or @flags is zero. For
 * XATTR_REPLACE we fail as mentioned above.
 *
 * Return: On success zero and on error a negative error code is returned.
 */
int simple_xattr_set(struct simple_xattrs *xattrs, const char *name,
		     const void *value, size_t size, int flags,
		     ssize_t *removed_size)
{
	struct simple_xattr *xattr;
	struct simple_xattr *new_xattr = NULL;
	int err = 0;

	if (removed_size)
		*removed_size = -1;

	if (value) {
		new_xattr = simple_xattr_alloc(value, size);
		if (!new_xattr)
			return -ENOMEM;

		new_xattr->name = kstrdup(name, GFP_KERNEL);
		if (!new_xattr->name) {
			kvfree(new_xattr);
			return -ENOMEM;
		}
	}

	spin_lock(&xattrs->lock);
	xattr = rhashtable_lookup_fast(&xattrs->rhash_tbl, name, rhash_params);
	if (xattr) {
		/* Fail if XATTR_CREATE is requested and the xattr exists. */
		if (flags & XATTR_CREATE) {
			err = -EEXIST;
			goto out_unlock;
		}

		/*
		 * If XATTR_REPLACE or no flags are specified together with a
		 * new value then we replace the existing xattr.
		 *
		 * If XATTR_REPLACE or no flags are specified without a new
		 * value we remove the existing xattr.
		 */
		if (new_xattr)
			err = rhashtable_replace_fast(&xattrs->rhash_tbl,
						      &xattr->rhash_head,
						      &new_xattr->rhash_head,
						      rhash_params);
		else
			rhashtable_remove_fast(&xattrs->rhash_tbl,
					       &xattr->rhash_head,
					       rhash_params);
		if (!err && removed_size)
			*removed_size = xattr->size;
	} else {
		/* Fail if XATTR_REPLACE is requested but no xattr is found. */
		if (flags & XATTR_REPLACE) {
			err = -ENODATA;
			goto out_unlock;
		}

		/*
		 * If XATTR_CREATE or no flags are specified together with a
		 * new value simply insert it.
		 */
		if (new_xattr)
			err = rhashtable_insert_fast(&xattrs->rhash_tbl,
						     &new_xattr->rhash_head,
						     rhash_params);
		/*
		 * If XATTR_CREATE or no flags are specified and neither an old
		 * or new xattr were found/exist then we don't need to do
		 * anything.
		 */
	}

out_unlock:
	spin_unlock(&xattrs->lock);
	if (err)
		free_simple_xattr(new_xattr);
	else
		put_simple_xattr(xattr);
	return err;
}

static bool xattr_is_trusted(const char *name)
{
	return !strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN);
}

static int xattr_list_one(char **buffer, ssize_t *remaining_size,
			  const char *name)
{
	size_t len = strlen(name) + 1;
	if (*buffer) {
		if (*remaining_size < len)
			return -ERANGE;
		memcpy(*buffer, name, len);
		*buffer += len;
	}
	*remaining_size -= len;
	return 0;
}

/**
 * simple_xattr_list - list all xattr objects
 * @inode: inode from which to get the xattrs
 * @xattrs: the header of the xattr object
 * @buffer: the buffer to store all xattrs into
 * @size: the size of @buffer
 *
 * List all xattrs associated with @inode. If @buffer is NULL we returned the
 * required size of the buffer. If @buffer is provided we store the xattrs
 * value into it provided it is big enough.
 *
 * This is lockles and we don't bump the reference count. So if callers race
 * with deletion they may see xattrs about to be removed. This is a race
 * userspace has to handle since forever anyway.
 *
 * Return: On success the required size or the size of the copied xattrs is
 * returned. On error a negative error code is returned.
 */
ssize_t simple_xattr_list(struct inode *inode, struct simple_xattrs *xattrs,
			  char *buffer, size_t size)
{
	bool trusted = capable(CAP_SYS_ADMIN);
	struct rhashtable_iter iter;
	struct simple_xattr *xattr;
	ssize_t remaining_size = size;
	int err = 0;

#ifdef CONFIG_FS_POSIX_ACL
	if (IS_POSIXACL(inode)) {
		if (inode->i_acl) {
			err = xattr_list_one(&buffer, &remaining_size,
					     XATTR_NAME_POSIX_ACL_ACCESS);
			if (err)
				return err;
		}
		if (inode->i_default_acl) {
			err = xattr_list_one(&buffer, &remaining_size,
					     XATTR_NAME_POSIX_ACL_DEFAULT);
			if (err)
				return err;
		}
	}
#endif

	rhashtable_walk_enter(&xattrs->rhash_tbl, &iter);
	rhashtable_walk_start(&iter);
	while ((xattr = rhashtable_walk_next(&iter))) {
		if (IS_ERR(xattr))
			continue;

		/* skip "trusted." attributes for unprivileged callers */
		if (!trusted && xattr_is_trusted(xattr->name))
			continue;

		/* skip removed xattrs */
		if (refcount_read(&xattr->ref) == 0)
			continue;

		err = xattr_list_one(&buffer, &remaining_size, xattr->name);
		if (err)
			break;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	return err ? err : size - remaining_size;
}

/**
 * simple_xattr_add - add xattr objects
 * @xattrs: the header of the xattr object
 * @xattr: the xattr object to add
 *
 * Add an xattr object to @xattrs. This assumes no replacement or removal of
 * matching xattrs is wanted.
 *
 * Return: On success zero and on error a negative error code is returned.
 */
int simple_xattr_add(struct simple_xattrs *xattrs,
		     struct simple_xattr *new_xattr)
{
	int err;

	spin_lock(&xattrs->lock);
	err = rhashtable_insert_fast(&xattrs->rhash_tbl,
				     &new_xattr->rhash_head, rhash_params);
	spin_unlock(&xattrs->lock);
	return err;
}

/**
 * simple_xattr_init - initialize new xattr header
 * @xattrs: header to initialize
 *
 * Initialize relevant fields of a an xattr header.
 *
 * Return: On success zero and on error a negative error code is returned.
 */
int simple_xattrs_init(struct simple_xattrs *xattrs)
{
	spin_lock_init(&xattrs->lock);
	return rhashtable_init(&xattrs->rhash_tbl, &rhash_params);
}

/**
 * free_simple_xattr_rhash_rc - free simple xattr in rhashtable
 * @data: the xattr object
 * @arg: ignored
 *
 * This is a callback function which which will be used to free xattr object
 * during during rhashtable teardown.
 */
static void free_simple_xattr_rhash_cb(void *data, void *arg)
{
	struct simple_xattr *xattr = data;
	free_simple_xattr(xattr);
}

/**
 * simple_xattrs_free - free xattrs
 * @xattrs: xattr header whose xattrs to destroy
 *
 * Destroy all xattrs and the rhashtable of @xattrs.
 */
void simple_xattrs_free(struct simple_xattrs *xattrs)
{
	rhashtable_free_and_destroy(&xattrs->rhash_tbl,
				    free_simple_xattr_rhash_cb, NULL);
}
