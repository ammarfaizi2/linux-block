/*
 *  linux/fs/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * Some corrections by tytso.
 */

/* [Feb 1997 T. Schoebel-Theuer] Complete rewrite of the pathname
 * lookup logic.
 */
/* [Feb-Apr 2000, AV] Rewrite to the new namespace architecture.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <asm/uaccess.h>

#include "internal.h"
#include "mount.h"
#include "union.h"

/* [Feb-1997 T. Schoebel-Theuer]
 * Fundamental changes in the pathname lookup mechanisms (namei)
 * were necessary because of omirr.  The reason is that omirr needs
 * to know the _real_ pathname, not the user-supplied one, in case
 * of symlinks (and also when transname replacements occur).
 *
 * The new code replaces the old recursive symlink resolution with
 * an iterative one (in case of non-nested symlink chains).  It does
 * this with calls to <fs>_follow_link().
 * As a side effect, dir_namei(), _namei() and follow_link() are now 
 * replaced with a single function lookup_dentry() that can handle all 
 * the special cases of the former code.
 *
 * With the new dcache, the pathname is stored at each inode, at least as
 * long as the refcount of the inode is positive.  As a side effect, the
 * size of the dcache depends on the inode cache and thus is dynamic.
 *
 * [29-Apr-1998 C. Scott Ananian] Updated above description of symlink
 * resolution to correspond with current state of the code.
 *
 * Note that the symlink resolution is not *completely* iterative.
 * There is still a significant amount of tail- and mid- recursion in
 * the algorithm.  Also, note that <fs>_readlink() is not used in
 * lookup_dentry(): lookup_dentry() on the result of <fs>_readlink()
 * may return different results than <fs>_follow_link().  Many virtual
 * filesystems (including /proc) exhibit this behavior.
 */

/* [24-Feb-97 T. Schoebel-Theuer] Side effects caused by new implementation:
 * New symlink semantics: when open() is called with flags O_CREAT | O_EXCL
 * and the name already exists in form of a symlink, try to create the new
 * name indicated by the symlink. The old code always complained that the
 * name already exists, due to not following the symlink even if its target
 * is nonexistent.  The new semantics affects also mknod() and link() when
 * the name is a symlink pointing to a non-existent name.
 *
 * I don't know which semantics is the right one, since I have no access
 * to standards. But I found by trial that HP-UX 9.0 has the full "new"
 * semantics implemented, while SunOS 4.1.1 and Solaris (SunOS 5.4) have the
 * "old" one. Personally, I think the new semantics is much more logical.
 * Note that "ln old new" where "new" is a symlink pointing to a non-existing
 * file does succeed in both HP-UX and SunOs, but not in Solaris
 * and in the old Linux semantics.
 */

/* [16-Dec-97 Kevin Buhr] For security reasons, we change some symlink
 * semantics.  See the comments in "open_namei" and "do_link" below.
 *
 * [10-Sep-98 Alan Modra] Another symlink change.
 */

/* [Feb-Apr 2000 AV] Complete rewrite. Rules for symlinks:
 *	inside the path - always follow.
 *	in the last component in creation/removal/renaming - never follow.
 *	if LOOKUP_FOLLOW passed - follow.
 *	if the pathname has trailing slashes - follow.
 *	otherwise - don't follow.
 * (applied in that order).
 *
 * [Jun 2000 AV] Inconsistent behaviour of open() in case if flags==O_CREAT
 * restored for 2.4. This is the last surviving part of old 4.2BSD bug.
 * During the 2.4 we need to fix the userland stuff depending on it -
 * hopefully we will be able to get rid of that wart in 2.5. So far only
 * XEmacs seems to be relying on it...
 */
/*
 * [Sep 2001 AV] Single-semaphore locking scheme (kudos to David Holland)
 * implemented.  Let's see if raised priority of ->s_vfs_rename_mutex gives
 * any extra contention...
 */

/* In order to reduce some races, while at the same time doing additional
 * checking and hopefully speeding things up, we copy filenames to the
 * kernel data space before using them..
 *
 * POSIX.1 2.4: an empty pathname is invalid (ENOENT).
 * PATH_MAX includes the nul terminator --RR.
 */
void final_putname(struct filename *name)
{
	if (name->separate) {
		__putname(name->name);
		kfree(name);
	} else {
		__putname(name);
	}
}

#define EMBEDDED_NAME_MAX	(PATH_MAX - sizeof(struct filename))

static struct filename *
getname_flags(const char __user *filename, int flags, int *empty)
{
	struct filename *result, *err;
	int len;
	long max;
	char *kname;

	result = audit_reusename(filename);
	if (result)
		return result;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	/*
	 * First, try to embed the struct filename inside the names_cache
	 * allocation
	 */
	kname = (char *)result + sizeof(*result);
	result->name = kname;
	result->separate = false;
	max = EMBEDDED_NAME_MAX;

recopy:
	len = strncpy_from_user(kname, filename, max);
	if (unlikely(len < 0)) {
		err = ERR_PTR(len);
		goto error;
	}

	/*
	 * Uh-oh. We have a name that's approaching PATH_MAX. Allocate a
	 * separate struct filename so we can dedicate the entire
	 * names_cache allocation for the pathname, and re-do the copy from
	 * userland.
	 */
	if (len == EMBEDDED_NAME_MAX && max == EMBEDDED_NAME_MAX) {
		kname = (char *)result;

		result = kzalloc(sizeof(*result), GFP_KERNEL);
		if (!result) {
			err = ERR_PTR(-ENOMEM);
			result = (struct filename *)kname;
			goto error;
		}
		result->name = kname;
		result->separate = true;
		max = PATH_MAX;
		goto recopy;
	}

	/* The empty path is special. */
	if (unlikely(!len)) {
		if (empty)
			*empty = 1;
		err = ERR_PTR(-ENOENT);
		if (!(flags & LOOKUP_EMPTY))
			goto error;
	}

	err = ERR_PTR(-ENAMETOOLONG);
	if (unlikely(len >= PATH_MAX))
		goto error;

	result->uptr = filename;
	audit_getname(result);
	return result;

error:
	final_putname(result);
	return err;
}

struct filename *
getname(const char __user * filename)
{
	return getname_flags(filename, 0, NULL);
}
EXPORT_SYMBOL(getname);

#ifdef CONFIG_AUDITSYSCALL
void putname(struct filename *name)
{
	if (unlikely(!audit_dummy_context()))
		return audit_putname(name);
	final_putname(name);
}
#endif

static int check_acl(struct inode *inode, int mask)
{
#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl *acl;

	if (mask & MAY_NOT_BLOCK) {
		acl = get_cached_acl_rcu(inode, ACL_TYPE_ACCESS);
	        if (!acl)
	                return -EAGAIN;
		/* no ->get_acl() calls in RCU mode... */
		if (acl == ACL_NOT_CACHED)
			return -ECHILD;
	        return posix_acl_permission(inode, acl, mask & ~MAY_NOT_BLOCK);
	}

	acl = get_cached_acl(inode, ACL_TYPE_ACCESS);

	/*
	 * A filesystem can force a ACL callback by just never filling the
	 * ACL cache. But normally you'd fill the cache either at inode
	 * instantiation time, or on the first ->get_acl call.
	 *
	 * If the filesystem doesn't have a get_acl() function at all, we'll
	 * just create the negative cache entry.
	 */
	if (acl == ACL_NOT_CACHED) {
	        if (inode->i_op->get_acl) {
			acl = inode->i_op->get_acl(inode, ACL_TYPE_ACCESS);
			if (IS_ERR(acl))
				return PTR_ERR(acl);
		} else {
		        set_cached_acl(inode, ACL_TYPE_ACCESS, NULL);
		        return -EAGAIN;
		}
	}

	if (acl) {
	        int error = posix_acl_permission(inode, acl, mask);
	        posix_acl_release(acl);
	        return error;
	}
#endif

	return -EAGAIN;
}

/*
 * This does the basic permission checking
 */
static int acl_permission_check(struct inode *inode, int mask)
{
	unsigned int mode = inode->i_mode;

	if (likely(uid_eq(current_fsuid(), inode->i_uid)))
		mode >>= 6;
	else {
		if (IS_POSIXACL(inode) && (mode & S_IRWXG)) {
			int error = check_acl(inode, mask);
			if (error != -EAGAIN)
				return error;
		}

		if (in_group_p(inode->i_gid))
			mode >>= 3;
	}

	/*
	 * If the DACs are ok we don't need any capability check.
	 */
	if ((mask & ~mode & (MAY_READ | MAY_WRITE | MAY_EXEC)) == 0)
		return 0;
	return -EACCES;
}

/**
 * generic_permission -  check for access rights on a Posix-like filesystem
 * @inode:	inode to check access rights for
 * @mask:	right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC, ...)
 *
 * Used to check for read/write/execute permissions on a file.
 * We use "fsuid" for this, letting us set arbitrary permissions
 * for filesystem access without changing the "normal" uids which
 * are used for other things.
 *
 * generic_permission is rcu-walk aware. It returns -ECHILD in case an rcu-walk
 * request cannot be satisfied (eg. requires blocking or too much complexity).
 * It would then be called again in ref-walk mode.
 */
int generic_permission(struct inode *inode, int mask)
{
	int ret;

	/*
	 * Do the basic permission checks.
	 */
	ret = acl_permission_check(inode, mask);
	if (ret != -EACCES)
		return ret;

	if (S_ISDIR(inode->i_mode)) {
		/* DACs are overridable for directories */
		if (inode_capable(inode, CAP_DAC_OVERRIDE))
			return 0;
		if (!(mask & MAY_WRITE))
			if (inode_capable(inode, CAP_DAC_READ_SEARCH))
				return 0;
		return -EACCES;
	}
	/*
	 * Read/write DACs are always overridable.
	 * Executable DACs are overridable when there is
	 * at least one exec bit set.
	 */
	if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
		if (inode_capable(inode, CAP_DAC_OVERRIDE))
			return 0;

	/*
	 * Searching includes executable on directories, else just read.
	 */
	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
	if (mask == MAY_READ)
		if (inode_capable(inode, CAP_DAC_READ_SEARCH))
			return 0;

	return -EACCES;
}

/*
 * We _really_ want to just do "generic_permission()" without
 * even looking at the inode->i_op values. So we keep a cache
 * flag in inode->i_opflags, that says "this has not special
 * permission function, use the fast case".
 */
static inline int do_inode_permission(struct inode *inode, int mask)
{
	if (unlikely(!(inode->i_opflags & IOP_FASTPERM))) {
		if (likely(inode->i_op->permission))
			return inode->i_op->permission(inode, mask);

		/* This gets set once for the inode lifetime */
		spin_lock(&inode->i_lock);
		inode->i_opflags |= IOP_FASTPERM;
		spin_unlock(&inode->i_lock);
	}
	return generic_permission(inode, mask);
}

/**
 * __inode_permission - Check for access rights to a given inode
 * @inode: Inode to check permission on
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Check for read/write/execute permissions on an inode.
 *
 * When checking for MAY_APPEND, MAY_WRITE must also be set in @mask.
 *
 * This does not check for a read-only file system.  You probably want
 * inode_permission().
 */
int __inode_permission(struct inode *inode, int mask)
{
	int retval;

	if (unlikely(mask & MAY_WRITE)) {
		/*
		 * Nobody gets write access to an immutable file.
		 */
		if (IS_IMMUTABLE(inode))
			return -EACCES;
	}

	retval = do_inode_permission(inode, mask);
	if (retval)
		return retval;

	retval = devcgroup_inode_permission(inode, mask);
	if (retval)
		return retval;

	return security_inode_permission(inode, mask);
}

/**
 * sb_permission - Check superblock-level permissions
 * @sb: Superblock of inode to check permission on
 * @inode: Inode to check permission on
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Separate out file-system wide checks from inode-specific permission checks.
 */
int sb_permission(struct super_block *sb, struct inode *inode, int mask)
{
	if (unlikely(mask & MAY_WRITE)) {
		umode_t mode = inode->i_mode;

		/* Nobody gets write access to a read-only fs. */
		if ((sb->s_flags & MS_RDONLY) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;
	}
	return 0;
}

/**
 * inode_permission - Check for access rights to a given inode
 * @inode: Inode to check permission on
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Check for read/write/execute permissions on an inode.  We use fs[ug]id for
 * this, letting us set arbitrary permissions for filesystem access without
 * changing the "normal" UIDs which are used for other things.
 *
 * When checking for MAY_APPEND, MAY_WRITE must also be set in @mask.
 */
int inode_permission(struct inode *inode, int mask)
{
	int retval;

	retval = sb_permission(inode->i_sb, inode, mask);
	if (retval)
		return retval;
	return __inode_permission(inode, mask);
}

/**
 * path_get - get a reference to a path
 * @path: path to get the reference to
 *
 * Given a path increment the reference count to the dentry and the vfsmount.
 */
void path_get(const struct path *path)
{
	mntget(path->mnt);
	dget(path->dentry);
}
EXPORT_SYMBOL(path_get);

/**
 * path_put - put a reference to a path
 * @path: path to put the reference to
 *
 * Given a path decrement the reference count to the dentry and the vfsmount.
 */
void path_put(const struct path *path)
{
	dput(path->dentry);
	mntput(path->mnt);
}
EXPORT_SYMBOL(path_put);

/*
 * Path walking has 2 modes, rcu-walk and ref-walk (see
 * Documentation/filesystems/path-lookup.txt).  In situations when we can't
 * continue in RCU mode, we attempt to drop out of rcu-walk mode and grab
 * normal reference counts on dentries and vfsmounts to transition to rcu-walk
 * mode.  Refcounts are grabbed at the last known good point before rcu-walk
 * got stuck, so ref-walk may continue from there. If this is not successful
 * (eg. a seqcount has changed), then failure is returned and it's up to caller
 * to restart the path walk from the beginning in ref-walk mode.
 */

/**
 * unlazy_walk - try to switch to ref-walk mode.
 * @nd: nameidata pathwalk data
 * @dentry: child of nd->path.dentry or NULL
 * Returns: 0 on success, -ECHILD on failure
 *
 * unlazy_walk attempts to legitimize the current nd->path, nd->root and dentry
 * for ref-walk mode.  @dentry must be a path found by a do_lookup call on
 * @nd or NULL.  Must be called from rcu-walk context.
 */
static int unlazy_walk(struct nameidata *nd, struct dentry *dentry)
{
	struct fs_struct *fs = current->fs;
	struct dentry *parent = nd->path.dentry;

	BUG_ON(!(nd->flags & LOOKUP_RCU));

	/*
	 * After legitimizing the bastards, terminate_walk()
	 * will do the right thing for non-RCU mode, and all our
	 * subsequent exit cases should rcu_read_unlock()
	 * before returning.  Do vfsmount first; if dentry
	 * can't be legitimized, just set nd->path.dentry to NULL
	 * and rely on dput(NULL) being a no-op.
	 */
	if (!legitimize_mnt(nd->path.mnt, nd->m_seq))
		return -ECHILD;
	nd->flags &= ~LOOKUP_RCU;

	if (!lockref_get_not_dead(&parent->d_lockref)) {
		nd->path.dentry = NULL;	
		goto out;
	}

	/*
	 * For a negative lookup, the lookup sequence point is the parents
	 * sequence point, and it only needs to revalidate the parent dentry.
	 *
	 * For a positive lookup, we need to move both the parent and the
	 * dentry from the RCU domain to be properly refcounted. And the
	 * sequence number in the dentry validates *both* dentry counters,
	 * since we checked the sequence number of the parent after we got
	 * the child sequence number. So we know the parent must still
	 * be valid if the child sequence number is still valid.
	 */
	if (!dentry) {
		if (read_seqcount_retry(&parent->d_seq, nd->seq))
			goto out;
		BUG_ON(nd->inode != parent->d_inode);
	} else {
		if (!lockref_get_not_dead(&dentry->d_lockref))
			goto out;
		if (read_seqcount_retry(&dentry->d_seq, nd->seq))
			goto drop_dentry;
	}

	/*
	 * Sequence counts matched. Now make sure that the root is
	 * still valid and get it if required.
	 */
	if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT)) {
		spin_lock(&fs->lock);
		if (nd->root.mnt != fs->root.mnt || nd->root.dentry != fs->root.dentry)
			goto unlock_and_drop_dentry;
		path_get(&nd->root);
		spin_unlock(&fs->lock);
	}

	rcu_read_unlock();
	return 0;

unlock_and_drop_dentry:
	spin_unlock(&fs->lock);
drop_dentry:
	rcu_read_unlock();
	dput(dentry);
	goto drop_root_mnt;
out:
	rcu_read_unlock();
drop_root_mnt:
	if (!(nd->flags & LOOKUP_ROOT))
		nd->root.mnt = NULL;
	return -ECHILD;
}

static inline int d_revalidate(struct dentry *dentry, unsigned int flags)
{
	return dentry->d_op->d_revalidate(dentry, flags);
}

/**
 * complete_walk - successful completion of path walk
 * @nd:  pointer nameidata
 *
 * If we had been in RCU mode, drop out of it and legitimize nd->path.
 * Revalidate the final result, unless we'd already done that during
 * the path walk or the filesystem doesn't ask for it.  Return 0 on
 * success, -error on failure.  In case of failure caller does not
 * need to drop nd->path.
 */
static int complete_walk(struct nameidata *nd)
{
	struct dentry *dentry = nd->path.dentry;
	struct inode *inode;
	int status;

	if (nd->flags & LOOKUP_RCU) {
		nd->flags &= ~LOOKUP_RCU;
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;

		if (!legitimize_mnt(nd->path.mnt, nd->m_seq)) {
			rcu_read_unlock();
			return -ECHILD;
		}
		if (unlikely(!lockref_get_not_dead(&dentry->d_lockref))) {
			rcu_read_unlock();
			mntput(nd->path.mnt);
			return -ECHILD;
		}
		if (read_seqcount_retry(&dentry->d_seq, nd->seq)) {
			rcu_read_unlock();
			dput(dentry);
			mntput(nd->path.mnt);
			return -ECHILD;
		}
		inode = d_inode_or_lower(dentry);
		BUG_ON(nd->inode != inode);
		rcu_read_unlock();
	}

	if (likely(!(nd->flags & LOOKUP_JUMPED)))
		return 0;

	if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE)))
		return 0;

	status = dentry->d_op->d_weak_revalidate(dentry, nd->flags);
	if (status > 0)
		return 0;

	if (!status)
		status = -ESTALE;

	path_put(&nd->path);
	return status;
}

static __always_inline void set_root(struct nameidata *nd)
{
	if (!nd->root.mnt)
		get_fs_root(current->fs, &nd->root);
}

static int link_path_walk(const char *, struct nameidata *);

static __always_inline void set_root_rcu(struct nameidata *nd)
{
	if (!nd->root.mnt) {
		struct fs_struct *fs = current->fs;
		unsigned seq;

		do {
			seq = read_seqcount_begin(&fs->seq);
			nd->root = fs->root;
			nd->seq = __read_seqcount_begin(&nd->root.dentry->d_seq);
		} while (read_seqcount_retry(&fs->seq, seq));
	}
}

static void path_put_conditional(struct path *path, struct nameidata *nd)
{
	dput(path->dentry);
	if (path->mnt != nd->path.mnt)
		mntput(path->mnt);
}

static inline void path_to_nameidata(const struct path *path,
					struct nameidata *nd)
{
	if (!(nd->flags & LOOKUP_RCU)) {
		dput(nd->path.dentry);
		if (nd->path.mnt != path->mnt)
			mntput(nd->path.mnt);
	}
	nd->path.mnt = path->mnt;
	nd->path.dentry = path->dentry;
}

/*
 * Helper to directly jump to a known parsed path from ->follow_link,
 * caller must have taken a reference to path beforehand.
 */
void nd_jump_link(struct nameidata *nd, struct path *path)
{
	path_put(&nd->path);

	nd->path = *path;
	nd->inode = nd->path.dentry->d_inode;
	nd->flags |= LOOKUP_JUMPED;
}

static inline void put_link(struct nameidata *nd, struct path *link, void *cookie)
{
	struct dentry *dentry = link->dentry;
	struct inode *inode;

	/* If the link was on the lower layer of a union when we started
	 * following it, then follow_link() must have updated link->dentry to
	 * point to that.
	 */
	inode = dentry->d_inode;
	if (inode->i_op->put_link)
		inode->i_op->put_link(dentry, nd, cookie);
	path_put(link);
}

int sysctl_protected_symlinks __read_mostly = 0;
int sysctl_protected_hardlinks __read_mostly = 0;

/**
 * may_follow_link - Check symlink following for unsafe situations
 * @link: The path of the symlink
 * @nd: nameidata pathwalk data
 *
 * In the case of the sysctl_protected_symlinks sysctl being enabled,
 * CAP_DAC_OVERRIDE needs to be specifically ignored if the symlink is
 * in a sticky world-writable directory. This is to protect privileged
 * processes from failing races against path names that may change out
 * from under them by way of other users creating malicious symlinks.
 * It will permit symlinks to be followed only when outside a sticky
 * world-writable directory, or when the uid of the symlink and follower
 * match, or when the directory owner matches the symlink's owner.
 *
 * Returns 0 if following the symlink is allowed, -ve on error.
 */
static inline int may_follow_link(struct path *link, struct nameidata *nd)
{
	const struct inode *inode;
	const struct inode *parent;

	if (!sysctl_protected_symlinks)
		return 0;

	/* Allowed if owner and follower match. */
	inode = link->dentry->d_inode;
#ifdef CONFIG_UNION_MOUNT
	if (!inode)
		inode = link->dentry->d_fallthru->d_inode;
#endif
	if (uid_eq(current_cred()->fsuid, inode->i_uid))
		return 0;

	/* Allowed if parent directory not sticky and world-writable. */
	parent = nd->path.dentry->d_inode;
	if ((parent->i_mode & (S_ISVTX|S_IWOTH)) != (S_ISVTX|S_IWOTH))
		return 0;

	/* Allowed if parent directory and link owner match. */
	if (uid_eq(parent->i_uid, inode->i_uid))
		return 0;

	audit_log_link_denied("follow_link", link);
	path_put_conditional(link, nd);
	path_put(&nd->path);
	return -EACCES;
}

/**
 * safe_hardlink_source - Check for safe hardlink conditions
 * @inode: the source inode to hardlink from
 *
 * Return false if at least one of the following conditions:
 *    - inode is not a regular file
 *    - inode is setuid
 *    - inode is setgid and group-exec
 *    - access failure for read and write
 *
 * Otherwise returns true.
 */
static bool safe_hardlink_source(struct inode *inode)
{
	umode_t mode = inode->i_mode;

	/* Special files should not get pinned to the filesystem. */
	if (!S_ISREG(mode))
		return false;

	/* Setuid files should not get pinned to the filesystem. */
	if (mode & S_ISUID)
		return false;

	/* Executable setgid files should not get pinned to the filesystem. */
	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))
		return false;

	/* Hardlinking to unreadable or unwritable sources is dangerous. */
	if (inode_permission(inode, MAY_READ | MAY_WRITE))
		return false;

	return true;
}

/**
 * may_linkat - Check permissions for creating a hardlink
 * @link: the source to hardlink from
 *
 * Block hardlink when all of:
 *  - sysctl_protected_hardlinks enabled
 *  - fsuid does not match inode
 *  - hardlink source is unsafe (see safe_hardlink_source() above)
 *  - not CAP_FOWNER
 *
 * Returns 0 if successful, -ve on error.
 */
static int may_linkat(struct path *link)
{
	struct inode *inode = link->dentry->d_inode;

	if (!sysctl_protected_hardlinks)
		return 0;

	/* Source inode owner (or CAP_FOWNER) can hardlink all they like,
	 * otherwise, it must be a safe source.
	 */
	if (uid_eq(current_cred()->fsuid, inode->i_uid) ||
	    safe_hardlink_source(inode) ||
	    capable(CAP_FOWNER)) {
		return 0;
	}

	audit_log_link_denied("linkat", link);
	return -EPERM;
}

static __always_inline int
follow_link(struct path *link, struct nameidata *nd, void **p)
{
	struct dentry *dentry = link->dentry;
	int error;
	char *s;

	BUG_ON(nd->flags & LOOKUP_RCU);

	if (link->mnt == nd->path.mnt)
		mntget(link->mnt);

	error = -ELOOP;
	if (unlikely(current->total_link_count >= 40))
		goto out_put_nd_path;

	cond_resched();
	current->total_link_count++;

	touch_atime(link);
	nd_set_link(nd, NULL);

#ifdef CONFIG_UNION_MOUNT
	if (unlikely(!dentry->d_inode)) {
		/* If the link is on the lower layer of a union, then we need
		 * to save this fact so that put_link() can call the correct
		 * ->put_link() op if the link gets copied whilst we're using
		 * it.
		 */
		link->dentry = dentry->d_fallthru;
		dput(dentry);
		dentry = dget(link->dentry);
	}
#endif

	error = security_inode_follow_link(dentry, nd);
	if (error)
		goto out_put_nd_path;

	nd->last_type = LAST_BIND;
	*p = dentry->d_inode->i_op->follow_link(dentry, nd);
	error = PTR_ERR(*p);
	if (IS_ERR(*p))
		goto out_put_nd_path;

	error = 0;
	s = nd_get_link(nd);
	if (s) {
		if (unlikely(IS_ERR(s))) {
			path_put(&nd->path);
			put_link(nd, link, *p);
			return PTR_ERR(s);
		}
		if (*s == '/') {
			set_root(nd);
			path_put(&nd->path);
			nd->path = nd->root;
			path_get(&nd->root);
			nd->flags |= LOOKUP_JUMPED;
		}
		nd->inode = nd->path.dentry->d_inode;
		error = link_path_walk(s, nd);
		if (unlikely(error))
			put_link(nd, link, *p);
	}

	return error;

out_put_nd_path:
	*p = NULL;
	path_put(&nd->path);
	path_put(link);
	return error;
}

static int follow_up_rcu(struct path *path)
{
	struct mount *mnt = real_mount(path->mnt);
	struct mount *parent;
	struct dentry *mountpoint;

	parent = mnt->mnt_parent;
	if (&parent->mnt == path->mnt)
		return 0;
	mountpoint = mnt->mnt_mountpoint;
	path->dentry = mountpoint;
	path->mnt = &parent->mnt;
	return 1;
}

/*
 * follow_up - Find the mountpoint of path's vfsmount
 *
 * Given a path, find the mountpoint of its source file system.
 * Replace @path with the path of the mountpoint in the parent mount.
 * Up is towards /.
 *
 * Return 1 if we went up a level and 0 if we were already at the
 * root.
 */
int follow_up(struct path *path)
{
	struct mount *mnt = real_mount(path->mnt);
	struct mount *parent;
	struct dentry *mountpoint;

	read_seqlock_excl(&mount_lock);
	parent = mnt->mnt_parent;
	if (parent == mnt) {
		read_sequnlock_excl(&mount_lock);
		return 0;
	}
	mntget(&parent->mnt);
	mountpoint = dget(mnt->mnt_mountpoint);
	read_sequnlock_excl(&mount_lock);
	dput(path->dentry);
	path->dentry = mountpoint;
	mntput(path->mnt);
	path->mnt = &parent->mnt;
	return 1;
}

/*
 * Perform an automount
 * - return -EISDIR to tell follow_managed() to stop and return the path we
 *   were called with.
 */
static int follow_automount(struct path *path, unsigned flags,
			    bool *need_mntput)
{
	struct vfsmount *mnt;
	int err;

	if (!path->dentry->d_op || !path->dentry->d_op->d_automount)
		return -EREMOTE;

	/* We don't want to mount if someone's just doing a stat -
	 * unless they're stat'ing a directory and appended a '/' to
	 * the name.
	 *
	 * We do, however, want to mount if someone wants to open or
	 * create a file of any type under the mountpoint, wants to
	 * traverse through the mountpoint or wants to open the
	 * mounted directory.  Also, autofs may mark negative dentries
	 * as being automount points.  These will need the attentions
	 * of the daemon to instantiate them before they can be used.
	 */
	if (!(flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY |
		     LOOKUP_OPEN | LOOKUP_CREATE | LOOKUP_AUTOMOUNT)) &&
	    path->dentry->d_inode)
		return -EISDIR;

	current->total_link_count++;
	if (current->total_link_count >= 40)
		return -ELOOP;

	mnt = path->dentry->d_op->d_automount(path);
	if (IS_ERR(mnt)) {
		/*
		 * The filesystem is allowed to return -EISDIR here to indicate
		 * it doesn't want to automount.  For instance, autofs would do
		 * this so that its userspace daemon can mount on this dentry.
		 *
		 * However, we can only permit this if it's a terminal point in
		 * the path being looked up; if it wasn't then the remainder of
		 * the path is inaccessible and we should say so.
		 */
		if (PTR_ERR(mnt) == -EISDIR && (flags & LOOKUP_PARENT))
			return -EREMOTE;
		return PTR_ERR(mnt);
	}

	if (!mnt) /* mount collision */
		return 0;

	if (!*need_mntput) {
		/* lock_mount() may release path->mnt on error */
		mntget(path->mnt);
		*need_mntput = true;
	}
	err = finish_automount(mnt, path);

	switch (err) {
	case -EBUSY:
		/* Someone else made a mount here whilst we were busy */
		return 0;
	case 0:
		path_put(path);
		path->mnt = mnt;
		path->dentry = dget(mnt->mnt_root);
		return 0;
	default:
		return err;
	}

}

/*
 * Handle a dentry that is managed in some way.
 * - Flagged for transit management (autofs)
 * - Flagged as mountpoint
 * - Flagged as automount point
 *
 * This may only be called in refwalk mode.
 *
 * Serialization is taken care of in namespace.c
 */
static int follow_managed(struct path *path, unsigned flags)
{
	struct vfsmount *mnt = path->mnt; /* held by caller, must be left alone */
	unsigned managed;
	bool need_mntput = false;
	int ret = 0;

	/* Given that we're not holding a lock here, we retain the value in a
	 * local variable for each dentry as we look at it so that we don't see
	 * the components of that value change under us */
	while (managed = ACCESS_ONCE(path->dentry->d_flags),
	       managed &= DCACHE_MANAGED_DENTRY,
	       unlikely(managed != 0)) {
		/* Allow the filesystem to manage the transit without i_mutex
		 * being held. */
		if (managed & DCACHE_MANAGE_TRANSIT) {
			BUG_ON(!path->dentry->d_op);
			BUG_ON(!path->dentry->d_op->d_manage);
			ret = path->dentry->d_op->d_manage(path->dentry, false);
			if (ret < 0)
				break;
		}

		/* Transit to a mounted filesystem. */
		if (managed & DCACHE_MOUNTED) {
			struct vfsmount *mounted = lookup_mnt(path);
			if (mounted) {
				dput(path->dentry);
				if (need_mntput)
					mntput(path->mnt);
				path->mnt = mounted;
				path->dentry = dget(mounted->mnt_root);
				need_mntput = true;
				continue;
			}

			/* Something is mounted on this dentry in another
			 * namespace and/or whatever was mounted there in this
			 * namespace got unmounted before lookup_mnt() could
			 * get it */
		}

		/* Handle an automount point */
		if (managed & DCACHE_NEED_AUTOMOUNT) {
			ret = follow_automount(path, flags, &need_mntput);
			if (ret < 0)
				break;
			continue;
		}

		/* We didn't change the current path point */
		break;
	}

	if (need_mntput && path->mnt == mnt)
		mntput(path->mnt);
	if (ret == -EISDIR)
		ret = 0;
	return ret < 0 ? ret : need_mntput;
}

int follow_down_one(struct path *path)
{
	struct vfsmount *mounted;

	mounted = lookup_mnt(path);
	if (mounted) {
		dput(path->dentry);
		mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
		return 1;
	}
	return 0;
}

static inline bool managed_dentry_might_block(struct dentry *dentry)
{
	return (dentry->d_flags & DCACHE_MANAGE_TRANSIT &&
		dentry->d_op->d_manage(dentry, true) < 0);
}

/*
 * Try to skip to top of mountpoint pile in rcuwalk mode.  Fail if
 * we meet a managed dentry that would need blocking.
 */
static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
			       struct inode **inode)
{
	for (;;) {
		struct mount *mounted;
		/*
		 * Don't forget we might have a non-mountpoint managed dentry
		 * that wants to block transit.
		 */
		if (unlikely(managed_dentry_might_block(path->dentry)))
			return false;

		if (!d_mountpoint(path->dentry))
			break;

		mounted = __lookup_mnt(path->mnt, path->dentry);
		if (!mounted)
			break;
		path->mnt = &mounted->mnt;
		path->dentry = mounted->mnt.mnt_root;
		nd->flags |= LOOKUP_JUMPED;
		nd->seq = read_seqcount_begin(&path->dentry->d_seq);
		/*
		 * Update the inode too. We don't need to re-check the
		 * dentry sequence number here after this d_inode read,
		 * because a mount-point is always pinned.
		 */
		*inode = path->dentry->d_inode;
	}
	return true;
}

static void follow_mount_rcu(struct nameidata *nd)
{
	while (d_mountpoint(nd->path.dentry)) {
		struct mount *mounted;
		mounted = __lookup_mnt(nd->path.mnt, nd->path.dentry);
		if (!mounted)
			break;
		nd->path.mnt = &mounted->mnt;
		nd->path.dentry = mounted->mnt.mnt_root;
		nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
	}
}

static int follow_dotdot_rcu(struct nameidata *nd)
{
	set_root_rcu(nd);

	while (1) {
		if (nd->path.dentry == nd->root.dentry &&
		    nd->path.mnt == nd->root.mnt) {
			break;
		}
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			struct dentry *old = nd->path.dentry;
			struct dentry *parent = old->d_parent;
			unsigned seq;

			seq = read_seqcount_begin(&parent->d_seq);
			if (read_seqcount_retry(&old->d_seq, nd->seq))
				goto failed;
			nd->path.dentry = parent;
			nd->seq = seq;
			break;
		}
		if (!follow_up_rcu(&nd->path))
			break;
		nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
	}
	follow_mount_rcu(nd);
	nd->inode = nd->path.dentry->d_inode;
	return 0;

failed:
	nd->flags &= ~LOOKUP_RCU;
	if (!(nd->flags & LOOKUP_ROOT))
		nd->root.mnt = NULL;
	rcu_read_unlock();
	return -ECHILD;
}

/*
 * Follow down to the covering mount currently visible to userspace.  At each
 * point, the filesystem owning that dentry may be queried as to whether the
 * caller is permitted to proceed or not.
 */
int follow_down(struct path *path)
{
	unsigned managed;
	int ret;

	while (managed = ACCESS_ONCE(path->dentry->d_flags),
	       unlikely(managed & DCACHE_MANAGED_DENTRY)) {
		/* Allow the filesystem to manage the transit without i_mutex
		 * being held.
		 *
		 * We indicate to the filesystem if someone is trying to mount
		 * something here.  This gives autofs the chance to deny anyone
		 * other than its daemon the right to mount on its
		 * superstructure.
		 *
		 * The filesystem may sleep at this point.
		 */
		if (managed & DCACHE_MANAGE_TRANSIT) {
			BUG_ON(!path->dentry->d_op);
			BUG_ON(!path->dentry->d_op->d_manage);
			ret = path->dentry->d_op->d_manage(
				path->dentry, false);
			if (ret < 0)
				return ret == -EISDIR ? 0 : ret;
		}

		/* Transit to a mounted filesystem. */
		if (managed & DCACHE_MOUNTED) {
			struct vfsmount *mounted = lookup_mnt(path);
			if (!mounted)
				break;
			dput(path->dentry);
			mntput(path->mnt);
			path->mnt = mounted;
			path->dentry = dget(mounted->mnt_root);
			continue;
		}

		/* Don't handle automount points here */
		break;
	}
	return 0;
}

/*
 * Skip to top of mountpoint pile in refwalk mode for follow_dotdot()
 */
static void follow_mount(struct path *path)
{
	while (d_mountpoint(path->dentry)) {
		struct vfsmount *mounted = lookup_mnt(path);
		if (!mounted)
			break;
		dput(path->dentry);
		mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
	}
}

static void follow_dotdot(struct nameidata *nd)
{
	set_root(nd);

	while(1) {
		struct dentry *old = nd->path.dentry;

		if (nd->path.dentry == nd->root.dentry &&
		    nd->path.mnt == nd->root.mnt) {
			break;
		}
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			/* rare case of legitimate dget_parent()... */
			nd->path.dentry = dget_parent(nd->path.dentry);
			dput(old);
			break;
		}
		if (!follow_up(&nd->path))
			break;
	}
	follow_mount(&nd->path);
	nd->inode = nd->path.dentry->d_inode;
}

/*
 * Inspect the lower layers of a potentially unioned file and appropriately
 * annotate the upper dentry.  Returns:
 *
 * (*) 0 if encountered a dir first - the union stack will be filled in, but
 *     will not be attached to the dentry.  The caller must create the top
 *     dentry first and only then attach it.
 *
 * (*) -ENOTDIR if encountered a symlink first - and upper d_fallthru will be
 *	set to point to the lower symlink and DCACHE_SYMLINK will be set.
 *
 * (*) -ENOTDIR if we encountered any other type of file first.
 *
 * (*) -ENOENT if we didn't encounter anything.
 *
 * The caller must hold i_mutex on the parent dir.
 */
static int union_annotate_dentry(struct path *parent, struct path *path,
				 struct union_stack *d)
{
	struct dentry *dentry = path->dentry, *lower = NULL;
	unsigned flags, i, layers = parent->dentry->d_sb->s_union_count;
	int ret = -ENOENT;

	printk("UNION: -->union_annotate_dentry(%pd/%pd {%x})\n",
	       parent->dentry, dentry, dentry->d_flags);

	BUG_ON(dentry->d_flags & DCACHE_UNION_PINNING_LOWER);

	if (d_is_whiteout(dentry)) {
		spin_lock(&dentry->d_lock);
		BUG_ON(!d_is_whiteout(dentry));
		dentry->d_flags |= DCACHE_UNION_LOOKUP_DONE;
		spin_unlock(&dentry->d_lock);
		return -ENOENT;
	}

	if (IS_OPAQUE(parent->dentry->d_inode) && !d_is_fallthru(dentry)) {
		spin_lock(&dentry->d_lock);
		dentry->d_flags |= DCACHE_UNION_LOOKUP_DONE;
		spin_unlock(&dentry->d_lock);
		return -ENOENT;
	}

	for (i = 0; i < layers; i++) {
		/* Get the parent directory for this layer and lookup
		 * the target in it.
		 */
		struct path *lower_parent = union_find_dir(parent->dentry, i);
		if (!lower_parent->mnt)
			continue;

		mutex_lock(&lower_parent->dentry->d_inode->i_mutex);
		lower = __lookup_hash(&dentry->d_name, lower_parent->dentry, 0);
		mutex_unlock(&lower_parent->dentry->d_inode->i_mutex);

		if (IS_ERR(lower)) {
			ret = PTR_ERR(lower);
			goto error_no_dput;
		}

		/* A negative dentry can mean several things: a plain negative
		 * dentry is ignored and lookup continues to the next layer,
		 * but a whiteout or a non-fallthru in an opaque dir covers
		 * everything below it.
		 */
		if (!lower->d_inode) {
			if (d_is_whiteout(lower))
				goto found_blocker;
			if (!d_is_fallthru(lower) &&
			    IS_OPAQUE(lower_parent->dentry->d_inode))
				goto found_blocker;
			dput(lower);
			lower = NULL;
			continue;
		}

		/* Non-directories block everything below them.  Special case:
		 * If we find a file below a directory (which makes no sense),
		 * just ignore the file and return the directory above it.
		 */
		if (!d_is_directory(lower)) {
			if (ret != -ENOENT)
				break;
			goto found_nondir_first;
		}

		printk("UNION: layer %u is dir\n", i);

		/* Mountpoints and automount points on a lowerfs just confuse
		 * everything, so refuse to handle them for the moment.
		 */
		if (unlikely(d_mountpoint(lower))) {
			if (ret == -ENOENT)
				ret = -EXDEV;
			goto error_dput;
		}
		if (unlikely(d_managed(lower))) {
			if (ret == -ENOENT)
				ret = -EREMOTE;
			goto error_dput;
		}

		d->u_dirs[i].dentry = lower;
		d->u_dirs[i].mnt = mntget(lower_parent->mnt);
		lower = NULL;
		ret = 0;
	}

	/* We may have found a lower directory at this point.  If we did, we
	 * don't annotate the dentry, but rather leave that to the caller to do
	 * when creating the upper directory.
	 *
	 * If there was nothing underneath, then annotate the top as being
	 * negative.
	 */
	if (ret == -ENOENT) {
		printk("UNION: Nothing underneath\n");
		flags = DCACHE_MISS_TYPE | DCACHE_UNION_LOOKUP_DONE;
		goto set_negative;
	}
found_directory:
	dput(lower);
	return 0;

	/* We found a blocking dentry in the lower levels so we mark the top
	 * dentry as blocking too.  The whiteout/negative type is propagated
	 * upwards.
	 */
found_blocker:
	printk("UNION: Found opaque/whiteout first\n");
	if (ret == 0)
		goto found_directory;
	flags = __d_entry_type(lower) | DCACHE_UNION_LOOKUP_DONE;
	dput(lower);
set_negative:
	spin_lock(&dentry->d_lock);
	if (!(dentry->d_flags & DCACHE_UNION_LOOKUP_DONE)) {
		BUG_ON(!d_is_miss(dentry));
		dentry->d_flags |= flags;
	}
	spin_unlock(&dentry->d_lock);
	return -ENOENT;

	/* A dentry that covers a lower file of any type is flagged and given a
	 * reference to the underlying file to hold.  We do the attachment here
	 * so as not to have to pass the lower dentry back to the caller.
	 */
found_nondir_first:
	printk("UNION: Found non-dir first\n");
	flags = __d_entry_type(lower) | DCACHE_UNION_LOOKUP_DONE;
	spin_lock(&dentry->d_lock);
	BUG_ON(!d_is_miss(dentry));
	if (!(dentry->d_flags & DCACHE_UNION_LOOKUP_DONE)) {
		d_pin_lower(dentry, lower);
		dentry->d_flags |= flags;
		printk("UNION: pin lower %x\n", dentry->d_flags);
		lower = NULL;
	} else {
		printk("UNION: lower already pinned\n");
	}
	spin_unlock(&dentry->d_lock);
	dput(lower);
	return -ENOTDIR;

error_dput:
	dput(lower);
error_no_dput:
	return ret;
}

/**
 * __union_lookup_point_locked - Look up the current dentry in lower layers under lock
 * @parent: The parent of @path
 * @path: Path of the target on the upper file system
 *
 * The caller must be holding the parent dir's i_mutex and must have locked the
 * mount point for write.
 */
static int __union_lookup_point_locked(struct path *parent, struct path *path)
{
	struct union_stack *d;
	struct dentry *dentry = path->dentry;
	int ret;

	printk("UNION: -->__union_lookup_point_locked(%pd/%pd)\n",
	       parent->dentry, dentry);

	d = union_alloc_stack(path);
	if (!d)
		return -ENOMEM;

	ret = union_annotate_dentry(parent, path, d);
	if (ret < 0) {
		if (ret == -ENOTDIR)
			ret = 0;
		goto out_kill_stack;
	}

	/* It's a directory, so it must be created on the upper level */
	printk("UNION: May need to create dir\n");

	ret = union_create_topmost_dir(parent, path, d);
	if (ret < 0)
		goto out_kill_stack;

	spin_lock(&dentry->d_lock);
	d_set_union_stack(dentry, d);
	dentry->d_flags |= DCACHE_UNION_LOOKUP_DONE;
	spin_unlock(&dentry->d_lock);
	ret = 0;
out:
	printk("UNION: <--__union_lookup_point_locked() = %d\n", ret);
	return ret;

out_kill_stack:
	union_free(parent, d);
	goto out;
}

static int union_lookup_point_locked(struct path *parent, struct path *path)
{
	if (!IS_PATH_UNIONED(parent) ||
	    path->dentry->d_flags & DCACHE_UNION_LOOKUP_DONE)
		return 0;

	return __union_lookup_point_locked(parent, path);
}

/**
 * __union_lookup_point - Look up the current point, raising a dir to upper level
 * @parent: The parent of @path
 * @path: Path of the target on the upper file system
 * @got_write: The caller is holding antifreeze on the upper mount.
 */
static int __union_lookup_point(struct path *parent, struct path *path,
				bool got_write)
{
	struct union_stack *d;
	struct dentry *dentry = path->dentry;
	struct inode *dir = parent->dentry->d_inode;
	int ret;

	printk("UNION: -->__union_lookup_point(%pd/%pd)\n",
	       parent->dentry, path->dentry);

	d = union_alloc_stack(path);
	if (!d)
		return -ENOMEM;

	mutex_lock_nested(&dir->i_mutex, I_MUTEX_PARENT);
	if (dentry->d_flags & DCACHE_UNION_LOOKUP_DONE) {
		printk("UNION: already (1)\n");
		ret = 0;
		goto out_unlock_mutex;
	}

	ret = union_annotate_dentry(parent, path, d);
	mutex_unlock(&dir->i_mutex);

	if (ret < 0) {
		if (ret == -ENOTDIR) {
			printk("UNION: sym/file\n");
			ret = 0;
		}
		goto out;
	}

	/* It's a directory, so it must be raised to the upper level.  However,
	 * we had to drop the parent lock so that we can take the locks in the
	 * right order.
	 */
	printk("UNION: May need to raise dir\n");
	if (!got_write) {
		ret = mnt_want_write(parent->mnt);
		if (ret < 0)
			goto out;
	}

	mutex_lock_nested(&dir->i_mutex, I_MUTEX_PARENT);

	if (!(dentry->d_flags & DCACHE_UNION_LOOKUP_DONE)) {
		printk("UNION: Need to raise dir\n");
		ret = union_create_topmost_dir(parent, path, d);
		if (ret == 0) {
			spin_lock(&dentry->d_lock);
			d_set_union_stack(dentry, d);
			dentry->d_flags |= DCACHE_UNION_LOOKUP_DONE;
			spin_unlock(&dentry->d_lock);
			d = NULL;
		}
	} else {
		printk("UNION: already (2)\n");
		ret = 0;
	}

	if (!got_write)
		mnt_drop_write(parent->mnt);
out_unlock_mutex:
	mutex_unlock(&dir->i_mutex);
out:
	union_free(parent, d);
	printk("UNION: <--__union_lookup_point() = %d\n", ret);
	return ret;
}

static int union_lookup_point(struct nameidata *nd, struct path *path,
			      bool got_write)
{
	if (!IS_PATH_UNIONED(&nd->path) ||
	    path->dentry->d_flags & DCACHE_UNION_LOOKUP_DONE)
		return 0;

	if (nd->flags & LOOKUP_RCU) {
		printk("UNION: unlazy for union_lookup_point()\n");
		if (unlikely(unlazy_walk(nd, path->dentry)))
			return -ECHILD;
	}

	return __union_lookup_point(&nd->path, path, got_write);
}

/*
 * lookup_union_rcu - Handle union mounted dentries in RCU-walk mode
 * @parent: The parent directory.
 * @path: The point just looked up in @parent.
 * @inode: The inode at @dentry (*@inode is NULL if negative dentry).
 *
 * Handle a dentry that represents a non-directory file or a hole/reference in
 * a union mount upperfs
 *
 * We return true if we don't need to do anything or if we've successfully
 * updated the path.  If we need to drop out of RCU-walk and go to refwalk
 * mode, we return false.
 */
static bool lookup_union_rcu(struct path *parent,
			     struct path *path,
			     struct inode **inode)
{
	struct dentry *dentry = path->dentry;

	/* Handle non-unionmount dentries first. */
	if (likely(!IS_PATH_UNIONED(parent)))
		return true;

	printk("UNION: Dir is unioned (RCU)\n");

	/* If it's positive then no further lookup is needed: the file or
	 * directory has been copied up and the user gets to play with that.
	 */
	if (*inode)
		return true;

	/* If this dentry is a blocker, then stop here. */
	if (d_is_negative(dentry))
		return true;

	/* If we need to look below, then we should break out of RCU walk mode
	 * with immediate effect.  There are three cases:
	 *
	 * (1) We've encountered a lower directory.  This must be copied up.
	 *
	 * (2) We've encountered a symlink.  Symlinks are walked in refwalk
	 *     mode (or (3) applies if NOFOLLOW).
	 *
	 * (3) We've encountered some other type of file.  This must terminate
	 *     the pathwalk immediately, one way or another.
	 */
	printk("UNION: Drop out of RCU\n");
	return false;
}

/*
 * This looks up the name in dcache, possibly revalidates the old dentry and
 * allocates a new one if not found or not valid.  In the need_lookup argument
 * returns whether i_op->lookup is necessary.
 *
 * dir->d_inode->i_mutex must be held
 */
static struct dentry *lookup_dcache(struct qstr *name, struct dentry *dir,
				    unsigned int flags, bool *need_lookup)
{
	struct dentry *dentry;
	int error;

	*need_lookup = false;
	dentry = d_lookup(dir, name);
	if (dentry) {
		if (dentry->d_flags & DCACHE_OP_REVALIDATE) {
			error = d_revalidate(dentry, flags);
			if (unlikely(error <= 0)) {
				if (error < 0) {
					dput(dentry);
					return ERR_PTR(error);
				} else if (!d_invalidate(dentry)) {
					dput(dentry);
					dentry = NULL;
				}
			}
		}
	}

	if (!dentry) {
		dentry = d_alloc(dir, name);
		if (unlikely(!dentry))
			return ERR_PTR(-ENOMEM);

		*need_lookup = true;
	}
	return dentry;
}

/*
 * Call i_op->lookup on the dentry.  The dentry must be negative and
 * unhashed.
 *
 * dir->d_inode->i_mutex must be held
 */
static struct dentry *lookup_real(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct dentry *old;

	/* Don't create child dentry for a dead directory. */
	if (unlikely(IS_DEADDIR(dir))) {
		dput(dentry);
		return ERR_PTR(-ENOENT);
	}

	old = dir->i_op->lookup(dir, dentry, flags);
	if (unlikely(old)) {
		dput(dentry);
		dentry = old;
	}
	return dentry;
}

struct dentry *__lookup_hash(struct qstr *name,
		struct dentry *base, unsigned int flags)
{
	bool need_lookup;
	struct dentry *dentry;

	dentry = lookup_dcache(name, base, flags, &need_lookup);
	if (!need_lookup)
		return dentry;

	return lookup_real(base->d_inode, dentry, flags);
}

/*
 *  It's more convoluted than I'd like it to be, but... it's still fairly
 *  small and for now I'd prefer to have fast path as straight as possible.
 *  It _is_ time-critical.
 */
static noinline int lookup_fast(struct nameidata *nd,
		       struct path *path, struct inode **_inode)
{
	struct vfsmount *mnt = nd->path.mnt;
	struct dentry *dentry, *parent = nd->path.dentry;
	int need_reval = 1;
	int status = 1;
	int err;

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: --> lookup_fast(%*.*s)\n",
		       nd->last.len, nd->last.len, nd->last.name);

	/*
	 * Rename seqlock is not required here because in the off chance
	 * of a false negative due to a concurrent rename, we're going to
	 * do the non-racy lookup, below.
	 */
	if (nd->flags & LOOKUP_RCU) {
		unsigned seq, pseq;
		dentry = __d_lookup_rcu(parent, &nd->last, &seq);
		if (!dentry) {
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: __d_lookup_rcu\n");
			goto unlazy;
		}

		/*
		 * This sequence count validates that the inode matches
		 * the dentry name information from lookup.
		 */
		*_inode = d_inode_or_lower(dentry);
		if (read_seqcount_retry(&dentry->d_seq, seq))
			return -ECHILD;

		/*
		 * This sequence count validates that the parent had no
		 * changes while we did the lookup of the dentry above.
		 *
		 * The memory barrier in read_seqcount_begin of child is
		 *  enough, we can use __read_seqcount_retry here.
		 */
		pseq = nd->seq;
		if (__read_seqcount_retry(&parent->d_seq, pseq))
			return -ECHILD;
		nd->seq = seq;

		if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE)) {
			status = d_revalidate(dentry, nd->flags);
			if (unlikely(status <= 0)) {
				if (status != -ECHILD)
					need_reval = 0;
				if (IS_PATH_UNIONED(&nd->path))
					printk("UNION: d_revalidate\n");
				goto unlazy;
			}
		}
		path->mnt = mnt;
		path->dentry = dentry;
		if (unlikely(!lookup_union_rcu(&nd->path, path, _inode))) {
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: !lookup_union_rcu\n");
			goto unlazy;
		}
		if (unlikely(!__follow_mount_rcu(nd, path, _inode))) {
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: !__follow_mount_rcu\n");
			goto unlazy;
		}
		if (unlikely(path->dentry->d_flags & DCACHE_NEED_AUTOMOUNT)) {
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: need_automount\n");
			goto unlazy;
		}
		return 0;
unlazy:
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: unlazy\n");
		if (unlazy_walk(nd, dentry))
			return -ECHILD;
	} else {
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: !RCU\n");
		dentry = __d_lookup(parent, &nd->last);
	}

	if (unlikely(!dentry))
		goto need_lookup;

	if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE) && need_reval)
		status = d_revalidate(dentry, nd->flags);
	if (unlikely(status <= 0)) {
		if (status < 0) {
			dput(dentry);
			return status;
		}
		if (!d_invalidate(dentry)) {
			dput(dentry);
			goto need_lookup;
		}
	}

	path->mnt = mnt;
	path->dentry = dentry;
	err = follow_managed(path, nd->flags);
	if (unlikely(err < 0)) {
		path_put_conditional(path, nd);
		return err;
	}
	if (err)
		nd->flags |= LOOKUP_JUMPED;

	*_inode = d_inode_or_lower(path->dentry);
	return 0;

need_lookup:
	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: need_lookup\n");
	return 1;
}

/* Fast lookup failed, do it the slow way */
static noinline int lookup_slow(struct nameidata *nd, struct path *path)
{
	struct dentry *dentry, *parent;
	int err;

	parent = nd->path.dentry;
	BUG_ON(nd->inode != parent->d_inode);

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: --> lookup_slow(%*.*s)\n",
		       nd->last.len, nd->last.len, nd->last.name);

	mutex_lock(&parent->d_inode->i_mutex);
	dentry = __lookup_hash(&nd->last, parent, nd->flags);
	mutex_unlock(&parent->d_inode->i_mutex);

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: slow: __lookup_hash() = %p\n", dentry);

	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	path->mnt = nd->path.mnt;
	path->dentry = dentry;
	err = follow_managed(path, nd->flags);
	if (unlikely(err < 0)) {
		path_put_conditional(path, nd);
		return err;
	}
	if (err)
		nd->flags |= LOOKUP_JUMPED;
	return 0;
}

static noinline int may_lookup(struct nameidata *nd)
{
	if (nd->flags & LOOKUP_RCU) {
		int err = inode_permission(nd->inode, MAY_EXEC|MAY_NOT_BLOCK);
		if (err != -ECHILD)
			return err;
		if (unlazy_walk(nd, NULL))
			return -ECHILD;
	}
	return inode_permission(nd->inode, MAY_EXEC);
}

static inline int handle_dots(struct nameidata *nd, int type)
{
	if (type == LAST_DOTDOT) {
		if (nd->flags & LOOKUP_RCU) {
			if (follow_dotdot_rcu(nd))
				return -ECHILD;
		} else
			follow_dotdot(nd);
	}
	return 0;
}

static void terminate_walk(struct nameidata *nd)
{
	if (!(nd->flags & LOOKUP_RCU)) {
		path_put(&nd->path);
	} else {
		nd->flags &= ~LOOKUP_RCU;
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;
		rcu_read_unlock();
	}
}

/*
 * Do we need to follow links? We _really_ want to be able
 * to do this check without having to look at inode->i_op,
 * so we keep a cache of "no, this doesn't need follow_link"
 * for the common case.
 */
static inline int should_follow_link(struct dentry *dentry, int follow)
{
	return unlikely(d_is_symlink(dentry)) ? follow : 0;
}

static noinline int walk_component(struct nameidata *nd, struct path *path,
		int follow)
{
	struct inode *inode;
	int err;

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: --> walk_component(%*.*s)\n",
		       nd->last.len, nd->last.len, nd->last.name);

	/*
	 * "." and ".." are special - ".." especially so because it has
	 * to be able to know about the current root directory and
	 * parent relationships.
	 */
	if (unlikely(nd->last_type != LAST_NORM))
		return handle_dots(nd, nd->last_type);
	err = lookup_fast(nd, path, &inode);
	if (unlikely(err)) {
		if (err < 0)
			goto out_err;

		err = lookup_slow(nd, path);
		if (err < 0)
			goto out_err;

		inode = d_inode_or_lower(path->dentry);
	}

	if (IS_PATH_UNIONED(path)) {
		printk("UNION: walk_comp: path->mnt UPPER%s\n",
		       nd->flags & LOOKUP_RCU ? " RCU" : "");
		printk("UNION: dentry %pd: %p(%p)\n",
		       path->dentry, path->dentry, path->dentry->d_inode);
	}

	if (!inode) {
		if (likely(!IS_MNT_UNION(path->mnt)))
			goto enoent;

		err = union_lookup_point(nd, path, false);
		if (err < 0)
			goto out_path_put;
		if (should_follow_link(path->dentry, follow))
			return 1;
		inode = path->dentry->d_inode;
		if (!inode && nd->flags & LOOKUP_PARENT)
			goto enoent;
		goto success;
	}

	if (should_follow_link(path->dentry, follow)) {
		if (nd->flags & LOOKUP_RCU) {
			if (unlikely(unlazy_walk(nd, path->dentry))) {
				err = -ECHILD;
				goto out_err;
			}
		}
		return 1;
	}
success:
	path_to_nameidata(path, nd);
	nd->inode = inode;
	return 0;

enoent:
	err = -ENOENT;
out_path_put:
	path_to_nameidata(path, nd);
out_err:
	terminate_walk(nd);
	return err;
}

/*
 * This limits recursive symlink follows to 8, while
 * limiting consecutive symlinks to 40.
 *
 * Without that kind of total limit, nasty chains of consecutive
 * symlinks can cause almost arbitrarily long lookups.
 */
static inline int nested_symlink(struct path *path, struct nameidata *nd)
{
	int res;

	if (unlikely(current->link_count >= MAX_NESTED_LINKS)) {
		path_put_conditional(path, nd);
		path_put(&nd->path);
		return -ELOOP;
	}
	BUG_ON(nd->depth >= MAX_NESTED_LINKS);

	nd->depth++;
	current->link_count++;

	do {
		struct path link = *path;
		void *cookie;

		res = follow_link(&link, nd, &cookie);
		if (res)
			break;
		res = walk_component(nd, path, LOOKUP_FOLLOW);
		put_link(nd, &link, cookie);
	} while (res > 0);

	current->link_count--;
	nd->depth--;
	return res;
}

/*
 * We can do the critical dentry name comparison and hashing
 * operations one word at a time, but we are limited to:
 *
 * - Architectures with fast unaligned word accesses. We could
 *   do a "get_unaligned()" if this helps and is sufficiently
 *   fast.
 *
 * - non-CONFIG_DEBUG_PAGEALLOC configurations (so that we
 *   do not trap on the (extremely unlikely) case of a page
 *   crossing operation.
 *
 * - Furthermore, we need an efficient 64-bit compile for the
 *   64-bit case in order to generate the "number of bytes in
 *   the final mask". Again, that could be replaced with a
 *   efficient population count instruction or similar.
 */
#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>

#ifdef CONFIG_64BIT

static inline unsigned int fold_hash(unsigned long hash)
{
	hash += hash >> (8*sizeof(int));
	return hash;
}

#else	/* 32-bit case */

#define fold_hash(x) (x)

#endif

unsigned int full_name_hash(const unsigned char *name, unsigned int len)
{
	unsigned long a, mask;
	unsigned long hash = 0;

	for (;;) {
		a = load_unaligned_zeropad(name);
		if (len < sizeof(unsigned long))
			break;
		hash += a;
		hash *= 9;
		name += sizeof(unsigned long);
		len -= sizeof(unsigned long);
		if (!len)
			goto done;
	}
	mask = bytemask_from_count(len);
	hash += mask & a;
done:
	return fold_hash(hash);
}
EXPORT_SYMBOL(full_name_hash);

/*
 * Calculate the length and hash of the path component, and
 * return the length of the component;
 */
static inline unsigned long hash_name(const char *name, unsigned int *hashp)
{
	unsigned long a, b, adata, bdata, mask, hash, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	hash = a = 0;
	len = -sizeof(unsigned long);
	do {
		hash = (hash + a) * 9;
		len += sizeof(unsigned long);
		a = load_unaligned_zeropad(name+len);
		b = a ^ REPEAT_BYTE('/');
	} while (!(has_zero(a, &adata, &constants) | has_zero(b, &bdata, &constants)));

	adata = prep_zero_mask(a, adata, &constants);
	bdata = prep_zero_mask(b, bdata, &constants);

	mask = create_zero_mask(adata | bdata);

	hash += a & zero_bytemask(mask);
	*hashp = fold_hash(hash);

	return len + find_zero(mask);
}

#else

unsigned int full_name_hash(const unsigned char *name, unsigned int len)
{
	unsigned long hash = init_name_hash();
	while (len--)
		hash = partial_name_hash(*name++, hash);
	return end_name_hash(hash);
}
EXPORT_SYMBOL(full_name_hash);

/*
 * We know there's a real path component here of at least
 * one character.
 */
static inline unsigned long hash_name(const char *name, unsigned int *hashp)
{
	unsigned long hash = init_name_hash();
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	} while (c && c != '/');
	*hashp = end_name_hash(hash);
	return len;
}

#endif

/*
 * Name resolution.
 * This is the basic name resolution function, turning a pathname into
 * the final dentry. We expect 'base' to be positive and a directory.
 *
 * Returns 0 and nd will have valid dentry and mnt on success.
 * Returns error and drops reference to input namei data on failure.
 */
static int link_path_walk(const char *name, struct nameidata *nd)
{
	struct path next;
	int err;
	
	while (*name=='/')
		name++;
	if (!*name)
		return 0;

	/* At this point we know we have a real path component. */
	for(;;) {
		struct qstr this;
		long len;
		int type;

		err = may_lookup(nd);
 		if (err)
			break;

		len = hash_name(name, &this.hash);
		this.name = name;
		this.len = len;

		type = LAST_NORM;
		if (name[0] == '.') switch (len) {
			case 2:
				if (name[1] == '.') {
					type = LAST_DOTDOT;
					nd->flags |= LOOKUP_JUMPED;
				}
				break;
			case 1:
				type = LAST_DOT;
		}
		if (likely(type == LAST_NORM)) {
			struct dentry *parent = nd->path.dentry;
			nd->flags &= ~LOOKUP_JUMPED;
			if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
				err = parent->d_op->d_hash(parent, &this);
				if (err < 0)
					break;
			}
		}

		nd->last = this;
		nd->last_type = type;

		if (!name[len])
			return 0;
		/*
		 * If it wasn't NUL, we know it was '/'. Skip that
		 * slash, and continue until no more slashes.
		 */
		do {
			len++;
		} while (unlikely(name[len] == '/'));
		if (!name[len])
			return 0;

		name += len;

		err = walk_component(nd, &next, LOOKUP_FOLLOW);
		if (err < 0)
			return err;

		if (err) {
			err = nested_symlink(&next, nd);
			if (err)
				return err;
		}
		if (!d_is_directory(nd->path.dentry)) {
			err = -ENOTDIR; 
			break;
		}
	}
	terminate_walk(nd);
	return err;
}

static int path_init(int dfd, const char *name, unsigned int flags,
		     struct nameidata *nd, struct file **fp)
{
	int retval = 0;

	nd->last_type = LAST_ROOT; /* if there are only slashes... */
	nd->flags = flags | LOOKUP_JUMPED;
	nd->depth = 0;
	if (flags & LOOKUP_ROOT) {
		struct dentry *root = nd->root.dentry;
		struct inode *inode = root->d_inode;
		if (*name) {
			if (!d_is_directory(root))
				return -ENOTDIR;
			retval = inode_permission(inode, MAY_EXEC);
			if (retval)
				return retval;
		}
		nd->path = nd->root;
		nd->inode = inode;
		if (flags & LOOKUP_RCU) {
			rcu_read_lock();
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			nd->m_seq = read_seqbegin(&mount_lock);
		} else {
			path_get(&nd->path);
		}
		return 0;
	}

	nd->root.mnt = NULL;

	nd->m_seq = read_seqbegin(&mount_lock);
	if (*name=='/') {
		if (flags & LOOKUP_RCU) {
			rcu_read_lock();
			set_root_rcu(nd);
		} else {
			set_root(nd);
			path_get(&nd->root);
		}
		nd->path = nd->root;
	} else if (dfd == AT_FDCWD) {
		if (flags & LOOKUP_RCU) {
			struct fs_struct *fs = current->fs;
			unsigned seq;

			rcu_read_lock();

			do {
				seq = read_seqcount_begin(&fs->seq);
				nd->path = fs->pwd;
				nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			} while (read_seqcount_retry(&fs->seq, seq));
		} else {
			get_fs_pwd(current->fs, &nd->path);
		}
	} else {
		/* Caller must check execute permissions on the starting path component */
		struct fd f = fdget_raw(dfd);
		struct dentry *dentry;

		if (!f.file)
			return -EBADF;

		dentry = f.file->f_path.dentry;

		if (*name) {
			if (!d_is_directory(dentry)) {
				fdput(f);
				return -ENOTDIR;
			}
		}

		nd->path = f.file->f_path;
		if (flags & LOOKUP_RCU) {
			if (f.need_put)
				*fp = f.file;
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			rcu_read_lock();
		} else {
			path_get(&nd->path);
			fdput(f);
		}
	}

	nd->inode = nd->path.dentry->d_inode;
	return 0;
}

static inline int lookup_last(struct nameidata *nd, struct path *path)
{
	if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len])
		nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

	nd->flags &= ~LOOKUP_PARENT;
	return walk_component(nd, path, nd->flags & LOOKUP_FOLLOW);
}

/* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
static int path_lookupat(int dfd, const char *name,
				unsigned int flags, struct nameidata *nd)
{
	struct file *base = NULL;
	struct path terminal_symlink;
	int err;

	/*
	 * Path walking is largely split up into 2 different synchronisation
	 * schemes, rcu-walk and ref-walk (explained in
	 * Documentation/filesystems/path-lookup.txt). These share much of the
	 * path walk code, but some things particularly setup, cleanup, and
	 * following mounts are sufficiently divergent that functions are
	 * duplicated. Typically there is a function foo(), and its RCU
	 * analogue, foo_rcu().
	 *
	 * -ECHILD is the error number of choice (just to avoid clashes) that
	 * is returned if some aspect of an rcu-walk fails. Such an error must
	 * be handled by restarting a traditional ref-walk (which will always
	 * be able to complete).
	 */
	err = path_init(dfd, name, flags | LOOKUP_PARENT, nd, &base);

	if (unlikely(err))
		return err;

	current->total_link_count = 0;
	err = link_path_walk(name, nd);
	if (!err && IS_PATH_UNIONED(&nd->path))
		printk("UNION: link_path_walk returned nd->path.mnt UPPER%s\n>>>\n",
		       flags & LOOKUP_PARENT ? " PARENT" : "");

	/* At this point we've processed all the non-terminal parts of the path
	 * and are ready to tackle the final section.  The final section may
	 * still include terminal symlinks, however, so we need to iterate
	 * through those.
	 */
	if (!err && !(flags & LOOKUP_PARENT)) {
		err = lookup_last(nd, &terminal_symlink);
		while (err > 0) {
			void *cookie;
			struct path link = terminal_symlink;
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: path_lookupat: may_follow_link\n");
			err = may_follow_link(&link, nd);
			if (unlikely(err))
				break;
			nd->flags |= LOOKUP_PARENT;
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: path_lookupat: follow_link\n");
			err = follow_link(&link, nd, &cookie);
			if (err)
				break;
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: path_lookupat: lookup_last\n");
			err = lookup_last(nd, &terminal_symlink);
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: path_lookupat: put_link\n");
			put_link(nd, &link, cookie);
		}

		if (!err) {
			if (!nd)
				printk("UNION: path_lookupat: !nd\n");
			else if (!nd->path.mnt)
				printk("UNION: path_lookupat: !nd->path.mnt\n");
			else if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: path_lookupat: nd->path.mnt UPPER\n");
		}
	}

	if (!err)
		err = complete_walk(nd);

	if (!err && nd->flags & LOOKUP_DIRECTORY) {
		if (!d_is_directory(nd->path.dentry)) {
			path_put(&nd->path);
			err = -ENOTDIR;
		}
	}

	if (base)
		fput(base);

	if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT)) {
		path_put(&nd->root);
		nd->root.mnt = NULL;
	}
	return err;
}

static int filename_lookup(int dfd, struct filename *name,
				unsigned int flags, struct nameidata *nd)
{
	int retval = path_lookupat(dfd, name->name, flags | LOOKUP_RCU, nd);
	if (unlikely(retval == -ECHILD))
		retval = path_lookupat(dfd, name->name, flags, nd);
	if (unlikely(retval == -ESTALE))
		retval = path_lookupat(dfd, name->name,
						flags | LOOKUP_REVAL, nd);

	if (likely(!retval))
		audit_inode(name, nd->path.dentry, flags & LOOKUP_PARENT);
	return retval;
}

static int do_path_lookup(int dfd, const char *name,
				unsigned int flags, struct nameidata *nd)
{
	struct filename filename = { .name = name };

	return filename_lookup(dfd, &filename, flags, nd);
}

/* does lookup, returns the object with parent locked */
struct dentry *kern_path_locked(const char *name, struct path *path)
{
	struct nameidata nd;
	struct dentry *d;
	int err = do_path_lookup(AT_FDCWD, name, LOOKUP_PARENT, &nd);
	if (err)
		return ERR_PTR(err);
	if (nd.last_type != LAST_NORM) {
		path_put(&nd.path);
		return ERR_PTR(-EINVAL);
	}
	mutex_lock_nested(&nd.path.dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	d = __lookup_hash(&nd.last, nd.path.dentry, 0);
	if (IS_ERR(d)) {
		mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
		path_put(&nd.path);
		return d;
	}
	*path = nd.path;
	return d;
}

int kern_path(const char *name, unsigned int flags, struct path *path)
{
	struct nameidata nd;
	int res = do_path_lookup(AT_FDCWD, name, flags, &nd);
	if (!res)
		*path = nd.path;
	return res;
}

/**
 * vfs_path_lookup - lookup a file path relative to a dentry-vfsmount pair
 * @dentry:  pointer to dentry of the base directory
 * @mnt: pointer to vfs mount of the base directory
 * @name: pointer to file name
 * @flags: lookup flags
 * @path: pointer to struct path to fill
 */
int vfs_path_lookup(struct dentry *dentry, struct vfsmount *mnt,
		    const char *name, unsigned int flags,
		    struct path *path)
{
	struct nameidata nd;
	int err;
	nd.root.dentry = dentry;
	nd.root.mnt = mnt;
	BUG_ON(flags & LOOKUP_PARENT);
	/* the first argument of do_path_lookup() is ignored with LOOKUP_ROOT */
	err = do_path_lookup(AT_FDCWD, name, flags | LOOKUP_ROOT, &nd);
	if (!err)
		*path = nd.path;
	return err;
}

/*
 * Restricted form of lookup. Doesn't follow links, single-component only,
 * needs parent already locked. Doesn't follow mounts.  Does annotate the
 * dentry for unionmount.  SMP-safe.
 */
static int lookup_hash(struct nameidata *nd, struct path *path)
{
	struct dentry *result;
	int ret;

	result = __lookup_hash(&nd->last, nd->path.dentry, nd->flags);
	if (IS_ERR(result)) {
		ret = PTR_ERR(result);
		goto error;
	}

	path->mnt = nd->path.mnt;
	path->dentry = result;
	ret = union_lookup_point_locked(&nd->path, path);
	if (ret)
		goto error_dput;
	return 0;

error_dput:
	dput(path->dentry);
error:
	path->mnt = NULL;
	path->dentry = NULL;
	return ret;
}

/**
 * lookup_one_len - filesystem helper to lookup single pathname component
 * @name:	pathname component to lookup
 * @base:	base directory to lookup from
 * @len:	maximum length @len should be interpreted to
 *
 * Note that this routine is purely a helper for filesystem usage and should
 * not be called by generic code.  Also note that by using this function the
 * nameidata argument is passed to the filesystem methods and a filesystem
 * using this helper needs to be prepared for that.
 */
struct dentry *lookup_one_len(const char *name, struct dentry *base, int len)
{
	struct qstr this;
	unsigned int c;
	int err;

	WARN_ON_ONCE(!mutex_is_locked(&base->d_inode->i_mutex));

	this.name = name;
	this.len = len;
	this.hash = full_name_hash(name, len);
	if (!len)
		return ERR_PTR(-EACCES);

	if (unlikely(name[0] == '.')) {
		if (len < 2 || (len == 2 && name[1] == '.'))
			return ERR_PTR(-EACCES);
	}

	while (len--) {
		c = *(const unsigned char *)name++;
		if (c == '/' || c == '\0')
			return ERR_PTR(-EACCES);
	}
	/*
	 * See if the low-level filesystem might want
	 * to use its own hash..
	 */
	if (base->d_flags & DCACHE_OP_HASH) {
		int err = base->d_op->d_hash(base, &this);
		if (err < 0)
			return ERR_PTR(err);
	}

	err = inode_permission(base->d_inode, MAY_EXEC);
	if (err)
		return ERR_PTR(err);

	return __lookup_hash(&this, base, 0);
}

int user_path_at_empty(int dfd, const char __user *name, unsigned flags,
		 struct path *path, int *empty)
{
	struct nameidata nd;
	struct filename *tmp = getname_flags(name, flags, empty);
	int err = PTR_ERR(tmp);
	if (!IS_ERR(tmp)) {

		BUG_ON(flags & LOOKUP_PARENT);

		err = filename_lookup(dfd, tmp, flags, &nd);
		putname(tmp);
		if (!err)
			*path = nd.path;
	}
	return err;
}

int user_path_at(int dfd, const char __user *name, unsigned flags,
		 struct path *path)
{
	return user_path_at_empty(dfd, name, flags, path, NULL);
}

/*
 * NB: most callers don't do anything directly with the reference to the
 *     to struct filename, but the nd->last pointer points into the name string
 *     allocated by getname. So we must hold the reference to it until all
 *     path-walking is complete.
 */
static struct filename *
user_path_parent(int dfd, const char __user *path, struct nameidata *nd,
		 unsigned int flags)
{
	struct filename *s = getname(path);
	int error;

	/* only LOOKUP_REVAL is allowed in extra flags */
	flags &= LOOKUP_REVAL;

	if (IS_ERR(s))
		return s;

	error = filename_lookup(dfd, s, flags | LOOKUP_PARENT, nd);
	if (error) {
		putname(s);
		return ERR_PTR(error);
	}

	return s;
}

/**
 * mountpoint_last - look up last component for umount
 * @nd:   pathwalk nameidata - currently pointing at parent directory of "last"
 * @path: pointer to container for result
 *
 * This is a special lookup_last function just for umount. In this case, we
 * need to resolve the path without doing any revalidation.
 *
 * The nameidata should be the result of doing a LOOKUP_PARENT pathwalk. Since
 * mountpoints are always pinned in the dcache, their ancestors are too. Thus,
 * in almost all cases, this lookup will be served out of the dcache. The only
 * cases where it won't are if nd->last refers to a symlink or the path is
 * bogus and it doesn't exist.
 *
 * Returns:
 * -error: if there was an error during lookup. This includes -ENOENT if the
 *         lookup found a negative dentry. The nd->path reference will also be
 *         put in this case.
 *
 * 0:      if we successfully resolved nd->path and found it to not to be a
 *         symlink that needs to be followed. "path" will also be populated.
 *         The nd->path reference will also be put.
 *
 * 1:      if we successfully resolved nd->last and found it to be a symlink
 *         that needs to be followed. "path" will be populated with the path
 *         to the link, and nd->path will *not* be put.
 */
static int
mountpoint_last(struct nameidata *nd, struct path *path)
{
	int error = 0;
	struct dentry *dentry;
	struct dentry *dir = nd->path.dentry;

	/* If we're in rcuwalk, drop out of it to handle last component */
	if (nd->flags & LOOKUP_RCU) {
		if (unlazy_walk(nd, NULL)) {
			error = -ECHILD;
			goto out;
		}
	}

	nd->flags &= ~LOOKUP_PARENT;

	if (unlikely(nd->last_type != LAST_NORM)) {
		error = handle_dots(nd, nd->last_type);
		if (error)
			goto out;
		dentry = dget(nd->path.dentry);
		goto done;
	}

	mutex_lock(&dir->d_inode->i_mutex);
	dentry = d_lookup(dir, &nd->last);
	if (!dentry) {
		/*
		 * No cached dentry. Mounted dentries are pinned in the cache,
		 * so that means that this dentry is probably a symlink or the
		 * path doesn't actually point to a mounted dentry.
		 */
		dentry = d_alloc(dir, &nd->last);
		if (!dentry) {
			error = -ENOMEM;
			mutex_unlock(&dir->d_inode->i_mutex);
			goto out;
		}
		dentry = lookup_real(dir->d_inode, dentry, nd->flags);
		error = PTR_ERR(dentry);
		if (IS_ERR(dentry)) {
			mutex_unlock(&dir->d_inode->i_mutex);
			goto out;
		}
	}
	mutex_unlock(&dir->d_inode->i_mutex);

done:
	if (!dentry->d_inode) {
		error = -ENOENT;
		dput(dentry);
		goto out;
	}
	path->dentry = dentry;
	path->mnt = mntget(nd->path.mnt);
	if (should_follow_link(dentry, nd->flags & LOOKUP_FOLLOW))
		return 1;
	follow_mount(path);
	error = 0;
out:
	terminate_walk(nd);
	return error;
}

/**
 * path_mountpoint - look up a path to be umounted
 * @dfd:	directory file descriptor to start walk from
 * @name:	full pathname to walk
 * @path:	pointer to container for result
 * @flags:	lookup flags
 *
 * Look up the given name, but don't attempt to revalidate the last component.
 * Returns 0 and "path" will be valid on success; Returns error otherwise.
 */
static int
path_mountpoint(int dfd, const char *name, struct path *path, unsigned int flags)
{
	struct file *base = NULL;
	struct nameidata nd;
	int err;

	err = path_init(dfd, name, flags | LOOKUP_PARENT, &nd, &base);
	if (unlikely(err))
		return err;

	current->total_link_count = 0;
	err = link_path_walk(name, &nd);
	if (err)
		goto out;

	err = mountpoint_last(&nd, path);
	while (err > 0) {
		void *cookie;
		struct path link = *path;
		err = may_follow_link(&link, &nd);
		if (unlikely(err))
			break;
		nd.flags |= LOOKUP_PARENT;
		err = follow_link(&link, &nd, &cookie);
		if (err)
			break;
		err = mountpoint_last(&nd, path);
		put_link(&nd, &link, cookie);
	}
out:
	if (base)
		fput(base);

	if (nd.root.mnt && !(nd.flags & LOOKUP_ROOT))
		path_put(&nd.root);

	return err;
}

static int
filename_mountpoint(int dfd, struct filename *s, struct path *path,
			unsigned int flags)
{
	int error = path_mountpoint(dfd, s->name, path, flags | LOOKUP_RCU);
	if (unlikely(error == -ECHILD))
		error = path_mountpoint(dfd, s->name, path, flags);
	if (unlikely(error == -ESTALE))
		error = path_mountpoint(dfd, s->name, path, flags | LOOKUP_REVAL);
	if (likely(!error))
		audit_inode(s, path->dentry, 0);
	return error;
}

/**
 * user_path_mountpoint_at - lookup a path from userland in order to umount it
 * @dfd:	directory file descriptor
 * @name:	pathname from userland
 * @flags:	lookup flags
 * @path:	pointer to container to hold result
 *
 * A umount is a special case for path walking. We're not actually interested
 * in the inode in this situation, and ESTALE errors can be a problem. We
 * simply want track down the dentry and vfsmount attached at the mountpoint
 * and avoid revalidating the last component.
 *
 * Returns 0 and populates "path" on success.
 */
int
user_path_mountpoint_at(int dfd, const char __user *name, unsigned int flags,
			struct path *path)
{
	struct filename *s = getname(name);
	int error;
	if (IS_ERR(s))
		return PTR_ERR(s);
	error = filename_mountpoint(dfd, s, path, flags);
	putname(s);
	return error;
}

int
kern_path_mountpoint(int dfd, const char *name, struct path *path,
			unsigned int flags)
{
	struct filename s = {.name = name};
	return filename_mountpoint(dfd, &s, path, flags);
}
EXPORT_SYMBOL(kern_path_mountpoint);

/*
 * It's inline, so penalty for filesystems that don't use sticky bit is
 * minimal.
 */
static inline int check_sticky(struct inode *dir, struct inode *inode)
{
	kuid_t fsuid = current_fsuid();

	if (!(dir->i_mode & S_ISVTX))
		return 0;
	if (uid_eq(inode->i_uid, fsuid))
		return 0;
	if (uid_eq(dir->i_uid, fsuid))
		return 0;
	return !inode_capable(inode, CAP_FOWNER);
}

/*
 *	Check whether we can remove a link victim from directory dir, check
 *  whether the type of victim is right.
 *  1. We can't do it if dir is read-only (done in permission())
 *  2. We should have write and exec permissions on dir
 *  3. We can't remove anything from append-only dir
 *  4. We can't do anything with immutable dir (done in permission())
 *  5. If the sticky bit on dir is set we should either
 *	a. be owner of dir, or
 *	b. be owner of victim, or
 *	c. have CAP_FOWNER capability
 *  6. If the victim is append-only or immutable we can't do antyhing with
 *     links pointing to it.
 *  7. If we were asked to remove a directory and victim isn't one - ENOTDIR.
 *  8. If we were asked to remove a non-directory and victim isn't one - EISDIR.
 *  9. We can't remove a root or mountpoint.
 * 10. We don't allow removal of NFS sillyrenamed files; it's handled by
 *     nfs_async_unlink().
 */
static int may_delete(struct inode *dir, struct dentry *victim, bool isdir)
{
	struct inode *inode = d_inode_or_lower(victim);
	int error;

	if (d_is_negative(victim))
		return -ENOENT;
	if (!inode) {
		pr_err("### DENTRY %pd {%x}\n", victim, victim->d_flags);
		BUG();
	}

	audit_inode_child(dir, victim, AUDIT_TYPE_CHILD_DELETE);

	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;

	if (check_sticky(dir, inode) || IS_APPEND(inode) ||
	    IS_IMMUTABLE(inode) || IS_SWAPFILE(inode))
		return -EPERM;
	if (isdir) {
		if (!d_is_directory(victim) && !d_is_autodir(victim))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (d_is_directory(victim) || d_is_autodir(victim))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

/*	Check whether we can create an object with dentry child in directory
 *  dir.
 *  1. We can't do it if child already exists (open has special treatment for
 *     this case, but since we are inlined it's OK)
 *  2. We can't do it if dir is read-only (done in permission())
 *  3. We should have write and exec permissions on dir
 *  4. We can't do it if dir is immutable (done in permission())
 */
static inline int may_create(struct inode *dir, struct dentry *child)
{
	audit_inode_child(dir, child, AUDIT_TYPE_CHILD_CREATE);
	if (child->d_inode)
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}

/*
 * p1 and p2 should be directories on the same fs.
 */
struct dentry *lock_rename(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	if (p1 == p2) {
		mutex_lock_nested(&p1->d_inode->i_mutex, I_MUTEX_PARENT);
		return NULL;
	}

	mutex_lock(&p1->d_inode->i_sb->s_vfs_rename_mutex);

	p = d_ancestor(p2, p1);
	if (p) {
		mutex_lock_nested(&p2->d_inode->i_mutex, I_MUTEX_PARENT);
		mutex_lock_nested(&p1->d_inode->i_mutex, I_MUTEX_CHILD);
		return p;
	}

	p = d_ancestor(p1, p2);
	if (p) {
		mutex_lock_nested(&p1->d_inode->i_mutex, I_MUTEX_PARENT);
		mutex_lock_nested(&p2->d_inode->i_mutex, I_MUTEX_CHILD);
		return p;
	}

	mutex_lock_nested(&p1->d_inode->i_mutex, I_MUTEX_PARENT);
	mutex_lock_nested(&p2->d_inode->i_mutex, I_MUTEX_CHILD);
	return NULL;
}

void unlock_rename(struct dentry *p1, struct dentry *p2)
{
	mutex_unlock(&p1->d_inode->i_mutex);
	if (p1 != p2) {
		mutex_unlock(&p2->d_inode->i_mutex);
		mutex_unlock(&p1->d_inode->i_sb->s_vfs_rename_mutex);
	}
}

int vfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool want_excl)
{
	int error = may_create(dir, dentry);
	if (error)
		return error;

	if (!dir->i_op->create)
		return -EACCES;	/* shouldn't it be ENOSYS? */
	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;
	error = dir->i_op->create(dir, dentry, mode, want_excl);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}

static int may_open(struct path *path, struct inode *inode, int acc_mode, int flag)
{
	int error;

	/* O_PATH? */
	if (!acc_mode)
		return 0;

	if (!inode)
		return -ENOENT;

	switch (inode->i_mode & S_IFMT) {
	case S_IFLNK:
		return -ELOOP;
	case S_IFDIR:
		if (acc_mode & MAY_WRITE)
			return -EISDIR;
		break;
	case S_IFBLK:
	case S_IFCHR:
		if (path->mnt->mnt_flags & MNT_NODEV)
			return -EACCES;
		/* fallthrough */
	case S_IFIFO:
	case S_IFSOCK:
		flag &= ~O_TRUNC;
		break;
	}

	error = inode_permission(inode, acc_mode);
	if (error)
		return error;

	/*
	 * An append-only file must be opened in append mode for writing.
	 */
	if (IS_APPEND(inode)) {
		if  ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND))
			return -EPERM;
		if (flag & O_TRUNC)
			return -EPERM;
	}

	/* O_NOATIME can only be set by the owner or superuser */
	if (flag & O_NOATIME && !inode_owner_or_capable(inode))
		return -EPERM;

	return 0;
}

static int handle_truncate(struct file *filp)
{
	struct path *path = &filp->f_path;
	struct inode *inode = path->dentry->d_inode;
	int error = get_write_access(inode);
	if (error)
		return error;
	/*
	 * Refuse to truncate files with mandatory locks held on them.
	 */
	error = locks_verify_locked(inode);
	if (!error)
		error = security_path_truncate(path);
	if (!error) {
		error = do_truncate(path->dentry, 0,
				    ATTR_MTIME|ATTR_CTIME|ATTR_OPEN,
				    filp);
	}
	put_write_access(inode);
	return error;
}

static inline int open_to_namei_flags(int flag)
{
	if ((flag & O_ACCMODE) == 3)
		flag--;
	return flag;
}

static int may_o_create(struct path *dir, struct dentry *dentry, umode_t mode)
{
	int error = security_path_mknod(dir, dentry, mode, 0);
	if (error)
		return error;

	error = inode_permission(dir->dentry->d_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	return security_inode_create(dir->dentry->d_inode, dentry, mode);
}

/*
 * Attempt to atomically look up, create and open a file from a negative
 * dentry.
 *
 * Returns 0 if successful.  The file will have been created and attached to
 * @file by the filesystem calling finish_open().
 *
 * Returns 1 if the file was looked up only or didn't need creating.  The
 * caller will need to perform the open themselves.  @path will have been
 * updated to point to the new dentry.  This may be negative.
 *
 * Returns an error code otherwise.
 */
static int atomic_open(struct nameidata *nd, struct dentry *dentry,
			struct path *path, struct file *file,
			const struct open_flags *op,
			bool got_write, bool need_lookup,
			int *opened)
{
	struct inode *dir =  nd->path.dentry->d_inode;
	unsigned open_flag = open_to_namei_flags(op->open_flag);
	umode_t mode;
	int error;
	int acc_mode;
	int create_error = 0;
	struct dentry *const DENTRY_NOT_SET = (void *) -1UL;
	bool excl;

	BUG_ON(dentry->d_inode);

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: --> atomic_open(%*.*s)\n",
		       nd->last.len, nd->last.len, nd->last.name);

	/* Don't create child dentry for a dead directory. */
	if (unlikely(IS_DEADDIR(dir))) {
		error = -ENOENT;
		goto out;
	}

	mode = op->mode;
	if ((open_flag & O_CREAT) && !IS_POSIXACL(dir))
		mode &= ~current_umask();

	excl = (open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT);
	if (excl)
		open_flag &= ~O_TRUNC;

	/*
	 * Checking write permission is tricky, bacuse we don't know if we are
	 * going to actually need it: O_CREAT opens should work as long as the
	 * file exists.  But checking existence breaks atomicity.  The trick is
	 * to check access and if not granted clear O_CREAT from the flags.
	 *
	 * Another problem is returing the "right" error value (e.g. for an
	 * O_EXCL open we want to return EEXIST not EROFS).
	 */
	if (((open_flag & (O_CREAT | O_TRUNC)) ||
	    (open_flag & O_ACCMODE) != O_RDONLY) && unlikely(!got_write)) {
		if (!(open_flag & O_CREAT)) {
			/*
			 * No O_CREATE -> atomicity not a requirement -> fall
			 * back to lookup + open
			 */
			goto no_open;
		} else if (open_flag & (O_EXCL | O_TRUNC)) {
			/* Fall back and fail with the right error */
			create_error = -EROFS;
			goto no_open;
		} else {
			/* No side effects, safe to clear O_CREAT */
			create_error = -EROFS;
			open_flag &= ~O_CREAT;
		}
	}

	if (open_flag & O_CREAT) {
		error = may_o_create(&nd->path, dentry, mode);
		if (error) {
			create_error = error;
			if (open_flag & O_EXCL)
				goto no_open;
			open_flag &= ~O_CREAT;
		}
	}

	if (nd->flags & LOOKUP_DIRECTORY)
		open_flag |= O_DIRECTORY;

	file->f_path.dentry = DENTRY_NOT_SET;
	file->f_path.mnt = nd->path.mnt;
	error = dir->i_op->atomic_open(dir, dentry, file, open_flag, mode,
				      opened);
	if (error < 0) {
		if (create_error && error == -ENOENT)
			error = create_error;
		goto out;
	}

	if (error) {	/* returned 1, that is */
		if (WARN_ON(file->f_path.dentry == DENTRY_NOT_SET)) {
			error = -EIO;
			goto out;
		}
		if (file->f_path.dentry) {
			dput(dentry);
			dentry = file->f_path.dentry;
		}
		if (*opened & FILE_CREATED)
			fsnotify_create(dir, dentry);
		if (!dentry->d_inode) {
			WARN_ON(*opened & FILE_CREATED);
			if (create_error) {
				error = create_error;
				goto out;
			}
		} else {
			if (excl && !(*opened & FILE_CREATED)) {
				error = -EEXIST;
				goto out;
			}
		}
		goto looked_up;
	}

	/*
	 * We didn't have the inode before the open, so check open permission
	 * here.
	 */
	acc_mode = op->acc_mode;
	if (*opened & FILE_CREATED) {
		WARN_ON(!(open_flag & O_CREAT));
		fsnotify_create(dir, dentry);
		acc_mode = MAY_OPEN;
	}
	error = may_open(&file->f_path, file->f_inode, acc_mode, open_flag);
	if (error)
		fput(file);

out:
	dput(dentry);
	return error;

no_open:
	if (need_lookup) {
		dentry = lookup_real(dir, dentry, nd->flags);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);

		if (create_error) {
			int open_flag = op->open_flag;

			error = create_error;
			if ((open_flag & O_EXCL)) {
				if (!dentry->d_inode)
					goto out;
			} else if (!dentry->d_inode) {
				goto out;
			} else if ((open_flag & O_TRUNC) &&
				   S_ISREG(dentry->d_inode->i_mode)) {
				goto out;
			}
			/* will fail later, go on to get the right error */
		}
	}
looked_up:
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	return 1;
}

/*
 * Look up and maybe create and open the last component.
 *
 * Must be called with i_mutex held on parent.
 *
 * Returns 0 if the file was successfully atomically created (if necessary) and
 * opened.  In this case the file will be returned attached to @file.
 *
 * Returns 1 if the file was not completely opened at this time, though lookups
 * and creations will have been performed and the dentry returned in @path will
 * be positive upon return if O_CREAT was specified.  If O_CREAT wasn't
 * specified then a negative dentry may be returned.
 *
 * An error code is returned otherwise.
 *
 * FILE_CREATE will be set in @*opened if the dentry was created and will be
 * cleared otherwise prior to returning.
 *
 * If an entry on a union mount is being considered, we pass back a file from
 * the lower layer if there is one and leave it up to do_last() to copy up if
 * need be.
 */
static int lookup_open(struct nameidata *nd, struct path *path,
			struct file *file,
			const struct open_flags *op,
			bool got_write, int *opened)
{
	struct dentry *dir = nd->path.dentry;
	struct inode *dir_inode = dir->d_inode;
	struct dentry *dentry;
	int error;
	bool need_lookup;

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: --> lookup_open(%*.*s)\n",
		       nd->last.len, nd->last.len, nd->last.name);

	*opened &= ~FILE_CREATED;
	dentry = lookup_dcache(&nd->last, dir, nd->flags, &need_lookup);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: lookup_dcache() = %p [%p]\n",
		       dentry, dentry ? dentry->d_inode : NULL);

	/* Cached positive dentry: will open in f_op->open */
	if (!need_lookup && dentry->d_inode)
		goto out_no_open;

	/* Perform an atomic open if that is available - but not if a file on
	 * the upper filesystem of a union is being opened for writing
	 */
	if ((nd->flags & LOOKUP_OPEN) && dir_inode->i_op->atomic_open &&
	    !(IS_MNT_UNION(nd->path.mnt) &&
	      op->acc_mode & (MAY_WRITE | MAY_APPEND))) {
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: open atomic\n");
		return atomic_open(nd, dentry, path, file, op, got_write,
				   need_lookup, opened);
	}

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: don't open atomic\n");
	if (need_lookup) {
		BUG_ON(dentry->d_inode);

		dentry = lookup_real(dir_inode, dentry, nd->flags);
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: lookup_real() = %p\n", dentry);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
	}

	/* Negative dentry, just create the file */
	if (!dentry->d_inode && (op->open_flag & O_CREAT)) {
		umode_t mode = op->mode;
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~current_umask();

		/* This write is needed to ensure that a
		 * rw->ro transition does not occur between
		 * the time when the file is created and when
		 * a permanent write count is taken through
		 * the 'struct file' in finish_open().
		 */
		if (!got_write) {
			error = -EROFS;
			goto out_dput;
		}

		/* If the negative dentry is on the upper layer of a union
		 * mount then we may need to copy up or turn a whiteout into a
		 * file.  The negative dentry will not be on a lower layer at
		 * this point.
		 *
		 * If the dentry is a whiteout or a normal negative dentry in
		 * an opaque directory then we can just create over it.
		 *
		 * If O_CREAT|O_TRUNC|O_EXCL is specified then we fail if
		 * there's a file in the lower layer or succeed without copying
		 * up otherwise.
		 *
		 * If O_CREAT|O_TRUNC is specified then we need to copy up the
		 * attributes if there's a lower file.
		 *
		 * If O_CREAT|O_RDONLY is specified and the file exists in the
		 * lower layer, we just use the lower file.
		 *
		 * Otherwise we need to copy up the whole file.
		 */
		if (IS_PATH_UNIONED(&nd->path)) {
			struct path tmp = {
				.mnt = nd->path.mnt,
				.dentry = dentry,
			};

			printk("UNION: deal with O_CREAT\n");

			error = union_lookup_point_locked(&nd->path, &tmp);
			if (error == -ENOENT)
				goto just_create;
			if (error < 0)
				goto out_dput;
			if (d_is_directory(dentry)) {
				error = -EISDIR;
				if (op->open_flag & O_EXCL)
					error = -EEXIST;
				goto out_dput;
			}

			if (d_is_symlink(dentry))
				goto out_no_open;
			if (d_is_negative(dentry)) {
				printk("UNION: lower blocked\n");
				goto just_create; /* Lower is blocked off */
			}

			printk("UNION: deal with O_CREAT\n");
			if (d_is_pinning_lower(dentry)) {
				BUG_ON(!d_get_fallthru(dentry)->d_inode);
				printk("UNION: lower available (O_CREAT ignored)\n");
				goto out_no_open;
			}

			printk("UNION: create over lower\n");
		}

	just_create:
		*opened |= FILE_CREATED;
		error = security_path_mknod(&nd->path, dentry, mode, 0);
		if (error)
			goto out_dput;
		error = vfs_create(dir->d_inode, dentry, mode,
				   nd->flags & LOOKUP_EXCL);
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: vfs_create() = %d [%pd: %p]\n",
			       error, dentry, dentry);
		if (error)
			goto out_dput;
	}

out_no_open:
	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: out_no_open\n");
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	return 1;

out_dput:
	dput(dentry);
	return error;
}

/*
 * Handle the last step of open()
 */
static int do_last(struct nameidata *nd, struct path *path,
		   struct file *file, const struct open_flags *op,
		   int *opened, struct filename *name)
{
	struct dentry *dir = nd->path.dentry;
	int open_flag = op->open_flag;
	bool will_truncate = (open_flag & O_TRUNC) != 0;
	bool got_write = false;
	int acc_mode = op->acc_mode;
	struct inode *inode = nd->inode;
	bool symlink_ok = false;
	struct path save_parent = { .dentry = NULL, .mnt = NULL };
	bool retried = false;
	int error;

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: --> do_last()\n");

	nd->flags &= ~LOOKUP_PARENT;
	nd->flags |= op->intent;

	if (nd->last_type != LAST_NORM) {
		error = handle_dots(nd, nd->last_type);
		if (error)
			return error;
		goto finish_open;
	}

	if (!(open_flag & O_CREAT)) {
		if (nd->last.name[nd->last.len])
			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
		if (open_flag & O_PATH && !(nd->flags & LOOKUP_FOLLOW))
			symlink_ok = true;
		/* we _can_ be in RCU mode here */
		error = lookup_fast(nd, path, &inode);
		if (likely(!error)) {
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: --> do_last: goto finish_lookup\n");
			goto finish_lookup;
		}

		if (error < 0)
			goto out;

		BUG_ON(nd->inode != dir->d_inode);
	} else {
		/* create side of things */
		/*
		 * This will *only* deal with leaving RCU mode - LOOKUP_JUMPED
		 * has been cleared when we got to the last component we are
		 * about to look up
		 */
		error = complete_walk(nd);
		if (error)
			return error;

		audit_inode(name, dir, LOOKUP_PARENT);
		error = -EISDIR;
		/* trailing slashes? */
		if (nd->last.name[nd->last.len])
			goto out;
	}

retry_lookup:
	if (op->open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
		error = mnt_want_write(nd->path.mnt);
		if (!error) {
			if (IS_PATH_UNIONED(&nd->path))
				printk("UNION: got_write = true\n");
			got_write = true;
		}
		/*
		 * do _not_ fail yet - we might not need that or fail with
		 * a different error; let lookup_open() decide; we'll be
		 * dropping this one anyway.
		 */
	}

	mutex_lock(&dir->d_inode->i_mutex);
	error = lookup_open(nd, path, file, op, got_write, opened);
	mutex_unlock(&dir->d_inode->i_mutex);

	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: lookup_open() = %d\n", error);
	if (error <= 0) {
		if (error)
			goto out;

		if ((*opened & FILE_CREATED) ||
		    !S_ISREG(file_inode(file)->i_mode))
			will_truncate = false;

		audit_inode(name, file->f_path.dentry, 0);
		goto opened;
	}

	/* At this point, the file may have been looked up and created or
	 * truncated but hasn't been opened yet - however, since we dropped the
	 * lock, things may have changed in the filesystem.
	 */
	if (*opened & FILE_CREATED) {
		/* Don't check for write permission, don't truncate */
		open_flag &= ~O_TRUNC;
		will_truncate = false;
		acc_mode = MAY_OPEN;
		inode = d_inode_or_lower(path->dentry);
		path_to_nameidata(path, nd);
		goto finish_open_created;
	}

	/*
	 * create/update audit record if it already exists.
	 */
	if (d_is_positive(path->dentry)) {
		audit_inode(name, path->dentry, 0);
		inode = d_inode_or_lower(path->dentry);
	}

	/*
	 * If atomic_open() acquired write access it is dropped now due to
	 * possible mount and symlink following (this might be optimized away if
	 * necessary...)
	 */
	if (got_write) {
		mnt_drop_write(nd->path.mnt);
		got_write = false;
	}

	error = -EEXIST;
	if ((open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT)) {
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: created, but O_EXCL\n");
		goto exit_dput;
	}

	if (IS_PATH_UNIONED(path) &&
	    d_is_pinning_lower(path->dentry) &&
	    d_managed(d_get_fallthru(path->dentry))) {
		error = -EREMOTE;
		goto exit_dput;
	}

	error = follow_managed(path, nd->flags);
	if (error < 0) {
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: follow_managed() = %d\n", error);
		goto exit_dput;
	}

	if (error)
		nd->flags |= LOOKUP_JUMPED;

	BUG_ON(nd->flags & LOOKUP_RCU);
	inode = d_inode_or_lower(path->dentry);
finish_lookup:
	if (IS_MNT_UNION(path->mnt))
		printk("UNION: do_last: finish_lookup: at upper\n");
	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: do_last: nd->path.mnt at upper\n");
	/* we _can_ be in RCU mode here */
	if (d_is_negative(path->dentry)) {
		if (likely(!IS_PATH_UNIONED(&nd->path)))
			goto noent;

		printk("UNION: %pd: d_flags = %x\n",
		       path->dentry, path->dentry->d_flags);

		error = union_lookup_point(nd, path, got_write);
		if (error)
			goto exit_dput;

		if (d_is_negative(path->dentry))
			goto noent;

		inode = d_inode_or_lower(path->dentry);
		if (!inode)
			goto noent;

		printk("UNION: got lower from d_fallthru\n");
	}

	if (should_follow_link(path->dentry, !symlink_ok)) {
		/* The dentry is either a symlink on this fs or it's a
		 * fallthrough to a symlink in a lower fs (in which case inode
		 * will be NULL).
		 */
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: should_follow_link() -> true\n");
		if (nd->flags & LOOKUP_RCU) {
			if (unlikely(unlazy_walk(nd, path->dentry))) {
				error = -ECHILD;
				goto out;
			}
		}
		if (got_write)
			mnt_drop_write(nd->path.mnt);
		return 1;
	}

	if (IS_PATH_UNIONED(&nd->path) &&
	    !path->dentry->d_inode &&
	    (op->acc_mode & (MAY_WRITE | MAY_APPEND) ||
	     op->open_flag & O_TRUNC) &&
	    S_ISREG(inode->i_mode)) {
		printk("UNION: WWWWW Need to copy up\n");

		if (nd->flags & LOOKUP_RCU &&
		    unlikely(unlazy_walk(nd, path->dentry))) {
			path_to_nameidata(path, nd);
			error = -ECHILD;
			goto out;
		}

		if (op->open_flag & O_DIRECTORY) {
			error = -ENOTDIR;
			goto exit_dput;
		}

		/* Like inode_permission(), but inode->i_sb != dentry->d_sb */
		error = sb_permission(path->dentry->d_sb, inode, MAY_WRITE);
		if (error < 0)
			goto exit_dput;
		error = __inode_permission(inode, MAY_WRITE);
		if (error < 0)
			goto exit_dput;

		error = mnt_want_write(nd->path.mnt);
		if (error)
			goto exit_dput;

		error = union_copy_up_for_do_last(&nd->path, path, will_truncate);
		mnt_drop_write(nd->path.mnt);
		if (error)
			goto exit_dput;

		if (path->mnt != nd->path.mnt)
			printk("UNION: !!! mnt not changed by copyup\n");

		printk("UNION: copied up lower\n");
		BUG_ON(path->mnt != nd->path.mnt);

		inode = path->dentry->d_inode;
		if (!inode)
			goto noent;

		open_flag &= ~O_TRUNC;
		will_truncate = false;
		acc_mode = MAY_OPEN;
	}

	if ((nd->flags & LOOKUP_RCU) || nd->path.mnt != path->mnt) {
		if (IS_PATH_UNIONED(&nd->path)) {
			if (nd->flags & LOOKUP_RCU)
				printk("UNION: in rcu mode\n");
			if (nd->path.mnt != path->mnt)
				printk("UNION: nd->path.mnt != path->mnt\n");
		}
		path_to_nameidata(path, nd);
	} else {
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: not in rcu mode\n");
		save_parent.dentry = nd->path.dentry;
		save_parent.mnt = mntget(path->mnt);
		nd->path.dentry = path->dentry;

	}
	nd->inode = inode;
	/* Why this, you ask?  _Now_ we might have grown LOOKUP_JUMPED... */
finish_open:
	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: --> complete_walk()\n");
	error = complete_walk(nd);
	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: <-- complete_walk() = %d\n", error);
	if (error) {
		path_put(&save_parent);
		return error;
	}
	inode = nd->inode;
	audit_inode(name, nd->path.dentry, 0);
	error = -EISDIR;
	if ((open_flag & O_CREAT) &&
	    (d_is_directory(nd->path.dentry) || d_is_autodir(nd->path.dentry)))
		goto out;
	error = -ENOTDIR;
	if ((nd->flags & LOOKUP_DIRECTORY) && !d_is_directory(nd->path.dentry)) {
		if (IS_PATH_UNIONED(&nd->path))
			printk("UNION: !can_lookup\n");
		goto out;
	}
	if (!S_ISREG(inode->i_mode))
		will_truncate = false;

	if (will_truncate && !got_write) {
		error = mnt_want_write(nd->path.mnt);
		if (error)
			goto out;
		got_write = true;
	}
finish_open_created:
	error = may_open(&nd->path, inode, acc_mode, open_flag);
	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: <-- may_open() = %d\n", error);
	if (error)
		goto out;
	file->f_path.mnt = nd->path.mnt;
	error = finish_open(file, nd->path.dentry, inode, NULL, opened);
	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: <-- finish_open() = %d\n", error);
	if (error) {
		if (error == -EOPENSTALE)
			goto stale_open;
		goto out;
	}
opened:
	error = open_check_o_direct(file);
	if (error)
		goto exit_fput;
	error = ima_file_check(file, op->acc_mode);
	if (error)
		goto exit_fput;

	if (will_truncate) {
		error = handle_truncate(file);
		if (error)
			goto exit_fput;
	}
out:
	if (got_write)
		mnt_drop_write(nd->path.mnt);
	path_put(&save_parent);
	terminate_walk(nd);
	return error;

noent:
	if (IS_PATH_UNIONED(&nd->path))
		printk("UNION: %pd: ENOENT\n", path->dentry);
	path_to_nameidata(path, nd);
	error = -ENOENT;
	goto out;

exit_dput:
	path_put_conditional(path, nd);
	goto out;
exit_fput:
	fput(file);
	goto out;

stale_open:
	/* If no saved parent or already retried then can't retry */
	if (!save_parent.dentry || retried)
		goto out;

	BUG_ON(save_parent.dentry != dir);
	path_put(&nd->path);
	nd->path = save_parent;
	nd->inode = dir->d_inode;
	save_parent.mnt = NULL;
	save_parent.dentry = NULL;
	if (got_write) {
		mnt_drop_write(nd->path.mnt);
		got_write = false;
	}
	retried = true;
	goto retry_lookup;
}

static int do_tmpfile(int dfd, struct filename *pathname,
		struct nameidata *nd, int flags,
		const struct open_flags *op,
		struct file *file, int *opened)
{
	static const struct qstr name = QSTR_INIT("/", 1);
	struct dentry *dentry, *child;
	struct inode *dir;
	int error = path_lookupat(dfd, pathname->name,
				  flags | LOOKUP_DIRECTORY, nd);
	if (unlikely(error))
		return error;
	error = mnt_want_write(nd->path.mnt);
	if (unlikely(error))
		goto out;
	/* we want directory to be writable */
	error = inode_permission(nd->inode, MAY_WRITE | MAY_EXEC);
	if (error)
		goto out2;
	dentry = nd->path.dentry;
	dir = dentry->d_inode;
	if (!dir->i_op->tmpfile) {
		error = -EOPNOTSUPP;
		goto out2;
	}
	child = d_alloc(dentry, &name);
	if (unlikely(!child)) {
		error = -ENOMEM;
		goto out2;
	}
	nd->flags &= ~LOOKUP_DIRECTORY;
	nd->flags |= op->intent;
	dput(nd->path.dentry);
	nd->path.dentry = child;
	error = dir->i_op->tmpfile(dir, nd->path.dentry, op->mode);
	if (error)
		goto out2;
	audit_inode(pathname, nd->path.dentry, 0);
	error = may_open(&nd->path, nd->path.dentry->d_inode, op->acc_mode, op->open_flag);
	if (error)
		goto out2;
	file->f_path.mnt = nd->path.mnt;
	error = finish_open(file, nd->path.dentry, nd->path.dentry->d_inode,
			    NULL, opened);
	if (error)
		goto out2;
	error = open_check_o_direct(file);
	if (error) {
		fput(file);
	} else if (!(op->open_flag & O_EXCL)) {
		struct inode *inode = file_inode(file);
		spin_lock(&inode->i_lock);
		inode->i_state |= I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
out2:
	mnt_drop_write(nd->path.mnt);
out:
	path_put(&nd->path);
	return error;
}

static struct file *path_openat(int dfd, struct filename *pathname,
		struct nameidata *nd, const struct open_flags *op, int flags)
{
	struct file *base = NULL;
	struct file *file;
	struct path terminal_symlink;
	int opened = 0;
	int error;

	file = get_empty_filp();
	if (IS_ERR(file))
		return file;

	file->f_flags = op->open_flag;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(dfd, pathname, nd, flags, op, file, &opened);
		goto out;
	}

	error = path_init(dfd, pathname->name, flags | LOOKUP_PARENT, nd, &base);
	if (unlikely(error))
		goto out;

	current->total_link_count = 0;
	error = link_path_walk(pathname->name, nd);
	if (unlikely(error))
		goto out;

	error = do_last(nd, &terminal_symlink, file, op, &opened, pathname);
	while (unlikely(error > 0)) { /* trailing symlink */
		struct path link = terminal_symlink;
		void *cookie;
		if (!(nd->flags & LOOKUP_FOLLOW)) {
			path_put_conditional(&terminal_symlink, nd);
			path_put(&nd->path);
			error = -ELOOP;
			break;
		}
		error = may_follow_link(&link, nd);
		if (unlikely(error))
			break;
		nd->flags |= LOOKUP_PARENT;
		nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
		error = follow_link(&link, nd, &cookie);
		if (unlikely(error))
			break;
		error = do_last(nd, &terminal_symlink, file, op, &opened, pathname);
		put_link(nd, &link, cookie);
	}
out:
	if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT))
		path_put(&nd->root);
	if (base)
		fput(base);
	if (!(opened & FILE_OPENED)) {
		BUG_ON(!error);
		put_filp(file);
	}
	if (unlikely(error)) {
		if (error == -EOPENSTALE) {
			if (flags & LOOKUP_RCU)
				error = -ECHILD;
			else
				error = -ESTALE;
		}
		file = ERR_PTR(error);
	}
	return file;
}

struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	filp = path_openat(dfd, pathname, &nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(dfd, pathname, &nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(dfd, pathname, &nd, op, flags | LOOKUP_REVAL);
	return filp;
}

struct file *do_file_open_root(struct dentry *dentry, struct vfsmount *mnt,
		const char *name, const struct open_flags *op)
{
	struct nameidata nd;
	struct file *file;
	struct filename filename = { .name = name };
	int flags = op->lookup_flags | LOOKUP_ROOT;

	nd.root.mnt = mnt;
	nd.root.dentry = dentry;

	if (d_is_symlink(dentry) && op->intent & LOOKUP_OPEN)
		return ERR_PTR(-ELOOP);

	file = path_openat(-1, &filename, &nd, op, flags | LOOKUP_RCU);
	if (unlikely(file == ERR_PTR(-ECHILD)))
		file = path_openat(-1, &filename, &nd, op, flags);
	if (unlikely(file == ERR_PTR(-ESTALE)))
		file = path_openat(-1, &filename, &nd, op, flags | LOOKUP_REVAL);
	return file;
}

struct dentry *kern_path_create(int dfd, const char *pathname,
				struct path *path, unsigned int lookup_flags)
{
	struct nameidata nd;
	struct path new_path;
	int err2;
	int error;
	bool is_dir = (lookup_flags & LOOKUP_DIRECTORY);

	/*
	 * Note that only LOOKUP_REVAL and LOOKUP_DIRECTORY matter here. Any
	 * other flags passed in are ignored!
	 */
	lookup_flags &= LOOKUP_REVAL;

	error = do_path_lookup(dfd, pathname, LOOKUP_PARENT|lookup_flags, &nd);
	if (error)
		return ERR_PTR(error);

	/*
	 * Yucky last component or no last component at all?
	 * (foo/., foo/.., /////)
	 */
	error = -EEXIST;
	if (nd.last_type != LAST_NORM)
		goto out;
	nd.flags &= ~LOOKUP_PARENT;
	nd.flags |= LOOKUP_CREATE | LOOKUP_EXCL;

	/* don't fail immediately if it's r/o, at least try to report other errors */
	err2 = mnt_want_write(nd.path.mnt);
	/*
	 * Do the final lookup.
	 */
	mutex_lock_nested(&nd.path.dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	error = lookup_hash(&nd, &new_path);
	if (error)
		goto unlock;

	error = -EEXIST;
	if (d_is_positive(new_path.dentry))
		goto fail;

	/*
	 * Special case - lookup gave negative, but... we had foo/bar/
	 * From the vfs_mknod() POV we just have a negative dentry -
	 * all is fine. Let's be bastards - you had / on the end, you've
	 * been asking for (non-existent) directory. -ENOENT for you.
	 */
	if (unlikely(!is_dir && nd.last.name[nd.last.len])) {
		error = -ENOENT;
		goto fail;
	}
	if (unlikely(err2)) {
		error = err2;
		goto fail;
	}
	*path = nd.path;
	return new_path.dentry;

fail:
	dput(new_path.dentry);
unlock:
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	if (!err2)
		mnt_drop_write(nd.path.mnt);
out:
	path_put(&nd.path);
	return ERR_PTR(error);
}
EXPORT_SYMBOL(kern_path_create);

void done_path_create(struct path *path, struct dentry *dentry)
{
	dput(dentry);
	mutex_unlock(&path->dentry->d_inode->i_mutex);
	mnt_drop_write(path->mnt);
	path_put(path);
}
EXPORT_SYMBOL(done_path_create);

struct dentry *user_path_create(int dfd, const char __user *pathname,
				struct path *path, unsigned int lookup_flags)
{
	struct filename *tmp = getname(pathname);
	struct dentry *res;
	if (IS_ERR(tmp))
		return ERR_CAST(tmp);
	res = kern_path_create(dfd, tmp->name, path, lookup_flags);
	putname(tmp);
	return res;
}
EXPORT_SYMBOL(user_path_create);

int vfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int error = may_create(dir, dentry);

	if (error)
		return error;

	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;

	if (!dir->i_op->mknod)
		return -EPERM;

	error = devcgroup_inode_mknod(mode, dev);
	if (error)
		return error;

	error = security_inode_mknod(dir, dentry, mode, dev);
	if (error)
		return error;

	error = dir->i_op->mknod(dir, dentry, mode, dev);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}

static int may_mknod(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
	case 0: /* zero mode translates to S_IFREG */
		return 0;
	case S_IFDIR:
		return -EPERM;
	default:
		return -EINVAL;
	}
}

SYSCALL_DEFINE4(mknodat, int, dfd, const char __user *, filename, umode_t, mode,
		unsigned, dev)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = 0;

	error = may_mknod(mode);
	if (error)
		return error;
retry:
	dentry = user_path_create(dfd, filename, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mknod(&path, dentry, mode, dev);
	if (error)
		goto out;
	switch (mode & S_IFMT) {
		case 0: case S_IFREG:
			error = vfs_create(path.dentry->d_inode,dentry,mode,true);
			break;
		case S_IFCHR: case S_IFBLK:
			error = vfs_mknod(path.dentry->d_inode,dentry,mode,
					new_decode_dev(dev));
			break;
		case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(path.dentry->d_inode,dentry,mode,0);
			break;
	}
out:
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(mknod, const char __user *, filename, umode_t, mode, unsigned, dev)
{
	return sys_mknodat(AT_FDCWD, filename, mode, dev);
}

int vfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int error = may_create(dir, dentry);
	unsigned max_links = dir->i_sb->s_max_links;

	if (error)
		return error;

	if (!dir->i_op->mkdir)
		return -EPERM;

	mode &= (S_IRWXUGO|S_ISVTX);
	error = security_inode_mkdir(dir, dentry, mode);
	if (error)
		return error;

	if (max_links && dir->i_nlink >= max_links)
		return -EMLINK;

	error = dir->i_op->mkdir(dir, dentry, mode);
	if (error)
		return error;

	/* XXX racy - crash now and dir isn't opaque */
	if (IS_DIR_UNIONED(dentry->d_parent)) {
		dentry->d_inode->i_flags |= S_OPAQUE;
		mark_inode_dirty(dentry->d_inode);
	}

	fsnotify_mkdir(dir, dentry);

	return error;
}

SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, umode_t, mode)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;

retry:
	dentry = user_path_create(dfd, pathname, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mkdir(&path, dentry, mode);
	if (!error)
		error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
{
	return sys_mkdirat(AT_FDCWD, pathname, mode);
}

/**
 * vfs_whiteout: Create a whiteout for the given directory entry
 * @parent: Parent directory
 * @old_path: Directory entry to whiteout
 * @isdir: The file at @old_path is a directory
 *
 * Create a whiteout for the given directory entry.  A whiteout prevents lookup
 * from dropping down to a lower layer of a union mounted file system.
 *
 * There are two important cases: (a) The directory entry to be whited out may
 * already exist, in which case it must first be deleted before we create the
 * whiteout, and (b) no such directory entry exists and we only have to create
 * the whiteout itself.
 *
 * The caller must pass in a dentry for the directory entry to be whited out -
 * a positive one if it exists, and a negative if not.  When this function
 * returns, the caller should dput() the old, now defunct dentry it passed in.
 * The dentry for the whiteout itself is created inside this function.
 *
 * The caller must hold the i_mutex lock on the parent directory.
 */
static int vfs_whiteout(struct dentry *parent, struct path *old_path, int isdir)
{
	struct dentry *old_dentry = old_path->dentry;
	struct inode *dir = parent->d_inode, *old_inode = old_dentry->d_inode;
	int err = 0;

	BUG_ON(old_dentry->d_parent != parent);

	if (!dir->i_op || !dir->i_op->whiteout)
		return -EOPNOTSUPP;

	/* If the old dentry is positive, then we have to delete this entry
	 * before we create the whiteout.  The file system ->whiteout() op does
	 * the actual delete, but we do all the VFS-level checks and changes
	 * here.
	 */
	if (old_inode) {
		mutex_lock(&old_inode->i_mutex);
		if (d_mountpoint(old_dentry)) {
			mutex_unlock(&old_inode->i_mutex);
			return -EBUSY;
		}
		if (isdir)
			err = security_inode_rmdir(dir, old_dentry);
		else
			err = security_inode_unlink(dir, old_dentry);
		if (err)
			goto error_unlock;

		/* If we're removing a directory, we need to work out if it is
		 * empty - but if the directory has not yet been copied up, we
		 * cannot tell that by simply reading the lower dirs.  We have
		 * to subtract the set of whiteouts in the top dir from the
		 * union of the sets of dirents from the lower dirs - ie. do a
		 * copyup.
		 */
		if (isdir) {
			err = union_copy_up_dir(old_path);
			if (err)
				goto error_unlock;
		}
	}

	err = dir->i_op->whiteout(dir, old_dentry);
	if (err)
		goto error_unlock;

	if (old_inode) {
		mutex_unlock(&old_inode->i_mutex);
		if (isdir) {
			old_inode->i_flags |= S_DEAD;
			dont_mount(old_dentry);
		} else {
			fsnotify_link_count(old_inode);
		}
		d_drop(old_dentry);
	}
	return err;

error_unlock:
	if (old_inode)
		mutex_unlock(&old_inode->i_mutex);
	return err;
}

static int do_whiteout(struct nameidata *nd, struct path *path, int isdir)
{
	struct path safe = nd->path;
	struct dentry *dentry = path->dentry;
	int err;

	path_get(&safe);

	err = may_delete(nd->path.dentry->d_inode, dentry, isdir);
	if (err)
		goto out;

	err = vfs_whiteout(nd->path.dentry, path, isdir);

out:
	path_put(&safe);
	return err;
}

/*
 * Create a whiteout to finish off a rename from a unionmounted directory.
 * This prevents any file of the same name in the lowerfs from showing through.
 */
static int vfs_whiteout_after_rename(struct dentry *parent,
				     const struct qstr *name)
{
	struct inode *dir = parent->d_inode;
	struct dentry *dummy;
	int err;

	if (!dir->i_op || !dir->i_op->whiteout)
		return -EOPNOTSUPP;

	/* Rename moved the old dentry somewhere else, so there can't be one
	 * here now (the caller's locks see to that) and so there's no need to
	 * call lookup, especially as the ->whiteout() op is expected to add
	 * the new dentry into the tree.
	 */
	dummy = d_alloc(parent, name);
	if (!dummy)
		return -ENOMEM;

	/* I think it's okay to pass the new whiteout as the old dentry here.
	 * What it seems to want is the name, the parent dentry and the inode.
	 * However, we know the inode no longer resides there and d_inode will
	 * be NULL.
	 */
	err = dir->i_op->whiteout(dir, dummy);

	dput(dummy);
	return err;
}

/*
 * The dentry_unhash() helper will try to drop the dentry early: we
 * should have a usage count of 1 if we're the only user of this
 * dentry, and if that is true (possibly after pruning the dcache),
 * then we drop the dentry now.
 *
 * A low-level filesystem can, if it choses, legally
 * do a
 *
 *	if (!d_unhashed(dentry))
 *		return -EBUSY;
 *
 * if it cannot handle the case of removing a directory
 * that is still in use by something else..
 */
void dentry_unhash(struct dentry *dentry)
{
	shrink_dcache_parent(dentry);
	spin_lock(&dentry->d_lock);
	if (dentry->d_lockref.count == 1)
		__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
}

int vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);

	if (error)
		return error;

	if (!dir->i_op->rmdir)
		return -EPERM;

	dget(dentry);
	mutex_lock(&dentry->d_inode->i_mutex);

	error = -EBUSY;
	if (d_mountpoint(dentry))
		goto out;

	error = security_inode_rmdir(dir, dentry);
	if (error)
		goto out;

	shrink_dcache_parent(dentry);
	error = dir->i_op->rmdir(dir, dentry);
	if (error)
		goto out;

	dentry->d_inode->i_flags |= S_DEAD;
	dont_mount(dentry);

out:
	mutex_unlock(&dentry->d_inode->i_mutex);
	dput(dentry);
	if (!error)
		d_delete(dentry);
	return error;
}

static long do_rmdir(int dfd, const char __user *pathname)
{
	int error = 0;
	struct filename *name;
	struct path path;
	struct nameidata nd;
	unsigned int lookup_flags = 0;
retry:
	name = user_path_parent(dfd, pathname, &nd, lookup_flags);
	if (IS_ERR(name))
		return PTR_ERR(name);

	switch(nd.last_type) {
	case LAST_DOTDOT:
		error = -ENOTEMPTY;
		goto exit1;
	case LAST_DOT:
		error = -EINVAL;
		goto exit1;
	case LAST_ROOT:
		error = -EBUSY;
		goto exit1;
	}

	nd.flags &= ~LOOKUP_PARENT;
	error = mnt_want_write(nd.path.mnt);
	if (error)
		goto exit1;

	mutex_lock_nested(&nd.path.dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	error = lookup_hash(&nd, &path);
	if (error)
		goto exit2;
	error = security_path_rmdir(&nd.path, path.dentry);
	if (error)
		goto exit3;
	if (IS_DIR_UNIONED(nd.path.dentry))
		error = do_whiteout(&nd, &path, 1);
	else
		error = vfs_rmdir(nd.path.dentry->d_inode, path.dentry);
exit3:
	path_put_conditional(&path, &nd);
exit2:
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	mnt_drop_write(nd.path.mnt);
exit1:
	path_put(&nd.path);
	putname(name);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE1(rmdir, const char __user *, pathname)
{
	return do_rmdir(AT_FDCWD, pathname);
}

/**
 * vfs_unlink - unlink a filesystem object
 * @dir:	parent directory
 * @dentry:	victim
 * @delegated_inode: returns victim inode, if the inode is delegated.
 *
 * The caller must hold dir->i_mutex.
 *
 * If vfs_unlink discovers a delegation, it will return -EWOULDBLOCK and
 * return a reference to the inode in delegated_inode.  The caller
 * should then break the delegation on that inode and retry.  Because
 * breaking a delegation may take a long time, the caller should drop
 * dir->i_mutex before doing so.
 *
 * Alternatively, a caller may pass NULL for delegated_inode.  This may
 * be appropriate for callers that expect the underlying filesystem not
 * to be NFS exported.
 */
int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	struct inode *target = dentry->d_inode;
	int error = may_delete(dir, dentry, 0);

	if (error)
		return error;

	if (!dir->i_op->unlink)
		return -EPERM;

	mutex_lock(&target->i_mutex);
	if (d_mountpoint(dentry))
		error = -EBUSY;
	else {
		error = security_inode_unlink(dir, dentry);
		if (!error) {
			error = try_break_deleg(target, delegated_inode);
			if (error)
				goto out;
			error = dir->i_op->unlink(dir, dentry);
			if (!error)
				dont_mount(dentry);
		}
	}
out:
	mutex_unlock(&target->i_mutex);

	/* We don't d_delete() NFS sillyrenamed files--they still exist. */
	if (!error && !(dentry->d_flags & DCACHE_NFSFS_RENAMED)) {
		fsnotify_link_count(target);
		d_delete(dentry);
	}

	return error;
}

/*
 * Make sure that the actual truncation of the file will occur outside its
 * directory's i_mutex.  Truncate can take a long time if there is a lot of
 * writeout happening, and we don't want to prevent access to the directory
 * while waiting on the I/O.
 */
static long do_unlinkat(int dfd, const char __user *pathname)
{
	int error;
	struct filename *name;
	struct path path;
	struct nameidata nd;
	struct inode *inode = NULL;
	struct inode *delegated_inode = NULL;
	unsigned int lookup_flags = 0;

retry:
	name = user_path_parent(dfd, pathname, &nd, lookup_flags);
	if (IS_ERR(name))
		return PTR_ERR(name);

	error = -EISDIR;
	if (nd.last_type != LAST_NORM)
		goto exit1;

	nd.flags &= ~LOOKUP_PARENT;
	error = mnt_want_write(nd.path.mnt);
	if (error)
		goto exit1;
retry_deleg:
	mutex_lock_nested(&nd.path.dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	error = lookup_hash(&nd, &path);
	if (error)
		goto exit2;

	/* Why not before? Because we want correct error value */
	if (d_is_negative(path.dentry)) {
		if (IS_PATH_UNIONED(&nd.path))
			printk("UNION: unlink neg\n");
		BUG_ON(path.dentry->d_inode);
		error = -ENOENT;
	} else if (nd.last.name[nd.last.len]) {
		if (IS_PATH_UNIONED(&nd.path))
			printk("UNION: unlink slash: %x\n", path.dentry->d_flags);
		BUG_ON(!(path.dentry->d_flags & DCACHE_UNION_PINNING_LOWER) &&
		       !path.dentry->d_inode);
		error = d_is_directory(path.dentry) ? -EISDIR : -ENOTDIR;
	} else if (!path.dentry->d_inode) {
		if (IS_PATH_UNIONED(&nd.path))
			printk("UNION: unlink lower\n");
		error = security_path_unlink(&nd.path, path.dentry);
		if (!error) {
			if (IS_PATH_UNIONED(&nd.path))
				printk("UNION: call do_whiteout()\n");
			error = do_whiteout(&nd, &path, 0);
		}
	} else {
		if (IS_PATH_UNIONED(&nd.path))
			printk("UNION: unlink upper\n");
		inode = path.dentry->d_inode;
		ihold(inode);
		error = security_path_unlink(&nd.path, path.dentry);
		if (!error) {
			if (IS_DIR_UNIONED(nd.path.dentry))
				error = do_whiteout(&nd, &path, 0);
			else
				error = vfs_unlink(nd.path.dentry->d_inode, path.dentry,
						   &delegated_inode);
		}
	}

	path_put_conditional(&path, &nd);
exit2:
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	if (inode)
		iput(inode);	/* truncate the inode here */
	inode = NULL;
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(nd.path.mnt);
exit1:
	path_put(&nd.path);
	putname(name);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		inode = NULL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
{
	if ((flag & ~AT_REMOVEDIR) != 0)
		return -EINVAL;

	if (flag & AT_REMOVEDIR)
		return do_rmdir(dfd, pathname);

	return do_unlinkat(dfd, pathname);
}

SYSCALL_DEFINE1(unlink, const char __user *, pathname)
{
	return do_unlinkat(AT_FDCWD, pathname);
}

int vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname)
{
	int error = may_create(dir, dentry);

	if (error)
		return error;

	if (!dir->i_op->symlink)
		return -EPERM;

	error = security_inode_symlink(dir, dentry, oldname);
	if (error)
		return error;

	error = dir->i_op->symlink(dir, dentry, oldname);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}

SYSCALL_DEFINE3(symlinkat, const char __user *, oldname,
		int, newdfd, const char __user *, newname)
{
	int error;
	struct filename *from;
	struct dentry *dentry;
	struct path path;
	unsigned int lookup_flags = 0;

	from = getname(oldname);
	if (IS_ERR(from))
		return PTR_ERR(from);
retry:
	dentry = user_path_create(newdfd, newname, &path, lookup_flags);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_putname;

	error = security_path_symlink(&path, dentry, from->name);
	if (!error)
		error = vfs_symlink(path.dentry->d_inode, dentry, from->name);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out_putname:
	putname(from);
	return error;
}

SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname)
{
	return sys_symlinkat(oldname, AT_FDCWD, newname);
}

/**
 * vfs_link - create a new link
 * @old_dentry:	object to be linked
 * @dir:	new parent
 * @new_dentry:	where to create the new link
 * @delegated_inode: returns inode needing a delegation break
 *
 * The caller must hold dir->i_mutex
 *
 * If vfs_link discovers a delegation on the to-be-linked file in need
 * of breaking, it will return -EWOULDBLOCK and return a reference to the
 * inode in delegated_inode.  The caller should then break the delegation
 * and retry.  Because breaking a delegation may take a long time, the
 * caller should drop the i_mutex before doing so.
 *
 * Alternatively, a caller may pass NULL for delegated_inode.  This may
 * be appropriate for callers that expect the underlying filesystem not
 * to be NFS exported.
 */
int vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry, struct inode **delegated_inode)
{
	struct inode *inode = old_dentry->d_inode;
	unsigned max_links = dir->i_sb->s_max_links;
	int error;

	if (!inode)
		return -ENOENT;

	error = may_create(dir, new_dentry);
	if (error)
		return error;

	if (dir->i_sb != inode->i_sb)
		return -EXDEV;

	/*
	 * A link to an append-only or immutable file cannot be created.
	 */
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	if (!dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	error = security_inode_link(old_dentry, dir, new_dentry);
	if (error)
		return error;

	mutex_lock(&inode->i_mutex);
	/* Make sure we don't allow creating hardlink to an unlinked file */
	if (inode->i_nlink == 0 && !(inode->i_state & I_LINKABLE))
		error =  -ENOENT;
	else if (max_links && inode->i_nlink >= max_links)
		error = -EMLINK;
	else {
		error = try_break_deleg(inode, delegated_inode);
		if (!error)
			error = dir->i_op->link(old_dentry, dir, new_dentry);
	}

	if (!error && (inode->i_state & I_LINKABLE)) {
		spin_lock(&inode->i_lock);
		inode->i_state &= ~I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
	mutex_unlock(&inode->i_mutex);
	if (!error)
		fsnotify_link(dir, inode, new_dentry);
	return error;
}

/*
 * Hardlinks are often used in delicate situations.  We avoid
 * security-related surprises by not following symlinks on the
 * newname.  --KAB
 *
 * We don't follow them on the oldname either to be compatible
 * with linux 2.0, and to avoid hard-linking to directories
 * and other special files.  --ADM
 */
SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname,
		int, newdfd, const char __user *, newname, int, flags)
{
	struct dentry *new_dentry;
	struct path old_path, new_path, lower_cache, actual;
	struct inode *inode, *delegated_inode = NULL;
	int how = 0;
	int error;

	if ((flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;
	/*
	 * To use null names we require CAP_DAC_READ_SEARCH
	 * This ensures that not everyone will be able to create
	 * handlink using the passed filedescriptor.
	 */
	if (flags & AT_EMPTY_PATH) {
		if (!capable(CAP_DAC_READ_SEARCH))
			return -ENOENT;
		how = LOOKUP_EMPTY;
	}

	if (flags & AT_SYMLINK_FOLLOW)
		how |= LOOKUP_FOLLOW;

retry:
	error = user_path_at(olddfd, oldname, how, &old_path);
	if (error)
		return error;

	inode = union_get_inode(&old_path, &lower_cache, &actual);
	if (IS_ERR(inode)) {
		error = PTR_ERR(inode);
		goto out;
	}
	error = union_copy_up(&old_path, &actual);
	path_put_maybe(&lower_cache);
	if (error < 0)
		goto out;

	new_dentry = user_path_create(newdfd, newname, &new_path,
					(how & LOOKUP_REVAL));
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto out;

	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto out_dput;
	error = may_linkat(&old_path);
	if (unlikely(error))
		goto out_dput;
	error = security_path_link(old_path.dentry, &new_path, new_dentry);
	if (error)
		goto out_dput;
	error = vfs_link(old_path.dentry, new_path.dentry->d_inode, new_dentry, &delegated_inode);
out_dput:
	done_path_create(&new_path, new_dentry);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry;
	}
	if (retry_estale(error, how)) {
		how |= LOOKUP_REVAL;
		goto retry;
	}
out:
	path_put(&old_path);

	return error;
}

SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *, newname)
{
	return sys_linkat(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}

/*
 * The worst of all namespace operations - renaming directory. "Perverted"
 * doesn't even start to describe it. Somebody in UCB had a heck of a trip...
 * Problems:
 *	a) we can get into loop creation. Check is done in is_subdir().
 *	b) race potential - two innocent renames can create a loop together.
 *	   That's where 4.4 screws up. Current fix: serialization on
 *	   sb->s_vfs_rename_mutex. We might be more accurate, but that's another
 *	   story.
 *	c) we have to lock _four_ objects - parents and victim (if it exists),
 *	   and source (if it is not a directory).
 *	   And that - after we got ->i_mutex on parents (until then we don't know
 *	   whether the target exists).  Solution: try to be smart with locking
 *	   order for inodes.  We rely on the fact that tree topology may change
 *	   only under ->s_vfs_rename_mutex _and_ that parent of the object we
 *	   move will be locked.  Thus we can rank directories by the tree
 *	   (ancestors first) and rank all non-directories after them.
 *	   That works since everybody except rename does "lock parent, lookup,
 *	   lock child" and rename is under ->s_vfs_rename_mutex.
 *	   HOWEVER, it relies on the assumption that any object with ->lookup()
 *	   has no more than 1 dentry.  If "hybrid" objects will ever appear,
 *	   we'd better make sure that there's no link(2) for them.
 *	d) conversion from fhandle to dentry may come in the wrong moment - when
 *	   we are removing the target. Solution: we will have to grab ->i_mutex
 *	   in the fhandle_to_dentry code. [FIXME - current nfsfh.c relies on
 *	   ->i_mutex on parents, which works but leads to some truly excessive
 *	   locking].
 */
static int vfs_rename_dir(struct inode *old_dir, struct dentry *old_dentry,
			  struct inode *new_dir, struct dentry *new_dentry)
{
	int error = 0;
	struct inode *target = new_dentry->d_inode;
	unsigned max_links = new_dir->i_sb->s_max_links;

	/*
	 * If we are going to change the parent - check write permissions,
	 * we'll need to flip '..'.
	 */
	if (new_dir != old_dir) {
		error = inode_permission(old_dentry->d_inode, MAY_WRITE);
		if (error)
			return error;
	}

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
	if (error)
		return error;

	dget(new_dentry);
	if (target)
		mutex_lock(&target->i_mutex);

	error = -EBUSY;
	if (d_mountpoint(old_dentry) || d_mountpoint(new_dentry))
		goto out;

	error = -EMLINK;
	if (max_links && !target && new_dir != old_dir &&
	    new_dir->i_nlink >= max_links)
		goto out;

	if (target)
		shrink_dcache_parent(new_dentry);
	error = old_dir->i_op->rename(old_dir, old_dentry, new_dir, new_dentry);
	if (error)
		goto out;

	if (target) {
		target->i_flags |= S_DEAD;
		dont_mount(new_dentry);
	}
out:
	if (target)
		mutex_unlock(&target->i_mutex);
	dput(new_dentry);
	if (!error)
		if (!(old_dir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE))
			d_move(old_dentry,new_dentry);
	return error;
}

static int vfs_rename_other(struct inode *old_dir, struct dentry *old_dentry,
			    struct inode *new_dir, struct dentry *new_dentry,
			    struct inode **delegated_inode)
{
	struct inode *target = new_dentry->d_inode;
	struct inode *source = old_dentry->d_inode;
	int error;

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
	if (error)
		return error;

	dget(new_dentry);
	lock_two_nondirectories(source, target);

	error = -EBUSY;
	if (d_mountpoint(old_dentry)||d_mountpoint(new_dentry))
		goto out;

	error = try_break_deleg(source, delegated_inode);
	if (error)
		goto out;
	if (target) {
		error = try_break_deleg(target, delegated_inode);
		if (error)
			goto out;
	}
	error = old_dir->i_op->rename(old_dir, old_dentry, new_dir, new_dentry);
	if (error)
		goto out;

	if (target)
		dont_mount(new_dentry);
	if (!(old_dir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE))
		d_move(old_dentry, new_dentry);
out:
	unlock_two_nondirectories(source, target);
	dput(new_dentry);
	return error;
}

/**
 * vfs_rename - rename a filesystem object
 * @old_dir:	parent of source
 * @old_dentry:	source
 * @new_dir:	parent of destination
 * @new_dentry:	destination
 * @delegated_inode: returns an inode needing a delegation break
 *
 * The caller must hold multiple mutexes--see lock_rename()).
 *
 * If vfs_rename discovers a delegation in need of breaking at either
 * the source or destination, it will return -EWOULDBLOCK and return a
 * reference to the inode in delegated_inode.  The caller should then
 * break the delegation and retry.  Because breaking a delegation may
 * take a long time, the caller should drop all locks before doing
 * so.
 *
 * Alternatively, a caller may pass NULL for delegated_inode.  This may
 * be appropriate for callers that expect the underlying filesystem not
 * to be NFS exported.
 */
int vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry,
	       struct inode **delegated_inode)
{
	int error;
	int is_dir = d_is_directory(old_dentry) || d_is_autodir(old_dentry);
	const unsigned char *old_name;

	if (old_dentry->d_inode == new_dentry->d_inode)
 		return 0;
 
	error = may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;

	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry);
	else
		error = may_delete(new_dir, new_dentry, is_dir);
	if (error)
		return error;

	if (!old_dir->i_op->rename)
		return -EPERM;

	old_name = fsnotify_oldname_init(old_dentry->d_name.name);

	if (is_dir)
		error = vfs_rename_dir(old_dir,old_dentry,new_dir,new_dentry);
	else
		error = vfs_rename_other(old_dir,old_dentry,new_dir,new_dentry,delegated_inode);
	if (!error)
		fsnotify_move(old_dir, new_dir, old_name, is_dir,
			      new_dentry->d_inode, old_dentry);
	fsnotify_oldname_free(old_name);

	return error;
}

SYSCALL_DEFINE4(renameat, int, olddfd, const char __user *, oldname,
		int, newdfd, const char __user *, newname)
{
	struct dentry *old_dir, *new_dir;
	struct inode *old_inode;
	struct path old, new, old_lower_cache, old_actual;
	struct dentry *trap;
	struct nameidata oldnd, newnd;
	struct inode *delegated_inode = NULL;
	struct filename *from;
	struct filename *to;
	unsigned int lookup_flags = 0;
	bool should_retry = false;
	int error;
retry:
	from = user_path_parent(olddfd, oldname, &oldnd, lookup_flags);
	if (IS_ERR(from)) {
		error = PTR_ERR(from);
		goto exit;
	}

	to = user_path_parent(newdfd, newname, &newnd, lookup_flags);
	if (IS_ERR(to)) {
		error = PTR_ERR(to);
		goto exit1;
	}

	error = -EXDEV;
	if (oldnd.path.mnt != newnd.path.mnt)
		goto exit2;
	old_dir = oldnd.path.dentry;
	error = -EBUSY;
	if (oldnd.last_type != LAST_NORM)
		goto exit2;

	new_dir = newnd.path.dentry;
	if (newnd.last_type != LAST_NORM)
		goto exit2;

	error = mnt_want_write(oldnd.path.mnt);
	if (error)
		goto exit2;

	oldnd.flags &= ~LOOKUP_PARENT;
	newnd.flags &= ~LOOKUP_PARENT;
	newnd.flags |= LOOKUP_RENAME_TARGET;

retry_deleg:
	trap = lock_rename(new_dir, old_dir);

	error = lookup_hash(&oldnd, &old);
	if (error)
		goto exit3;
	/* source must exist */
	old_inode = d_inode_or_lower(old.dentry);
	error = -ENOENT;
	if (d_is_negative(old.dentry))
		goto exit4;
	/* unless the source is a directory trailing slashes give -ENOTDIR */
	if (!d_is_directory(old.dentry) && !d_is_autodir(old.dentry)) {
		error = -ENOTDIR;
		if (oldnd.last.name[oldnd.last.len])
			goto exit4;
		if (newnd.last.name[newnd.last.len])
			goto exit4;
	}
	/* source should not be ancestor of target */
	error = -EINVAL;
	if (old.dentry == trap)
		goto exit4;
	error = -EXDEV;
	/* Can't rename a directory from a lower layer */
	if (IS_DIR_UNIONED(oldnd.path.dentry) &&
	    IS_DIR_UNIONED(old.dentry))
		goto exit4;
	error = lookup_hash(&newnd, &new);
	if (error)
		goto exit4;
	/* target should not be an ancestor of source */
	error = -ENOTEMPTY;
	if (new.dentry == trap)
		goto exit5;
	error = -EXDEV;
	/* Can't rename over directories on the lower layer */
	if (IS_DIR_UNIONED(newnd.path.dentry) &&
	    IS_DIR_UNIONED(new.dentry))
		goto exit5;

	error = security_path_rename(&oldnd.path, old.dentry,
				     &newnd.path, new.dentry,
				     old_inode);
	if (error)
		goto exit5;

	error = union_copy_up_locked(&oldnd.path, &old, &old_actual);
	if (error)
		goto exit5;

	error = vfs_rename(old_dir->d_inode, old.dentry,
				   new_dir->d_inode, new.dentry,
				   &delegated_inode);
	if (error)
		goto exit5;

	/* Now whiteout the source.  We may have exposed a positive lower level
	 * dentry, so we have to make sure it doesn't get resurrected.  We
	 * could probe the lower levels at this point to find out whether there
	 * is actually anything that needs whiting out.
	 *
	 * Note that if this fails, it may leave the lower dentry exposed, and
	 * we may not be able to recover by simply renaming back (say we
	 * encountered ENOMEM or ENOSPC conditions).
	 */
	if (IS_DIR_UNIONED(oldnd.path.dentry))
		error = vfs_whiteout_after_rename(old_dir, &oldnd.last);

exit5:
	path_put_conditional(&new, &newnd);
exit4:
	path_put_maybe(&old_lower_cache);
	path_put_conditional(&old, &oldnd);
exit3:
	unlock_rename(new_dir, old_dir);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(oldnd.path.mnt);
exit2:
	if (retry_estale(error, lookup_flags))
		should_retry = true;
	path_put(&newnd.path);
	putname(to);
exit1:
	path_put(&oldnd.path);
	putname(from);
	if (should_retry) {
		should_retry = false;
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
exit:
	return error;
}

SYSCALL_DEFINE2(rename, const char __user *, oldname, const char __user *, newname)
{
	return sys_renameat(AT_FDCWD, oldname, AT_FDCWD, newname);
}

int vfs_readlink(struct dentry *dentry, char __user *buffer, int buflen, const char *link)
{
	int len;

	len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}

/*
 * A helper for ->readlink().  This should be used *ONLY* for symlinks that
 * have ->follow_link() touching nd only in nd_set_link().  Using (or not
 * using) it for any given inode is up to filesystem.
 */
int generic_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct nameidata nd;
	void *cookie;
	int res;

	nd.depth = 0;
	dentry = d_dentry_or_lower(dentry);
	cookie = dentry->d_inode->i_op->follow_link(dentry, &nd);
	if (IS_ERR(cookie))
		return PTR_ERR(cookie);

	res = vfs_readlink(dentry, buffer, buflen, nd_get_link(&nd));
	if (dentry->d_inode->i_op->put_link)
		dentry->d_inode->i_op->put_link(dentry, &nd, cookie);
	return res;
}

/* get the link contents into pagecache */
static char *page_getlink(struct dentry * dentry, struct page **ppage)
{
	char *kaddr;
	struct page *page;
	struct address_space *mapping = dentry->d_inode->i_mapping;
	page = read_mapping_page(mapping, 0, NULL);
	if (IS_ERR(page))
		return (char*)page;
	*ppage = page;
	kaddr = kmap(page);
	nd_terminate_link(kaddr, dentry->d_inode->i_size, PAGE_SIZE - 1);
	return kaddr;
}

int page_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct page *page = NULL;
	char *s = page_getlink(dentry, &page);
	int res = vfs_readlink(dentry,buffer,buflen,s);
	if (page) {
		kunmap(page);
		page_cache_release(page);
	}
	return res;
}

void *page_follow_link_light(struct dentry *dentry, struct nameidata *nd)
{
	struct page *page = NULL;
	nd_set_link(nd, page_getlink(dentry, &page));
	return page;
}

void page_put_link(struct dentry *dentry, struct nameidata *nd, void *cookie)
{
	struct page *page = cookie;

	if (page) {
		kunmap(page);
		page_cache_release(page);
	}
}

/*
 * The nofs argument instructs pagecache_write_begin to pass AOP_FLAG_NOFS
 */
int __page_symlink(struct inode *inode, const char *symname, int len, int nofs)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	void *fsdata;
	int err;
	char *kaddr;
	unsigned int flags = AOP_FLAG_UNINTERRUPTIBLE;
	if (nofs)
		flags |= AOP_FLAG_NOFS;

retry:
	err = pagecache_write_begin(NULL, mapping, 0, len-1,
				flags, &page, &fsdata);
	if (err)
		goto fail;

	kaddr = kmap_atomic(page);
	memcpy(kaddr, symname, len-1);
	kunmap_atomic(kaddr);

	err = pagecache_write_end(NULL, mapping, 0, len-1, len-1,
							page, fsdata);
	if (err < 0)
		goto fail;
	if (err < len-1)
		goto retry;

	mark_inode_dirty(inode);
	return 0;
fail:
	return err;
}

int page_symlink(struct inode *inode, const char *symname, int len)
{
	return __page_symlink(inode, symname, len,
			!(mapping_gfp_mask(inode->i_mapping) & __GFP_FS));
}

const struct inode_operations page_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
};

EXPORT_SYMBOL(user_path_at);
EXPORT_SYMBOL(follow_down_one);
EXPORT_SYMBOL(follow_down);
EXPORT_SYMBOL(follow_up);
EXPORT_SYMBOL(get_write_access); /* nfsd */
EXPORT_SYMBOL(lock_rename);
EXPORT_SYMBOL(lookup_one_len);
EXPORT_SYMBOL(page_follow_link_light);
EXPORT_SYMBOL(page_put_link);
EXPORT_SYMBOL(page_readlink);
EXPORT_SYMBOL(__page_symlink);
EXPORT_SYMBOL(page_symlink);
EXPORT_SYMBOL(page_symlink_inode_operations);
EXPORT_SYMBOL(kern_path);
EXPORT_SYMBOL(vfs_path_lookup);
EXPORT_SYMBOL(inode_permission);
EXPORT_SYMBOL(unlock_rename);
EXPORT_SYMBOL(vfs_create);
EXPORT_SYMBOL(vfs_link);
EXPORT_SYMBOL(vfs_mkdir);
EXPORT_SYMBOL(vfs_mknod);
EXPORT_SYMBOL(generic_permission);
EXPORT_SYMBOL(vfs_readlink);
EXPORT_SYMBOL(vfs_rename);
EXPORT_SYMBOL(vfs_rmdir);
EXPORT_SYMBOL(vfs_symlink);
EXPORT_SYMBOL(vfs_unlink);
EXPORT_SYMBOL(dentry_unhash);
EXPORT_SYMBOL(generic_readlink);
