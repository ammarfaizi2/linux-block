// SPDX-License-Identifier: GPL-2.0-or-later
/* CacheFiles path walking and related routines
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/quotaops.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * Mark the backing file as being a cache file if it's not already in use so.
 */
static bool cachefiles_mark_inode_in_use(struct cachefiles_object *object,
					 struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	bool can_use = false;

	_enter(",%x", object->debug_id);

	inode_lock(inode);

	if (!(inode->i_flags & S_KERNEL_FILE)) {
		inode->i_flags |= S_KERNEL_FILE;
		trace_cachefiles_mark_active(object, inode);
		can_use = true;
	} else {
		pr_notice("cachefiles: Inode already in use: %pD\n", object->file);
	}

	inode_unlock(inode);
	return can_use;
}

/*
 * Unmark a backing inode.
 */
void cachefiles_unmark_inode_in_use(struct cachefiles_object *object,
				    struct file *file)
{
	struct inode *inode = file_inode(file);

	if (!inode)
		return;

	inode_lock(inode);
	inode->i_flags &= ~S_KERNEL_FILE;
	inode_unlock(inode);
	trace_cachefiles_mark_inactive(object, inode);
}

/*
 * Mark an object as being inactive.
 */
static void cachefiles_mark_object_inactive(struct cachefiles_object *object,
					    struct file *file)
{
	struct cachefiles_cache *cache = object->volume->cache;
	blkcnt_t i_blocks = file_inode(file)->i_blocks;

	/* This object can now be culled, so we need to let the daemon know
	 * that there is something it can remove if it needs to.
	 */
	atomic_long_add(i_blocks, &cache->b_released);
	if (atomic_inc_return(&cache->f_released))
		cachefiles_state_changed(cache);
}

/*
 * delete an object representation from the cache
 * - file backed objects are unlinked
 * - directory backed objects are stuffed into the graveyard for userspace to
 *   delete
 */
int cachefiles_bury_object(struct cachefiles_cache *cache,
			   struct cachefiles_object *object,
			   struct dentry *dir,
			   struct dentry *rep,
			   enum fscache_why_object_killed why)
{
	struct dentry *grave, *trap;
	struct path path, path_to_graveyard;
	char nbuffer[8 + 8 + 1];
	int ret;

	_enter(",'%pd','%pd'", dir, rep);

	if (rep->d_parent != dir) {
		inode_unlock(d_inode(dir));
		_leave(" = -ESTALE");
		return -ESTALE;
	}

	/* non-directories can just be unlinked */
	if (!d_is_dir(rep)) {
		_debug("unlink stale object");

		path.mnt = cache->mnt;
		path.dentry = dir;
		ret = security_path_unlink(&path, rep);
		if (ret < 0) {
			cachefiles_io_error(cache, "Unlink security error");
		} else {
			trace_cachefiles_unlink(object, rep, why);
			dget(rep); /* Stop the dentry being negated if it's
				    * only pinned by a file struct.
				    */
			ret = cachefiles_inject_remove_error();
			if (ret == 0)
				ret = vfs_unlink(&init_user_ns, d_inode(dir), rep, NULL);
			dput(rep);
		}

		inode_unlock(d_inode(dir));

		if (ret < 0) {
			trace_cachefiles_vfs_error(object, d_inode(dir), ret,
						   cachefiles_trace_unlink_error);
			if (ret == -EIO)
				cachefiles_io_error(cache, "Unlink failed");
		}

		_leave(" = %d", ret);
		return ret;
	}

	/* directories have to be moved to the graveyard */
	_debug("move stale object to graveyard");
	inode_unlock(d_inode(dir));

try_again:
	/* first step is to make up a grave dentry in the graveyard */
	sprintf(nbuffer, "%08x%08x",
		(uint32_t) ktime_get_real_seconds(),
		(uint32_t) atomic_inc_return(&cache->gravecounter));

	/* do the multiway lock magic */
	trap = lock_rename(cache->graveyard, dir);

	/* do some checks before getting the grave dentry */
	if (rep->d_parent != dir || IS_DEADDIR(d_inode(rep))) {
		/* the entry was probably culled when we dropped the parent dir
		 * lock */
		unlock_rename(cache->graveyard, dir);
		_leave(" = 0 [culled?]");
		return 0;
	}

	if (!d_can_lookup(cache->graveyard)) {
		unlock_rename(cache->graveyard, dir);
		cachefiles_io_error(cache, "Graveyard no longer a directory");
		return -EIO;
	}

	if (trap == rep) {
		unlock_rename(cache->graveyard, dir);
		cachefiles_io_error(cache, "May not make directory loop");
		return -EIO;
	}

	if (d_mountpoint(rep)) {
		unlock_rename(cache->graveyard, dir);
		cachefiles_io_error(cache, "Mountpoint in cache");
		return -EIO;
	}

	grave = lookup_one_len(nbuffer, cache->graveyard, strlen(nbuffer));
	if (IS_ERR(grave)) {
		unlock_rename(cache->graveyard, dir);
		trace_cachefiles_vfs_error(object, d_inode(cache->graveyard),
					   PTR_ERR(grave),
					   cachefiles_trace_lookup_error);

		if (PTR_ERR(grave) == -ENOMEM) {
			_leave(" = -ENOMEM");
			return -ENOMEM;
		}

		cachefiles_io_error(cache, "Lookup error %ld", PTR_ERR(grave));
		return -EIO;
	}

	if (d_is_positive(grave)) {
		unlock_rename(cache->graveyard, dir);
		dput(grave);
		grave = NULL;
		cond_resched();
		goto try_again;
	}

	if (d_mountpoint(grave)) {
		unlock_rename(cache->graveyard, dir);
		dput(grave);
		cachefiles_io_error(cache, "Mountpoint in graveyard");
		return -EIO;
	}

	/* target should not be an ancestor of source */
	if (trap == grave) {
		unlock_rename(cache->graveyard, dir);
		dput(grave);
		cachefiles_io_error(cache, "May not make directory loop");
		return -EIO;
	}

	/* attempt the rename */
	path.mnt = cache->mnt;
	path.dentry = dir;
	path_to_graveyard.mnt = cache->mnt;
	path_to_graveyard.dentry = cache->graveyard;
	ret = security_path_rename(&path, rep, &path_to_graveyard, grave, 0);
	if (ret < 0) {
		cachefiles_io_error(cache, "Rename security error %d", ret);
	} else {
		struct renamedata rd = {
			.old_mnt_userns	= &init_user_ns,
			.old_dir	= d_inode(dir),
			.old_dentry	= rep,
			.new_mnt_userns	= &init_user_ns,
			.new_dir	= d_inode(cache->graveyard),
			.new_dentry	= grave,
		};
		trace_cachefiles_rename(object, rep, grave, why);
		ret = cachefiles_inject_read_error();
		if (ret == 0)
			ret = vfs_rename(&rd);
		if (ret != 0)
			trace_cachefiles_vfs_error(object, d_inode(dir),
						   PTR_ERR(grave),
						   cachefiles_trace_rename_error);
		if (ret != 0 && ret != -ENOMEM)
			cachefiles_io_error(cache,
					    "Rename failed with error %d", ret);
	}

	unlock_rename(cache->graveyard, dir);
	dput(grave);
	_leave(" = 0");
	return 0;
}

static int cachefiles_unlink(struct cachefiles_object *object,
			     struct dentry *fan, struct dentry *dentry,
			     enum fscache_why_object_killed why)
{
	struct path path = {
		.mnt	= object->volume->cache->mnt,
		.dentry	= fan,
	};
	int ret;

	trace_cachefiles_unlink(object, dentry, why);
	ret = security_path_unlink(&path, dentry);
	if (ret == 0)
		ret = cachefiles_inject_remove_error();
	if (ret == 0)
		ret = vfs_unlink(&init_user_ns, d_backing_inode(fan), dentry, NULL);
	if (ret != 0)
		trace_cachefiles_vfs_error(object, d_backing_inode(fan), ret,
					   cachefiles_trace_unlink_error);
	return ret;
}

/*
 * Delete a cache file.
 */
int cachefiles_delete_object(struct cachefiles_object *object,
			     enum fscache_why_object_killed why)
{
	struct cachefiles_volume *volume = object->volume;
	struct dentry *dentry = object->file->f_path.dentry;
	struct dentry *fan = volume->fanout[(u8)object->key_hash];
	int ret;

	_enter(",OBJ%x{%pD}", object->debug_id, object->file);

	/* Stop the dentry being negated if it's only pinned by a file struct. */
	dget(dentry);

	inode_lock_nested(d_backing_inode(fan), I_MUTEX_PARENT);
	ret = cachefiles_unlink(object, fan, dentry, why);
	inode_unlock(d_backing_inode(fan));
	dput(dentry);

	if (ret < 0)
		trace_cachefiles_vfs_error(object, d_backing_inode(fan), ret,
					   cachefiles_trace_unlink_error);
	if (ret < 0 && ret != -ENOENT)
		cachefiles_io_error(volume->cache, "Unlink failed");
	return ret;
}

/*
 * Create a new file.
 */
static bool cachefiles_create_file(struct cachefiles_object *object)
{
	struct file *file;
	int ret;

	ret = cachefiles_has_space(object->volume->cache, 1, 0);
	if (ret < 0)
		return false;

	file = cachefiles_create_tmpfile(object);
	if (IS_ERR(file))
		return false;

	set_bit(FSCACHE_COOKIE_NEEDS_UPDATE, &object->cookie->flags);
	set_bit(CACHEFILES_OBJECT_USING_TMPFILE, &object->flags);
	_debug("create -> %pD{ino=%lu}", file, file_inode(file)->i_ino);
	object->file = file;
	return true;
}

/*
 * Open an existing file, checking its attributes and replacing it if it is
 * stale.
 */
static bool cachefiles_open_file(struct cachefiles_object *object,
				 struct dentry *dentry)
{
	struct cachefiles_cache *cache = object->volume->cache;
	struct file *file;
	struct path path;
	int ret;

	_enter("%pd", dentry);

	if (!cachefiles_mark_inode_in_use(object, dentry))
		return false;

	/* We need to open a file interface onto a data file now as we can't do
	 * it on demand because writeback called from do_exit() sees
	 * current->fs == NULL - which breaks d_path() called from ext4 open.
	 */
	path.mnt = cache->mnt;
	path.dentry = dentry;
	file = open_with_fake_path(&path, O_RDWR | O_LARGEFILE | O_DIRECT,
				   d_backing_inode(dentry), cache->cache_cred);
	if (IS_ERR(file)) {
		trace_cachefiles_vfs_error(object, d_backing_inode(dentry),
					   PTR_ERR(file),
					   cachefiles_trace_open_error);
		goto error;
	}

	if (unlikely(!file->f_op->read_iter) ||
	    unlikely(!file->f_op->write_iter)) {
		pr_notice("Cache does not support read_iter and write_iter\n");
		goto error_fput;
	}
	_debug("file -> %pd positive", dentry);

	ret = cachefiles_check_auxdata(object, file);
	if (ret < 0)
		goto check_failed;

	object->file = file;

	/* Always update the atime on an object we've just looked up (this is
	 * used to keep track of culling, and atimes are only updated by read,
	 * write and readdir but not lookup or open).
	 */
	touch_atime(&file->f_path);
	dput(dentry);
	return true;

check_failed:
	fscache_cookie_lookup_negative(object->cookie);
	cachefiles_unmark_inode_in_use(object, file);
	cachefiles_mark_object_inactive(object, file);
	if (ret == -ESTALE) {
		fput(file);
		dput(dentry);
		return cachefiles_create_file(object);
	}
error_fput:
	fput(file);
error:
	dput(dentry);
	return false;
}

/*
 * walk from the parent object to the child object through the backing
 * filesystem, creating directories as we go
 */
bool cachefiles_look_up_object(struct cachefiles_object *object)
{
	struct cachefiles_volume *volume = object->volume;
	struct dentry *dentry, *fan = volume->fanout[(u8)object->key_hash];
	int ret;

	_enter("OBJ%x,%s,", object->debug_id, object->d_name);

	/* Look up path "cache/vol/fanout/file". */
	ret = cachefiles_inject_read_error();
	if (ret == 0)
		dentry = lookup_positive_unlocked(object->d_name, fan,
						  object->d_name_len);
	else
		dentry = ERR_PTR(ret);
	trace_cachefiles_lookup(object, dentry);
	if (IS_ERR(dentry)) {
		if (dentry == ERR_PTR(-ENOENT))
			goto new_file;
		if (dentry == ERR_PTR(-EIO))
			cachefiles_io_error_obj(object, "Lookup failed");
		return false;
	}

	if (!d_is_reg(dentry)) {
		pr_err("%pd is not a file\n", dentry);
		inode_lock_nested(d_inode(fan), I_MUTEX_PARENT);
		ret = cachefiles_bury_object(volume->cache, object, fan, dentry,
					     FSCACHE_OBJECT_IS_WEIRD);
		dput(dentry);
		if (ret < 0)
			return false;
		goto new_file;
	}

	if (!cachefiles_open_file(object, dentry))
		return false;

	_leave(" = t [%lu]", file_inode(object->file)->i_ino);
	return true;

new_file:
	fscache_cookie_lookup_negative(object->cookie);
	return cachefiles_create_file(object);
}

/*
 * get a subdirectory
 */
struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					struct dentry *dir,
					const char *dirname)
{
	struct dentry *subdir;
	struct path path;
	int ret;

	_enter(",,%s", dirname);

	/* search the current directory for the element name */
	inode_lock(d_inode(dir));

retry:
	ret = cachefiles_inject_read_error();
	if (ret == 0)
		subdir = lookup_one_len(dirname, dir, strlen(dirname));
	else
		subdir = ERR_PTR(ret);
	if (IS_ERR(subdir)) {
		trace_cachefiles_vfs_error(NULL, d_backing_inode(dir),
					   PTR_ERR(subdir),
					   cachefiles_trace_lookup_error);
		if (PTR_ERR(subdir) == -ENOMEM)
			goto nomem_d_alloc;
		goto lookup_error;
	}

	_debug("subdir -> %pd %s",
	       subdir, d_backing_inode(subdir) ? "positive" : "negative");

	/* we need to create the subdir if it doesn't exist yet */
	if (d_is_negative(subdir)) {
		if (cache->store) {
			ret = cachefiles_has_space(cache, 1, 0);
			if (ret < 0)
				goto mkdir_error;
		}

		_debug("attempt mkdir");

		path.mnt = cache->mnt;
		path.dentry = dir;
		ret = security_path_mkdir(&path, subdir, 0700);
		if (ret < 0)
			goto mkdir_error;
		ret = cachefiles_inject_write_error();
		if (ret == 0)
			ret = vfs_mkdir(&init_user_ns, d_inode(dir), subdir, 0700);
		if (ret < 0) {
			trace_cachefiles_vfs_error(NULL, d_inode(dir), ret,
						   cachefiles_trace_mkdir_error);
			goto mkdir_error;
		}

		if (unlikely(d_unhashed(subdir))) {
			dput(subdir);
			goto retry;
		}
		ASSERT(d_backing_inode(subdir));

		_debug("mkdir -> %pd{ino=%lu}",
		       subdir, d_backing_inode(subdir)->i_ino);
	}

	inode_unlock(d_inode(dir));

	/* we need to make sure the subdir is a directory */
	ASSERT(d_backing_inode(subdir));

	if (!d_can_lookup(subdir)) {
		pr_err("%s is not a directory\n", dirname);
		ret = -EIO;
		goto check_error;
	}

	ret = -EPERM;
	if (!(d_backing_inode(subdir)->i_opflags & IOP_XATTR) ||
	    !d_backing_inode(subdir)->i_op->lookup ||
	    !d_backing_inode(subdir)->i_op->mkdir ||
	    !d_backing_inode(subdir)->i_op->rename ||
	    !d_backing_inode(subdir)->i_op->rmdir ||
	    !d_backing_inode(subdir)->i_op->unlink)
		goto check_error;

	_leave(" = [%lu]", d_backing_inode(subdir)->i_ino);
	return subdir;

check_error:
	dput(subdir);
	_leave(" = %d [check]", ret);
	return ERR_PTR(ret);

mkdir_error:
	inode_unlock(d_inode(dir));
	dput(subdir);
	pr_err("mkdir %s failed with error %d\n", dirname, ret);
	return ERR_PTR(ret);

lookup_error:
	inode_unlock(d_inode(dir));
	ret = PTR_ERR(subdir);
	pr_err("Lookup %s failed with error %d\n", dirname, ret);
	return ERR_PTR(ret);

nomem_d_alloc:
	inode_unlock(d_inode(dir));
	_leave(" = -ENOMEM");
	return ERR_PTR(-ENOMEM);
}

/*
 * find out if an object is in use or not
 * - if finds object and it's not in use:
 *   - returns a pointer to the object and a reference on it
 *   - returns with the directory locked
 */
static struct dentry *cachefiles_check_active(struct cachefiles_cache *cache,
					      struct dentry *dir,
					      char *filename)
{
	struct dentry *victim;
	int ret;

	//_enter(",%pd/,%s",
	//       dir, filename);

	/* look up the victim */
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);

	victim = lookup_one_len(filename, dir, strlen(filename));
	if (IS_ERR(victim))
		goto lookup_error;

	//_debug("victim -> %pd %s",
	//       victim, d_backing_inode(victim) ? "positive" : "negative");

	/* if the object is no longer there then we probably retired the object
	 * at the netfs's request whilst the cull was in progress
	 */
	if (d_is_negative(victim)) {
		inode_unlock(d_inode(dir));
		dput(victim);
		_leave(" = -ENOENT [absent]");
		return ERR_PTR(-ENOENT);
	}

	//_leave(" = %pd", victim);
	return victim;

lookup_error:
	inode_unlock(d_inode(dir));
	ret = PTR_ERR(victim);
	if (ret == -ENOENT) {
		/* file or dir now absent - probably retired by netfs */
		_leave(" = -ESTALE [absent]");
		return ERR_PTR(-ESTALE);
	}

	if (ret == -EIO) {
		cachefiles_io_error(cache, "Lookup failed");
	} else if (ret != -ENOMEM) {
		pr_err("Internal error: %d\n", ret);
		ret = -EIO;
	}

	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

/*
 * cull an object if it's not in use
 * - called only by cache manager daemon
 */
int cachefiles_cull(struct cachefiles_cache *cache, struct dentry *dir,
		    char *filename)
{
	struct dentry *victim;
	struct inode *inode;
	int ret;

	_enter(",%pd/,%s", dir, filename);

	victim = cachefiles_check_active(cache, dir, filename);
	if (IS_ERR(victim))
		return PTR_ERR(victim);

	/* check to see if someone is using this object */
	inode = d_inode(victim);
	inode_lock(inode);
	if (inode->i_flags & S_KERNEL_FILE) {
		ret = -EBUSY;
	} else {
		inode->i_flags |= S_KERNEL_FILE;
		ret = 0;
	}
	inode_unlock(inode);
	if (ret < 0)
		goto error_unlock;

	_debug("victim -> %pd %s",
	       victim, d_backing_inode(victim) ? "positive" : "negative");

	/* okay... the victim is not being used so we can cull it
	 * - start by marking it as stale
	 */
	_debug("victim is cullable");

	ret = cachefiles_remove_object_xattr(cache, NULL, victim);
	if (ret < 0)
		goto error_unlock;

	/*  actually remove the victim (drops the dir mutex) */
	_debug("bury");

	ret = cachefiles_bury_object(cache, NULL, dir, victim,
				     FSCACHE_OBJECT_WAS_CULLED);
	if (ret < 0)
		goto error;

	dput(victim);
	_leave(" = 0");
	return 0;

error_unlock:
	inode_unlock(d_inode(dir));
error:
	dput(victim);
	if (ret == -ENOENT) {
		/* file or dir now absent - probably retired by netfs */
		_leave(" = -ESTALE [absent]");
		return -ESTALE;
	}

	if (ret != -ENOMEM) {
		pr_err("Internal error: %d\n", ret);
		ret = -EIO;
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * find out if an object is in use or not
 * - called only by cache manager daemon
 * - returns -EBUSY or 0 to indicate whether an object is in use or not
 */
int cachefiles_check_in_use(struct cachefiles_cache *cache, struct dentry *dir,
			    char *filename)
{
	struct dentry *victim;
	int ret = 0;

	//_enter(",%pd/,%s",
	//       dir, filename);

	victim = cachefiles_check_active(cache, dir, filename);
	if (IS_ERR(victim))
		return PTR_ERR(victim);

	inode_unlock(d_inode(dir));
	if (d_inode(victim)->i_flags & S_KERNEL_FILE)
		ret = -EBUSY;
	dput(victim);
	//_leave(" = 0");
	return ret;
}

/*
 * Create a temporary file and leave it unattached and un-xattr'd until the
 * time comes to discard the object from memory.
 */
struct file *cachefiles_create_tmpfile(struct cachefiles_object *object)
{
	struct cachefiles_volume *volume = object->volume;
	struct cachefiles_cache *cache = volume->cache;
	const struct cred *saved_cred;
	struct dentry *fan = volume->fanout[(u8)object->key_hash];
	struct file *file;
	struct path path;
	uint64_t ni_size = object->cookie->object_size;
	long ret;

	ni_size = round_up(ni_size, CACHEFILES_DIO_BLOCK_SIZE);

	cachefiles_begin_secure(cache, &saved_cred);

	path.mnt = cache->mnt;
	ret = cachefiles_inject_write_error();
	if (ret == 0)
		path.dentry = vfs_tmpfile(&init_user_ns, fan, S_IFREG, O_RDWR);
	else
		path.dentry = ERR_PTR(ret);
	if (IS_ERR(path.dentry)) {
		trace_cachefiles_vfs_error(object, d_inode(fan), PTR_ERR(path.dentry),
					   cachefiles_trace_tmpfile_error);
		if (PTR_ERR(path.dentry) == -EIO)
			cachefiles_io_error_obj(object, "Failed to create tmpfile");
		file = ERR_CAST(path.dentry);
		goto out;
	}

	trace_cachefiles_tmpfile(object, d_backing_inode(path.dentry));

	if (!cachefiles_mark_inode_in_use(object, path.dentry)) {
		file = ERR_PTR(-EBUSY);
		goto out_dput;
	}

	if (ni_size > 0) {
		trace_cachefiles_trunc(object, d_backing_inode(path.dentry), 0, ni_size,
				       cachefiles_trunc_expand_tmpfile);
		ret = cachefiles_inject_write_error();
		if (ret == 0)
			ret = vfs_truncate(&path, ni_size);
		if (ret < 0) {
			trace_cachefiles_vfs_error(
				object, d_backing_inode(path.dentry), ret,
				cachefiles_trace_trunc_error);
			file = ERR_PTR(ret);
			goto out_dput;
		}
	}

	file = open_with_fake_path(&path, O_RDWR | O_LARGEFILE | O_DIRECT,
				   d_backing_inode(path.dentry), cache->cache_cred);
	if (IS_ERR(file)) {
		trace_cachefiles_vfs_error(object, d_backing_inode(path.dentry),
					   PTR_ERR(file),
					   cachefiles_trace_open_error);
		goto out_dput;
	}
	if (unlikely(!file->f_op->read_iter) ||
	    unlikely(!file->f_op->write_iter)) {
		fput(file);
		pr_notice("Cache does not support read_iter and write_iter\n");
		file = ERR_PTR(-EINVAL);
	}

out_dput:
	dput(path.dentry);
out:
	cachefiles_end_secure(cache, saved_cred);
	return file;
}

/*
 * Attempt to link a temporary file into its rightful place in the cache.
 */
bool cachefiles_commit_tmpfile(struct cachefiles_cache *cache,
			       struct cachefiles_object *object)
{
	struct cachefiles_volume *volume = object->volume;
	struct dentry *dentry, *fan = volume->fanout[(u8)object->key_hash];
	bool success = false;
	int ret;

	_enter(",%pD", object->file);

	inode_lock_nested(d_inode(fan), I_MUTEX_PARENT);
	ret = cachefiles_inject_read_error();
	if (ret == 0)
		dentry = lookup_one_len(object->d_name, fan, object->d_name_len);
	else
		dentry = ERR_PTR(ret);
	if (IS_ERR(dentry)) {
		trace_cachefiles_vfs_error(object, d_inode(fan), PTR_ERR(dentry),
					   cachefiles_trace_lookup_error);
		_debug("lookup fail %ld", PTR_ERR(dentry));
		goto out_unlock;
	}

	if (!d_is_negative(dentry)) {
		if (d_backing_inode(dentry) == file_inode(object->file)) {
			success = true;
			goto out_dput;
		}

		ret = cachefiles_unlink(object, fan, dentry, FSCACHE_OBJECT_IS_STALE);
		if (ret < 0) {
			trace_cachefiles_vfs_error(object, d_inode(fan), ret,
						   cachefiles_trace_unlink_error);
			goto out_dput;
		}

		dput(dentry);
		ret = cachefiles_inject_read_error();
		if (ret == 0)
			dentry = lookup_one_len(object->d_name, fan, object->d_name_len);
		else
			dentry = ERR_PTR(ret);
		if (IS_ERR(dentry)) {
			trace_cachefiles_vfs_error(object, d_inode(fan), PTR_ERR(dentry),
						   cachefiles_trace_lookup_error);
			_debug("lookup fail %ld", PTR_ERR(dentry));
			goto out_unlock;
		}
	}

	ret = cachefiles_inject_read_error();
	if (ret == 0)
		ret = vfs_link(object->file->f_path.dentry, &init_user_ns,
			       d_inode(fan), dentry, NULL);
	if (ret < 0) {
		trace_cachefiles_vfs_error(object, d_inode(fan), PTR_ERR(dentry),
					   cachefiles_trace_link_error);
		_debug("link fail %d", ret);
	} else {
		trace_cachefiles_link(object, file_inode(object->file));
		spin_lock(&object->lock);
		/* TODO: Do we want to switch the file pointer to the new dentry? */
		clear_bit(CACHEFILES_OBJECT_USING_TMPFILE, &object->flags);
		spin_unlock(&object->lock);
		success = true;
	}

out_dput:
	dput(dentry);
out_unlock:
	inode_unlock(d_inode(fan));
	_leave(" = %u", success);
	return success;
}
