// SPDX-License-Identifier: GPL-2.0-or-later
/* CacheFiles path walking and related routines
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
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

#define CACHEFILES_KEYBUF_SIZE 512

/*
 * Mark the backing file as being a cache file if it's not already in use so.
 */
static bool cachefiles_mark_inode_in_use(struct cachefiles_object *object)
{
	struct inode *inode = file_inode(object->file);
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
void cachefiles_unmark_inode_in_use(struct cachefiles_object *object)
{
	struct inode *inode = file_inode(object->file);

	inode_lock(inode);
	inode->i_flags &= ~S_KERNEL_FILE;
	inode_unlock(inode);
	trace_cachefiles_mark_inactive(object, inode);
}

/*
 * Mark an object as being inactive.
 */
static void cachefiles_mark_object_inactive(struct cachefiles_cache *cache,
					    struct cachefiles_object *object)
{
	blkcnt_t i_blocks = file_inode(object->file)->i_blocks;

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
 * - unlocks the directory mutex
 */
static int cachefiles_bury_object(struct cachefiles_cache *cache,
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
			ret = vfs_unlink(&init_user_ns, d_inode(dir), rep, NULL);
			dput(rep);
		}

		inode_unlock(d_inode(dir));

		if (ret == -EIO)
			cachefiles_io_error(cache, "Unlink failed");

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
		ret = vfs_rename(&rd);
		if (ret != 0 && ret != -ENOMEM)
			cachefiles_io_error(cache,
					    "Rename failed with error %d", ret);
	}

	unlock_rename(cache->graveyard, dir);
	dput(grave);
	_leave(" = 0");
	return 0;
}

/*
 * delete an object representation from the cache
 */
int cachefiles_delete_object(struct cachefiles_cache *cache,
			     struct cachefiles_object *object)
{
	struct dentry *dentry = object->file->f_path.dentry, *dir;
	int ret;

	_enter(",OBJ%x{%pD}", object->debug_id, object->file);

	ASSERT(d_backing_inode(dentry));
	ASSERT(dentry->d_parent);

	dir = dget_parent(dentry);

	inode_lock_nested(d_backing_inode(dir), I_MUTEX_PARENT);

	/* We need to check that our parent is _still_ our parent - it may have
	 * been renamed.
	 */
	if (dir == dentry->d_parent) {
		ret = cachefiles_bury_object(cache, object, dir, dentry,
					     FSCACHE_OBJECT_WAS_RETIRED);
	} else {
		/* It got moved, presumably by cachefilesd culling it, so it's
		 * no longer in the key path and we can ignore it.
		 */
		inode_unlock(d_backing_inode(dir));
		ret = 0;
	}

	dput(dir);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Check and open the terminal object.
 */
static int cachefiles_check_open_object(struct cachefiles_cache *cache,
					struct cachefiles_object *object,
					struct dentry *fan)
{
	int ret;

	if (!cachefiles_mark_inode_in_use(object))
		return -EBUSY;

	/* if we've found that the terminal object exists, then we need to
	 * check its attributes and delete it if it's out of date */
	if (!object->new) {
		_debug("validate '%pD'", object->file);

		ret = cachefiles_check_auxdata(object);
		if (ret == -ESTALE)
			goto stale;
		if (ret < 0)
			goto error_unmark;
	}

	_debug("=== OBTAINED_OBJECT ===");

	if (object->new) {
		/* attach data to a newly constructed terminal object */
		ret = cachefiles_set_object_xattr(object);
		if (ret < 0)
			goto error_unmark;
	} else {
		/* always update the atime on an object we've just looked up
		 * (this is used to keep track of culling, and atimes are only
		 * updated by read, write and readdir but not lookup or
		 * open) */
		touch_atime(&object->file->f_path);
	}

	return 0;

stale:
	cachefiles_unmark_inode_in_use(object);
	inode_lock_nested(d_inode(fan), I_MUTEX_PARENT);
	ret = cachefiles_bury_object(cache, object, fan,
				     object->file->f_path.dentry,
				     FSCACHE_OBJECT_IS_STALE);
	if (ret < 0)
		return ret;
	_debug("redo lookup");
	return -ESTALE;

error_unmark:
	cachefiles_unmark_inode_in_use(object);
	return ret;
}

/*
 * Walk to a file, creating it if necessary.
 */
static int cachefiles_open_file(struct cachefiles_cache *cache,
				struct cachefiles_object *object,
				struct dentry *fan)
{
	struct dentry *dentry;
	struct inode *dinode = d_backing_inode(fan), *inode;
	struct file *file;
	struct path fan_path, path;
	int ret;

	_enter("%pd %s", fan, object->d_name);

	inode_lock_nested(dinode, I_MUTEX_PARENT);

	dentry = lookup_one_len(object->d_name, fan, object->d_name_len);
	trace_cachefiles_lookup(object, dentry);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto error_unlock;
	}

	if (d_is_negative(dentry)) {
		/* This element of the path doesn't exist, so we can release
		 * any readers in the certain knowledge that there's nothing
		 * for them to actually read */
		fscache_object_lookup_negative(object);

		ret = cachefiles_has_space(cache, 1, 0);
		if (ret < 0) {
			fscache_object_mark_killed(object, FSCACHE_OBJECT_NO_SPACE);
			goto error_dput;
		}

		fan_path.mnt = cache->mnt;
		fan_path.dentry = fan;
		ret = security_path_mknod(&fan_path, dentry, S_IFREG, 0);
		if (ret < 0)
			goto error_dput;
		ret = vfs_create(&init_user_ns, dinode, dentry, S_IFREG, true);
		trace_cachefiles_create(object, dentry, ret);
		if (ret < 0)
			goto error_dput;

		inode = d_backing_inode(dentry);
		_debug("create -> %pd{ino=%lu}", dentry, inode->i_ino);

	} else if (!d_is_reg(dentry)) {
		inode = d_backing_inode(dentry);
		pr_err("inode %lu is not a file\n", inode->i_ino);
		ret = -EIO;
		goto error_dput;
	} else {
		inode = d_backing_inode(dentry);
		_debug("file -> %pd positive", dentry);
	}

	inode_unlock(dinode);

	/* We need to open a file interface onto a data file now as we can't do
	 * it on demand because writeback called from do_exit() sees
	 * current->fs == NULL - which breaks d_path() called from ext4 open.
	 */
	path.mnt = cache->mnt;
	path.dentry = dentry;
	file = open_with_fake_path(&path, O_RDWR | O_LARGEFILE | O_DIRECT,
				   inode, cache->cache_cred);
	dput(dentry);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto error;
	}
	if (unlikely(!file->f_op->read_iter) ||
	    unlikely(!file->f_op->write_iter)) {
		pr_notice("Cache does not support read_iter and write_iter\n");
		ret = -EIO;
		goto error_fput;
	}

	object->file = file;
	return 0;

error_dput:
	dput(dentry);
error_unlock:
	inode_unlock(dinode);
	return ret;
error_fput:
	fput(file);
error:
	return ret;
}

/*
 * Walk over the fanout directory.
 */
static struct dentry *cachefiles_walk_over_fanout(struct cachefiles_object *object,
						  struct cachefiles_cache *cache,
						  struct dentry *dir)
{
	char name[4];

	snprintf(name, sizeof(name), "@%02x", object->key_hash);
	return cachefiles_get_directory(cache, dir, name, object);
}

/*
 * walk from the parent object to the child object through the backing
 * filesystem, creating directories as we go
 */
int cachefiles_walk_to_object(struct cachefiles_object *parent,
			      struct cachefiles_object *object)
{
	struct cachefiles_cache *cache;
	struct dentry *fan;
	int ret;

	_enter("OBJ%x{%pD},OBJ%x,%s,",
	       parent->debug_id, parent->file,
	       object->debug_id, object->d_name);

	cache = container_of(parent->cache, struct cachefiles_cache, cache);
	ASSERT(parent->file);

lookup_again:
	fan = cachefiles_walk_over_fanout(object, cache, parent->file->f_path.dentry);
	if (IS_ERR(fan))
		return PTR_ERR(fan);

	/* Open path "parent/fanout/object". */
	if (object->type == FSCACHE_COOKIE_TYPE_INDEX) {
		struct dentry *dentry;
		struct file *file;
		struct path path;

		dentry = cachefiles_get_directory(cache, fan, object->d_name,
						  object);
		if (IS_ERR(dentry)) {
			dput(fan);
			return PTR_ERR(dentry);
		}
		path.mnt = cache->mnt;
		path.dentry = dentry;
		file = open_with_fake_path(&path, O_RDONLY | O_DIRECTORY,
					   d_backing_inode(dentry),
					   cache->cache_cred);
		dput(dentry);
		if (IS_ERR(file)) {
			dput(fan);
			return PTR_ERR(file);
		}
		object->file = file;
	} else {
		ret = cachefiles_open_file(cache, object, fan);
		if (ret < 0) {
			dput(fan);
			return ret;
		}
	}

	ret = cachefiles_check_open_object(cache, object, fan);
	dput(fan);
	fan = NULL;
	if (ret < 0)
		goto check_error;

	object->new = false;
	fscache_obtained_object(object);
	_leave(" = t [%lu]", file_inode(object->file)->i_ino);
	return true;

check_error:
	fput(object->file);
	object->file = NULL;
	if (ret == -ESTALE)
		goto lookup_again;
	if (ret == -EIO)
		cachefiles_io_error_obj(object, "Lookup failed");
	cachefiles_mark_object_inactive(cache, object);
	_leave(" = error %d", ret);
	return ret;
}

/*
 * get a subdirectory
 */
struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					struct dentry *dir,
					const char *dirname,
					struct cachefiles_object *object)
{
	struct dentry *subdir;
	struct path path;
	int ret;

	_enter(",,%s", dirname);

	/* search the current directory for the element name */
	inode_lock(d_inode(dir));

retry:
	subdir = lookup_one_len(dirname, dir, strlen(dirname));
	if (IS_ERR(subdir)) {
		if (PTR_ERR(subdir) == -ENOMEM)
			goto nomem_d_alloc;
		goto lookup_error;
	}

	_debug("subdir -> %pd %s",
	       subdir, d_backing_inode(subdir) ? "positive" : "negative");

	/* we need to create the subdir if it doesn't exist yet */
	if (d_is_negative(subdir)) {
		/* This element of the path doesn't exist, so we can release
		 * any readers in the certain knowledge that there's nothing
		 * for them to actually read */
		if (object)
			fscache_object_lookup_negative(object);

		ret = cachefiles_has_space(cache, 1, 0);
		if (ret < 0)
			goto mkdir_error;

		_debug("attempt mkdir");

		path.mnt = cache->mnt;
		path.dentry = dir;
		ret = security_path_mkdir(&path, subdir, 0700);
		if (ret < 0)
			goto mkdir_error;
		ret = vfs_mkdir(&init_user_ns, d_inode(dir), subdir, 0700);
		if (ret < 0)
			goto mkdir_error;

		if (unlikely(d_unhashed(subdir))) {
			dput(subdir);
			goto retry;
		}
		ASSERT(d_backing_inode(subdir));

		_debug("mkdir -> %pd{ino=%lu}",
		       subdir, d_backing_inode(subdir)->i_ino);
		if (object)
			object->new = true;
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
	    !d_backing_inode(subdir)->i_op->create ||
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

	ret = cachefiles_remove_object_xattr(cache, victim);
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
