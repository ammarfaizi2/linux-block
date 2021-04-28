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

/*
 * Mark the backing file as being a cache file if it's not already in use so.
 */
static bool cachefiles_mark_inode_in_use(struct cachefiles_object *object)
{
	struct dentry *dentry = object->dentry;
	struct inode *inode = d_backing_inode(dentry);
	bool can_use = false;

	_enter(",%x", object->debug_id);

	inode_lock(inode);

	if (!(inode->i_flags & S_CACHE_FILE)) {
		inode->i_flags |= S_CACHE_FILE;
		trace_cachefiles_mark_active(object, dentry);
		can_use = true;
	} else {
		pr_notice("cachefiles: Inode already in use: %pd\n", dentry);
	}

	inode_unlock(inode);
	return can_use;
}

/*
 * Unmark a backing inode.
 */
void cachefiles_unmark_inode_in_use(struct cachefiles_object *object)
{
	struct inode *inode = d_backing_inode(object->dentry);

	inode_lock(inode);
	inode->i_flags &= ~S_CACHE_FILE;
	inode_unlock(inode);
	trace_cachefiles_mark_inactive(object, object->dentry, inode);
}

/*
 * Mark an object as being inactive.
 */
static void cachefiles_mark_object_inactive(struct cachefiles_cache *cache,
					    struct cachefiles_object *object)
{
	blkcnt_t i_blocks = d_backing_inode(object->dentry)->i_blocks;

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
static int cachefiles_bury_object(struct cachefiles_cache *cache,
				  struct cachefiles_object *object,
				  struct dentry *dir,
				  struct dentry *rep,
				  enum fscache_why_object_killed why)
{
	struct dentry *grave, *trap;
	struct path path;
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

		path.mnt = cache->cache_path.mnt;
		path.dentry = dir;
		ret = security_path_unlink(&path, rep);
		if (ret < 0) {
			cachefiles_io_error(cache, "Unlink security error");
		} else {
			trace_cachefiles_unlink(object, rep, why);
			ret = vfs_unlink(&init_user_ns, d_inode(dir), rep, NULL);
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
	trap = lock_rename(cache->graveyard_path.dentry, dir);

	/* do some checks before getting the grave dentry */
	if (rep->d_parent != dir || IS_DEADDIR(d_inode(rep))) {
		/* the entry was probably culled when we dropped the parent dir
		 * lock */
		unlock_rename(cache->graveyard_path.dentry, dir);
		_leave(" = 0 [culled?]");
		return 0;
	}

	if (!d_can_lookup(cache->graveyard_path.dentry)) {
		unlock_rename(cache->graveyard_path.dentry, dir);
		cachefiles_io_error(cache, "Graveyard no longer a directory");
		return -EIO;
	}

	if (trap == rep) {
		unlock_rename(cache->graveyard_path.dentry, dir);
		cachefiles_io_error(cache, "May not make directory loop");
		return -EIO;
	}

	if (d_mountpoint(rep)) {
		unlock_rename(cache->graveyard_path.dentry, dir);
		cachefiles_io_error(cache, "Mountpoint in cache");
		return -EIO;
	}

	grave = lookup_one_len(nbuffer, cache->graveyard_path.dentry, strlen(nbuffer));
	if (IS_ERR(grave)) {
		unlock_rename(cache->graveyard_path.dentry, dir);

		if (PTR_ERR(grave) == -ENOMEM) {
			_leave(" = -ENOMEM");
			return -ENOMEM;
		}

		cachefiles_io_error(cache, "Lookup error %ld", PTR_ERR(grave));
		return -EIO;
	}

	if (d_is_positive(grave)) {
		unlock_rename(cache->graveyard_path.dentry, dir);
		dput(grave);
		grave = NULL;
		cond_resched();
		goto try_again;
	}

	if (d_mountpoint(grave)) {
		unlock_rename(cache->graveyard_path.dentry, dir);
		dput(grave);
		cachefiles_io_error(cache, "Mountpoint in graveyard");
		return -EIO;
	}

	/* target should not be an ancestor of source */
	if (trap == grave) {
		unlock_rename(cache->graveyard_path.dentry, dir);
		dput(grave);
		cachefiles_io_error(cache, "May not make directory loop");
		return -EIO;
	}

	/* attempt the rename */
	path.mnt = cache->cache_path.mnt;
	path.dentry = dir;
	ret = security_path_rename(&path, rep, &cache->graveyard_path, grave, 0);
	if (ret < 0) {
		cachefiles_io_error(cache, "Rename security error %d", ret);
	} else {
		struct renamedata rd = {
			.old_mnt_userns	= &init_user_ns,
			.old_dir	= d_inode(dir),
			.old_dentry	= rep,
			.new_mnt_userns	= &init_user_ns,
			.new_dir	= d_inode(cache->graveyard_path.dentry),
			.new_dentry	= grave,
		};
		trace_cachefiles_rename(object, rep, grave, why);
		ret = vfs_rename(&rd);
		if (ret != 0 && ret != -ENOMEM)
			cachefiles_io_error(cache,
					    "Rename failed with error %d", ret);
	}

	unlock_rename(cache->graveyard_path.dentry, dir);
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
	struct dentry *dir;
	int ret;

	_enter(",OBJ%x{%pd}", object->debug_id, object->dentry);

	ASSERT(object->dentry);
	ASSERT(d_backing_inode(object->dentry));
	ASSERT(object->dentry->d_parent);

	dir = dget_parent(object->dentry);

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	ret = cachefiles_bury_object(cache, object, dir, object->dentry,
				     FSCACHE_OBJECT_WAS_RETIRED);

	dput(dir);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Walk to a file, creating it if necessary.
 */
static struct dentry *cachefiles_walk_to_file(struct cachefiles_object *object,
					      struct path *dir,
					      const char *name,
					      size_t nlen)
{
	struct cachefiles_cache *cache = object->cache;
	struct dentry *dentry;
	struct inode *dinode = d_backing_inode(dir->dentry);
	int ret;

	inode_lock_nested(dinode, I_MUTEX_PARENT);

	dentry = lookup_one_len(name, dir->dentry, nlen);
	if (IS_ERR(dentry)) {
		trace_cachefiles_lookup(object, dentry, NULL);
		dentry = NULL;
		goto error;
	}

	trace_cachefiles_lookup(object, dentry, d_backing_inode(dentry));

	if (d_is_negative(dentry)) {
		ret = cachefiles_has_space(cache, 1, 0);
		if (ret < 0)
			goto error_dput;

		ret = security_path_mknod(dir, dentry, S_IFREG, 0);
		if (ret < 0)
			goto error_dput;
		ret = vfs_create(&init_user_ns, dinode, dentry, S_IFREG, true);
		trace_cachefiles_create(object, dentry, ret);
		if (ret < 0)
			goto error_dput;

		_debug("create -> %pd{ino=%lu}",
		       dentry, d_backing_inode(dentry)->i_ino);
		object->new = true;

	} else if (!d_is_reg(dentry)) {
		pr_err("inode %lu is not a file\n",
		       d_backing_inode(dentry)->i_ino);
		goto error;
	} else {
		_debug("file -> %pd positive", dentry);
	}

out:
	inode_unlock(dinode);
	return dentry;

error_dput:
	dput(dentry);
error:
	dentry = NULL;
	goto out;
}

/*
 * Walk to a directory, creating it if necessary.
 */
static struct dentry *cachefiles_walk_to_dir(struct cachefiles_object *object,
					     struct path *dir,
					     const char *name,
					     size_t nlen)
{
	struct cachefiles_cache *cache = object->cache;
	struct dentry *dentry;
	struct inode *dinode = d_backing_inode(dir->dentry);
	int ret;

	_enter("%pd,%zu", dir->dentry, nlen);

	inode_lock_nested(dinode, I_MUTEX_PARENT);

	dentry = lookup_one_len(name, dir->dentry, nlen);
	if (IS_ERR(dentry)) {
		trace_cachefiles_lookup(object, dentry, NULL);
		goto error;
	}

	trace_cachefiles_lookup(object, dentry, d_backing_inode(dentry));

	if (d_is_negative(dentry)) {
		_debug("dir -> %pd negative", dentry);
		ret = cachefiles_has_space(cache, 1, 0);
		if (ret < 0)
			goto error_dput;

		ret = security_path_mkdir(dir, dentry, 0);
		if (ret < 0)
			goto error_dput;
		ret = vfs_mkdir(&init_user_ns, dinode, dentry, 0);
		trace_cachefiles_mkdir(object, dentry, ret);
		if (ret < 0)
			goto error_dput;

		if (unlikely(d_unhashed(dentry)))
			goto error_dput;

		_debug("mkdir -> %pd{ino=%lu}",
		       dentry, d_backing_inode(dentry)->i_ino);

	} else if (!d_can_lookup(dentry)) {
		pr_err("inode %lu is not a directory\n",
		       d_backing_inode(dentry)->i_ino);
		goto error;
	} else {
		_debug("dir -> %pd positive", dentry);
	}

out:
	inode_unlock(dinode);
	return dentry;

error_dput:
	dput(dentry);
error:
	dentry = NULL;
	goto out;
}

/*
 * Walk to the volume level directory, creating it if necessary.
 */
static struct dentry *cachefiles_walk_to_volume(struct cachefiles_object *object)
{
	struct fscache_volume *volume = object->cookie->volume;
	struct dentry *dentry;
	char *name;
	size_t len;

	dentry = volume->cache_priv;
	if (dentry)
		return dget(dentry);

	len = volume->key[0];
	name = kmalloc(len + 2, GFP_NOFS);
	if (!name)
		return ERR_PTR(-ENOMEM);
	name[0] = 'I';
	memcpy(name + 1, volume->key + 1, len);
	name[len + 1] = 0;

	dentry = cachefiles_walk_to_dir(object, &object->cache->cache_path,
					name, len + 1);
	kfree(name);
	if (dentry) {
		spin_lock(&volume->lock);
		if (!volume->cache_priv) {
			volume->cache_priv = dget(dentry);
			atomic_inc(&volume->n_accesses); /* Stop wakeups on dec-to-0 */
		}
		spin_unlock(&volume->lock);
	}

	return dentry;
}

/*
 * Check and open the terminal object.
 */
static int cachefiles_check_open_object(struct cachefiles_object *object,
					struct dentry *fan)
{
	struct path path;
	int ret;

	if (!cachefiles_mark_inode_in_use(object))
		return -EBUSY;

	/* if we've found that the terminal object exists, then we need to
	 * check its attributes and delete it if it's out of date */
	if (!object->new) {
		_debug("validate '%pd'", object->dentry);

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
		path.mnt = object->cache->cache_path.mnt;
		path.dentry = object->dentry;
		touch_atime(&path);
	}

	/* open a file interface onto a data file */
	ret = -EIO;
	if (object->dentry->d_sb->s_blocksize > PAGE_SIZE) {
		pr_warn("cachefiles: Block size too large\n");
		goto error_unmark;
	}

	if (!cachefiles_open_object(object))
		goto error_unmark;

	if (object->new)
		object->stage = CACHEFILES_OBJECT_STAGE_LIVE_EMPTY;
	else
		object->stage = CACHEFILES_OBJECT_STAGE_LIVE;
	wake_up_var(&object->stage);
	return 0;

stale:
	cachefiles_unmark_inode_in_use(object);
	inode_lock_nested(d_inode(fan), I_MUTEX_PARENT);
	ret = cachefiles_bury_object(object->cache, object, fan, object->dentry,
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
 * walk from the parent object to the child object through the backing
 * filesystem, creating directories as we go
 */
bool cachefiles_walk_to_object(struct cachefiles_object *object,
			       const char *key)
{
	struct dentry *vol, *fan, *dentry;
	struct path path;
	char hashname[4];
	int ret, nlen;

	_enter("OBJ%x,%s,", object->debug_id, key);

lookup_again:
	path.mnt = object->cache->cache_path.mnt;

	/* Walk over path "cache/vol/fanout/file". */
	vol = cachefiles_walk_to_volume(object);
	if (!vol)
		return false;

	path.dentry = vol;
	nlen = snprintf(hashname, 4, "@%02x", (u8)object->key_hash);
	fan = cachefiles_walk_to_dir(object, &path, hashname, nlen);
	dput(vol);
	if (!fan)
		return false;

	path.dentry = fan;
	dentry = cachefiles_walk_to_file(object, &path, key, strlen(key));
	if (!dentry) {
		dput(fan);
		return false;
	}

	object->dentry = dentry;
	ret = cachefiles_check_open_object(object, fan);
	dput(fan);
	if (ret < 0)
		goto check_error;

	object->new = false;
	_leave(" = t [%lu]", d_backing_inode(object->dentry)->i_ino);
	return true;

check_error:
	if (ret == -ESTALE)
		goto lookup_again;
	if (ret == -EIO)
		cachefiles_io_error(object->cache, "Lookup failed");
	object->stage = CACHEFILES_OBJECT_STAGE_DEAD;
	wake_up_var(&object->stage);
	cachefiles_mark_object_inactive(object->cache, object);
	dput(object->dentry);
	object->dentry = NULL;
	return false;
}

/*
 * get a subdirectory
 */
int cachefiles_get_directory(struct cachefiles_cache *cache,
			     const char *dirname,
			     struct path *_path)
{
	struct dentry *dir = cache->root_path.dentry, *subdir;
	unsigned long start;
	struct path path;
	int ret;

	_enter(",,%s", dirname);

	/* search the current directory for the element name */
	inode_lock(d_inode(dir));

retry:
	start = jiffies;
	subdir = lookup_one_len(dirname, dir, strlen(dirname));
	cachefiles_hist(cachefiles_lookup_histogram, start);
	if (IS_ERR(subdir)) {
		if (PTR_ERR(subdir) == -ENOMEM)
			goto nomem_d_alloc;
		goto lookup_error;
	}

	_debug("subdir -> %pd %s",
	       subdir, d_backing_inode(subdir) ? "positive" : "negative");

	/* we need to create the subdir if it doesn't exist yet */
	if (d_is_negative(subdir)) {
		ret = cachefiles_has_space(cache, 1, 0);
		if (ret < 0)
			goto mkdir_error;

		_debug("attempt mkdir");

		path.mnt = cache->cache_path.mnt;
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
	_path->dentry = subdir;
	_path->mnt = mntget(cache->root_path.mnt);
	return 0;

check_error:
	dput(subdir);
	_leave(" = %d [check]", ret);
	return ret;

mkdir_error:
	inode_unlock(d_inode(dir));
	dput(subdir);
	pr_err("mkdir %s failed with error %d\n", dirname, ret);
	return ret;

lookup_error:
	inode_unlock(d_inode(dir));
	ret = PTR_ERR(subdir);
	pr_err("Lookup %s failed with error %d\n", dirname, ret);
	return ret;

nomem_d_alloc:
	inode_unlock(d_inode(dir));
	_leave(" = -ENOMEM");
	return -ENOMEM;
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
	unsigned long start;
	int ret;

	//_enter(",%pd/,%s",
	//       dir, filename);

	/* look up the victim */
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);

	start = jiffies;
	victim = lookup_one_len(filename, dir, strlen(filename));
	cachefiles_hist(cachefiles_lookup_histogram, start);
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
	if (inode->i_flags & S_CACHE_FILE) {
		ret = -EBUSY;
	} else {
		inode->i_flags |= S_CACHE_FILE;
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

	/*  actually remove the victim */
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
	if (d_inode(victim)->i_flags & S_CACHE_FILE)
		ret = -EBUSY;
	dput(victim);
	//_leave(" = 0");
	return ret;
}

/*
 * Attempt to link a temporary file into its rightful place in the cache.
 */
bool cachefiles_commit_tmpfile(struct cachefiles_cache *cache,
			       struct cachefiles_object *object)
{
	struct dentry *dir, *dentry, *old;
	char *name;
	unsigned int namelen;
	bool success = false;
	int ret;

	_enter(",%pd", object->old);

	namelen = object->old->d_name.len;
	name = kmemdup_nul(object->old->d_name.name, namelen, GFP_KERNEL);
	if (!name)
		goto out;

	dir = dget_parent(object->old);

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	ret = cachefiles_bury_object(cache, object, dir, object->old,
				     FSCACHE_OBJECT_IS_STALE);
	dput(object->old);
	object->old = NULL;
	if (ret < 0 && ret != -ENOENT) {
		_debug("bury fail %d", ret);
		goto out_name;
	}

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	dentry = lookup_one_len(name, dir, namelen);
	if (IS_ERR(dentry)) {
		_debug("lookup fail %ld", PTR_ERR(dentry));
		goto out_unlock;
	}

	ret = vfs_link(object->dentry, &init_user_ns, d_inode(dir), dentry, NULL);
	if (ret < 0) {
		_debug("link fail %d", ret);
		dput(dentry);
	} else {
		trace_cachefiles_link(object, d_inode(object->dentry));
		spin_lock(&object->lock);
		old = object->dentry;
		object->dentry = dentry;
		success = true;
		clear_bit(CACHEFILES_OBJECT_USING_TMPFILE, &object->flags);
		spin_unlock(&object->lock);
		dput(old);
	}

out_unlock:
	inode_unlock(d_inode(dir));
out_name:
	kfree(name);
	dput(dir);
out:
	_leave(" = %u", success);
	return success;
}
