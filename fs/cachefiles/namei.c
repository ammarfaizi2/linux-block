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
static bool cachefiles_mark_inode_in_use(struct cachefiles_object *object,
					 struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	bool can_use = false;

	_enter(",%x", object->fscache.debug_id);

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
void cachefiles_unmark_inode_in_use(struct cachefiles_object *object,
				    struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);

	inode_lock(inode);
	inode->i_flags &= ~S_CACHE_FILE;
	inode_unlock(inode);
	trace_cachefiles_mark_inactive(object, dentry, inode);
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
			ret = vfs_unlink(d_inode(dir), rep, NULL);
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
		trace_cachefiles_rename(object, rep, grave, why);
		ret = vfs_rename(d_inode(dir), rep,
				 d_inode(cache->graveyard), grave, NULL, 0);
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
	struct dentry *dir;
	int ret;

	_enter(",OBJ%x{%pd}", object->fscache.debug_id, object->dentry);

	ASSERT(object->dentry);
	ASSERT(d_backing_inode(object->dentry));
	ASSERT(object->dentry->d_parent);

	dir = dget_parent(object->dentry);

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);

	/* We need to check that our parent is _still_ our parent - it may have
	 * been renamed.
	 */
	if (dir == object->dentry->d_parent) {
		ret = cachefiles_bury_object(cache, object, dir, object->dentry,
					     FSCACHE_OBJECT_WAS_RETIRED);
	} else {
		/* It got moved, presumably by cachefilesd culling it, so it's
		 * no longer in the key path and we can ignore it.
		 */
		inode_unlock(d_inode(dir));
		ret = 0;
	}

	dput(dir);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Handle negative lookup.  We create a temporary file for a datafile to use
 * which we will link into place later.
 */
static void cachefiles_negative_lookup(struct cachefiles_object *parent,
				       struct cachefiles_object *object)
{
	// TODO: Use vfs_tmpfile() for datafiles
	//fscache_object_lookup_negative(&object->fscache);
}

/*
 * walk from the parent object to the child object through the backing
 * filesystem, creating directories as we go
 */
bool cachefiles_walk_to_object(struct cachefiles_object *parent,
			       struct cachefiles_object *object,
			       const char *key)
{
	struct cachefiles_cache *cache;
	struct dentry *dir, *next = NULL;
	struct inode *inode;
	struct path path;
	unsigned long start;
	const char *name;
	bool marked = false, negated = false;
	int ret, nlen;

	_enter("OBJ%x{%pd},OBJ%x,%s,",
	       parent->fscache.debug_id, parent->dentry,
	       object->fscache.debug_id, key);

	cache = container_of(parent->fscache.cache,
			     struct cachefiles_cache, cache);
	path.mnt = cache->mnt;

	ASSERT(parent->dentry);
	ASSERT(d_backing_inode(parent->dentry));

	if (!(d_is_dir(parent->dentry))) {
		// TODO: convert file to dir
		_leave("looking up in none directory");
		return false;
	}

	dir = dget(parent->dentry);

advance:
	/* attempt to transit the first directory component */
	name = key;
	nlen = strlen(key);

	/* key ends in a double NUL */
	key = key + nlen + 1;
	if (!*key)
		key = NULL;

lookup_again:
	/* search the current directory for the element name */
	_debug("lookup '%s'", name);

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);

	start = jiffies;
	next = lookup_one_len(name, dir, nlen);
	cachefiles_hist(cachefiles_lookup_histogram, start);
	if (IS_ERR(next)) {
		trace_cachefiles_lookup(object, next, NULL);
		ret = PTR_ERR(next);
		goto lookup_error;
	}

	inode = d_backing_inode(next);
	trace_cachefiles_lookup(object, next, inode);
	_debug("next -> %pd %s", next, inode ? "positive" : "negative");

	if (!key)
		object->new = !inode;

	/* if this element of the path doesn't exist, then the lookup phase
	 * failed, and we can release any readers in the certain knowledge that
	 * there's nothing for them to actually read */
	if (d_is_negative(next) && !negated) {
		cachefiles_negative_lookup(object, parent);
		negated = true;
	}

	/* we need to create the object if it's negative */
	if (key || object->type == FSCACHE_COOKIE_TYPE_INDEX) {
		/* index objects and intervening tree levels must be subdirs */
		if (d_is_negative(next)) {
			ret = cachefiles_has_space(cache, 1, 0);
			if (ret < 0)
				goto no_space_error;

			path.dentry = dir;
			ret = security_path_mkdir(&path, next, 0);
			if (ret < 0)
				goto create_error;
			start = jiffies;
			ret = vfs_mkdir(d_inode(dir), next, 0);
			cachefiles_hist(cachefiles_mkdir_histogram, start);
			if (!key)
				trace_cachefiles_mkdir(object, next, ret);
			if (ret < 0)
				goto create_error;

			if (unlikely(d_unhashed(next))) {
				dput(next);
				inode_unlock(d_inode(dir));
				goto lookup_again;
			}
			ASSERT(d_backing_inode(next));

			_debug("mkdir -> %pd{ino=%lu}",
			       next, d_backing_inode(next)->i_ino);

		} else if (!d_can_lookup(next)) {
			pr_err("inode %lu is not a directory\n",
			       d_backing_inode(next)->i_ino);
			ret = -ENOBUFS;
			goto error;
		}

	} else {
		/* non-index objects start out life as files */
		if (d_is_negative(next)) {
			ret = cachefiles_has_space(cache, 1, 0);
			if (ret < 0)
				goto no_space_error;

			path.dentry = dir;
			ret = security_path_mknod(&path, next, S_IFREG, 0);
			if (ret < 0)
				goto create_error;
			start = jiffies;
			ret = vfs_create(d_inode(dir), next, S_IFREG, true);
			cachefiles_hist(cachefiles_create_histogram, start);
			trace_cachefiles_create(object, next, ret);
			if (ret < 0)
				goto create_error;

			ASSERT(d_backing_inode(next));

			_debug("create -> %pd{ino=%lu}",
			       next, d_backing_inode(next)->i_ino);

		} else if (!d_can_lookup(next) &&
			   !d_is_reg(next)
			   ) {
			pr_err("inode %lu is not a file or directory\n",
			       d_backing_inode(next)->i_ino);
			ret = -ENOBUFS;
			goto error;
		}
	}

	/* process the next component */
	if (key) {
		_debug("advance");
		inode_unlock(d_inode(dir));
		dput(dir);
		dir = next;
		next = NULL;
		goto advance;
	}

	/* we've found the object we were looking for */
	object->dentry = next;

	/* note that we're now using this object */
	if (!cachefiles_mark_inode_in_use(object, object->dentry)) {
		ret = -EBUSY;
		goto check_error_unlock;
	}
	marked = true;

	/* if we've found that the terminal object exists, then we need to
	 * check its attributes and delete it if it's out of date */
	if (!object->new) {
		_debug("validate '%pd'", next);

		ret = cachefiles_check_auxdata(object);
		if (ret == -ESTALE) {
			/* delete the object (the deleter drops the directory
			 * mutex) */
			object->dentry = NULL;

			ret = cachefiles_bury_object(cache, object, dir, next,
						     FSCACHE_OBJECT_IS_STALE);
			dput(next);
			next = NULL;

			if (ret < 0)
				goto error_out2;

			_debug("redo lookup");
			fscache_object_retrying_stale(&object->fscache);
			goto lookup_again;
		}

		if (ret < 0)
			goto check_error_unlock;
	}

	inode_unlock(d_inode(dir));
	dput(dir);
	dir = NULL;

	_debug("=== OBTAINED_OBJECT ===");

	if (object->new) {
		/* attach data to a newly constructed terminal object */
		ret = cachefiles_set_object_xattr(object);
		if (ret < 0)
			goto check_error;
	} else {
		/* always update the atime on an object we've just looked up
		 * (this is used to keep track of culling, and atimes are only
		 * updated by read, write and readdir but not lookup or
		 * open) */
		path.dentry = next;
		touch_atime(&path);
	}

	/* open a file interface onto a data file */
	if (object->type != FSCACHE_COOKIE_TYPE_INDEX) {
		if (d_is_reg(object->dentry)) {
			if (object->dentry->d_sb->s_blocksize > PAGE_SIZE) {
				pr_warn("cachefiles: Block size too large\n");
				goto check_error;
			}
		} else {
			BUG(); // TODO: open file in data-class subdir
		}

		if (!cachefiles_open_object(object))
			goto check_error;
	}

	if (object->new)
		object->fscache.stage = FSCACHE_OBJECT_STAGE_LIVE_EMPTY;
	else
		object->fscache.stage = FSCACHE_OBJECT_STAGE_LIVE;
	wake_up_var(&object->fscache.stage);

	object->new = false;
	_leave(" = t [%lu]", d_backing_inode(object->dentry)->i_ino);
	return true;

no_space_error:
	fscache_object_mark_killed(&object->fscache, FSCACHE_OBJECT_NO_SPACE);
create_error:
	_debug("create error %d", ret);
	if (ret == -EIO)
		cachefiles_io_error(cache, "Create/mkdir failed");
	goto error;

check_error_unlock:
	inode_unlock(d_inode(dir));
	dput(dir);
check_error:
	if (marked)
		cachefiles_unmark_inode_in_use(object, object->dentry);
	cachefiles_mark_object_inactive(cache, object);
	dput(object->dentry);
	object->dentry = NULL;
	goto error_out;

lookup_error:
	_debug("lookup error %d", ret);
	if (ret == -EIO)
		cachefiles_io_error(cache, "Lookup failed");
	next = NULL;
error:
	inode_unlock(d_inode(dir));
	dput(next);
error_out2:
	dput(dir);
error_out:
	object->fscache.stage = FSCACHE_OBJECT_STAGE_DEAD;
	wake_up_var(&object->fscache.stage);
	_leave(" = f");
	return false;
}

/*
 * get a subdirectory
 */
struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					struct dentry *dir,
					const char *dirname)
{
	struct dentry *subdir;
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

		path.mnt = cache->mnt;
		path.dentry = dir;
		ret = security_path_mkdir(&path, subdir, 0700);
		if (ret < 0)
			goto mkdir_error;
		ret = vfs_mkdir(d_inode(dir), subdir, 0700);
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

	ret = vfs_link(object->dentry, d_inode(dir), dentry, NULL);
	if (ret < 0) {
		_debug("link fail %d", ret);
		dput(dentry);
	} else {
		trace_cachefiles_link(object, d_inode(object->dentry));
		spin_lock(&object->fscache.lock);
		old = object->dentry;
		object->dentry = dentry;
		success = true;
		clear_bit(CACHEFILES_OBJECT_USING_TMPFILE, &object->flags);
		spin_unlock(&object->fscache.lock);
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
