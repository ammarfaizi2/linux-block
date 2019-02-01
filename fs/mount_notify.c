/* Provide mount topology/attribute change notifications.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include "mount.h"

/*
 * Post mount notifications to all watches going rootwards along the tree.
 *
 * Must be called with the mount_lock held.
 */
void post_mount_notification(struct mount *changed,
			     struct mount_notification *notify)
{
	const struct cred *cred = current_cred();
	struct path cursor;
	struct mount *mnt;
	unsigned seq;

	seq = 0;
	rcu_read_lock();
restart:
	cursor.mnt = &changed->mnt;
	cursor.dentry = changed->mnt.mnt_root;
	mnt = real_mount(cursor.mnt);
	notify->watch.info &= ~WATCH_INFO_IN_SUBTREE;

	read_seqbegin_or_lock(&rename_lock, &seq);
	for (;;) {
		if (mnt->mnt_watchers &&
		    !hlist_empty(&mnt->mnt_watchers->watchers)) {
			if (cursor.dentry->d_flags & DCACHE_MOUNT_WATCH)
				post_watch_notification(mnt->mnt_watchers,
							&notify->watch, cred,
							(unsigned long)cursor.dentry);
		} else {
			cursor.dentry = mnt->mnt.mnt_root;
		}
		notify->watch.info |= WATCH_INFO_IN_SUBTREE;

		if (cursor.dentry == cursor.mnt->mnt_root ||
		    IS_ROOT(cursor.dentry)) {
			struct mount *parent = READ_ONCE(mnt->mnt_parent);

			/* Escaped? */
			if (cursor.dentry != cursor.mnt->mnt_root)
				break;

			/* Global root? */
			if (mnt != parent) {
				cursor.dentry = READ_ONCE(mnt->mnt_mountpoint);
				mnt = parent;
				cursor.mnt = &mnt->mnt;
				continue;
			}
			break;
		}

		cursor.dentry = cursor.dentry->d_parent;
	}

	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}

	done_seqretry(&rename_lock, seq);
	rcu_read_unlock();
}

static void release_mount_watch(struct watch_list *wlist, struct watch *watch)
{
	struct vfsmount *mnt = watch->private;
	struct dentry *dentry = (struct dentry *)(unsigned long)watch->id;

	dput(dentry);
	mntput(mnt);
}

/**
 * sys_mount_notify - Watch for mount topology/attribute changes
 * @dfd: Base directory to pathwalk from or fd referring to mount.
 * @filename: Path to mount to place the watch upon
 * @at_flags: Pathwalk control flags
 * @watch_fd: The watch queue to send notifications to.
 * @watch_id: The watch ID to be placed in the notification (-1 to remove watch)
 */
SYSCALL_DEFINE5(mount_notify,
		int, dfd,
		const char __user *, filename,
		unsigned int, at_flags,
		int, watch_fd,
		int, watch_id)
{
	struct watch_queue *wqueue;
	struct watch_list *wlist = NULL;
	struct watch *watch;
	struct mount *m;
	struct path path;
	int ret;

	if (watch_id < -1 || watch_id > 0xff)
		return -EINVAL;

	ret = user_path_at(dfd, filename, at_flags, &path);
	if (ret)
		return ret;

	wqueue = get_watch_queue(watch_fd);
	if (IS_ERR(wqueue))
		goto err_path;

	m = real_mount(path.mnt);

	if (watch_id >= 0) {
		if (!m->mnt_watchers) {
			wlist = kzalloc(sizeof(*wlist), GFP_KERNEL);
			if (!wlist)
				goto err_wqueue;
			INIT_HLIST_HEAD(&wlist->watchers);
			spin_lock_init(&wlist->lock);
			wlist->release_watch = release_mount_watch;
		}

		watch = kzalloc(sizeof(*watch), GFP_KERNEL);
		if (!watch)
			goto err_wlist;

		init_watch(watch);
		watch->id		= (unsigned long)path.dentry;
		watch->queue		= wqueue;
		watch->private		= path.mnt;
		watch->info_id		= (u32)watch_id << 24;

		down_write(&m->mnt.mnt_sb->s_umount);
		if (!m->mnt_watchers) {
			m->mnt_watchers = wlist;
			wlist = NULL;
		}

		watch->watch_list = m->mnt_watchers;
		ret = add_watch_to_object(watch);
		if (ret == 0) {
			spin_lock(&path.dentry->d_lock);
			path.dentry->d_flags |= DCACHE_MOUNT_WATCH;
			spin_unlock(&path.dentry->d_lock);
			path_get(&path);
		}
		up_write(&m->mnt.mnt_sb->s_umount);
		if (ret < 0)
			kfree(watch);
	} else if (m->mnt_watchers) {
		down_write(&m->mnt.mnt_sb->s_umount);
		ret = remove_watch_from_object(m->mnt_watchers, wqueue,
					       (unsigned long)path.dentry,
					       false);
		up_write(&m->mnt.mnt_sb->s_umount);
	} else {
		ret = -EBADSLT;
	}

err_wlist:
	kfree(wlist);
err_wqueue:
	put_watch_queue(wqueue);
err_path:
	path_put(&path);
	return ret;
}
