/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  tracefs.h - a pseudo file system for activating tracing
 *
 * Based on debugfs by: 2004 Greg Kroah-Hartman <greg@kroah.com>
 *
 *  Copyright (C) 2014 Red Hat Inc, author: Steven Rostedt <srostedt@redhat.com>
 *
 * tracefs is the file system that is used by the tracing infrastructure.
 */

#ifndef _TRACEFS_H_
#define _TRACEFS_H_

#include <linux/fs.h>
#include <linux/seq_file.h>

#include <linux/types.h>

struct file_operations;

#ifdef CONFIG_TRACING
struct dentry *eventfs_start_creating(const char *name, struct dentry *parent,
				      bool inode_locked);
struct dentry *eventfs_failed_creating(struct dentry *dentry,
				       bool inode_locked);
struct dentry *eventfs_end_creating(struct dentry *dentry,
				    bool inode_locked);

struct dentry *tracefs_create_file(const char *name, umode_t mode,
				   struct dentry *parent, void *data,
				   const struct file_operations *fops);

struct dentry *tracefs_create_dir(const char *name, struct dentry *parent);

void tracefs_remove(struct dentry *dentry);

struct dentry *tracefs_create_instance_dir(const char *name, struct dentry *parent,
					   int (*mkdir)(const char *name),
					   int (*rmdir)(const char *name));

bool tracefs_initialized(void);

struct dentry *eventfs_create_dir(const char *name, struct dentry *parent);
int eventfs_create_top_file(const char *name, umode_t mode,
			   struct dentry *parent, void *data,
			   const struct file_operations *fops);

#endif /* CONFIG_TRACING */

#endif
