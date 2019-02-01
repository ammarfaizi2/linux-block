/* Container objects
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_CONTAINER_H
#define _LINUX_CONTAINER_H

#include <uapi/linux/container.h>
#include <linux/refcount.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/path.h>
#include <linux/seqlock.h>

struct fs_struct;
struct nsproxy;
struct task_struct;

/*
 * The container object.
 */
struct container {
	char			name[24];
	u64			id;		/* Container ID */
	refcount_t		usage;
	int			exit_code;	/* The exit code of 'init' */
	const struct cred	*cred;		/* Creds for this container, including userns */
	struct nsproxy		*ns;		/* This container's namespaces */
	struct path		root;		/* The root of the container's fs namespace */
	struct task_struct	*init;		/* The 'init' task for this container */
	struct container	*parent;	/* Parent of this container. */
	struct pid_namespace	*pid_ns;	/* The process ID namespace for this container */
	void			*security;	/* LSM data */
	struct list_head	members;	/* Member processes, guarded with ->lock */
	struct list_head	child_link;	/* Link in parent->children */
	struct list_head	children;	/* Child containers */
	wait_queue_head_t	waitq;		/* Someone waiting for init to exit waits here */
	unsigned long		flags;
#define CONTAINER_FLAG_INIT_STARTED	0	/* Init is started - certain ops now prohibited */
#define CONTAINER_FLAG_DEAD		1	/* Init has died */
#define CONTAINER_FLAG_KILL_ON_CLOSE	2	/* Kill init if container handle closed */
	spinlock_t		lock;
	seqcount_t		seq;		/* Track changes in ->root */
};

extern struct container init_container;

#ifdef CONFIG_CONTAINERS
extern const struct file_operations container_fops;

extern int copy_container(unsigned long flags, struct task_struct *tsk,
			  struct container *container);
extern void exit_container(struct task_struct *tsk);
extern void put_container(struct container *c);

static inline struct container *get_container(struct container *c)
{
	refcount_inc(&c->usage);
	return c;
}

static inline bool is_container_file(struct file *file)
{
	return file->f_op == &container_fops;
}

#else

static inline int copy_container(unsigned long flags, struct task_struct *tsk,
				 struct container *container)
{ return 0; }
static inline void exit_container(struct task_struct *tsk) { }
static inline void put_container(struct container *c) {}
static inline struct container *get_container(struct container *c) { return NULL; }
static inline bool is_container_file(struct file *file) { return false; }

#endif /* CONFIG_CONTAINERS */

#endif /* _LINUX_CONTAINER_H */
