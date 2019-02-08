/* Implement container objects.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/init_task.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/anon_inodes.h>
#include <linux/container.h>
#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/proc_fs.h>
#include <linux/mnt_namespace.h>
#include "namespaces.h"

struct container init_container = {
	.name		= ".init",
	.id		= 1,
	.usage		= REFCOUNT_INIT(2),
	.cred		= &init_cred,
	.ns		= &init_nsproxy,
	.init		= &init_task,
	.pid_ns		= &init_pid_ns,
	.members.next	= &init_task.container_link,
	.members.prev	= &init_task.container_link,
	.children	= LIST_HEAD_INIT(init_container.children),
	.req_key_traps	= LIST_HEAD_INIT(init_container.req_key_traps),
	.flags		= (1 << CONTAINER_FLAG_INIT_STARTED),
	.lock		= __SPIN_LOCK_UNLOCKED(init_container.lock),
	.seq		= SEQCNT_ZERO(init_fs.seq),
};

#ifdef CONFIG_CONTAINERS

static atomic64_t container_id_counter = ATOMIC_INIT(1);

/*
 * Drop a ref on a container and clear it if no longer in use.
 */
void put_container(struct container *c)
{
	struct container *parent;

	while (c && refcount_dec_and_test(&c->usage)) {
		BUG_ON(!list_empty(&c->members));
		if (!list_empty(&c->req_key_traps))
			key_del_intercept(c, NULL);
		if (c->pid_ns)
			put_pid_ns(c->pid_ns);
		if (c->ns)
			put_nsproxy(c->ns);
		path_put(&c->root);

		parent = c->parent;
		if (parent) {
			spin_lock(&parent->lock);
			list_del(&c->child_link);
			spin_unlock(&parent->lock);
		}

		if (c->cred)
			put_cred(c->cred);
		key_put(c->keyring);
		security_container_free(c);
		kfree(c);
		c = parent;
	}
}

static void *container_proc_start(struct seq_file *m, loff_t *_pos)
{
	struct container *c = m->private;
	struct list_head *p;
	loff_t pos = *_pos;

	spin_lock(&c->lock);

	if (pos <= 1) {
		*_pos = 1;
		return (void *)1UL; /* Banner on first line */
	}

	if (pos == 2)
		return m->private; /* Current container on second line */

	/* Subordinate containers thereafter */
	p = c->children.next;
	pos--;
	for (pos--; pos > 0 && p != &c->children; pos--) {
		p = p->next;
	}

	if (p == &c->children)
		return NULL;
	return container_of(p, struct container, child_link);
}

static void *container_proc_next(struct seq_file *m, void *v, loff_t *_pos)
{
	struct container *c = m->private, *vc = v;
	struct list_head *p;
	loff_t pos = *_pos;

	pos++;
	*_pos = pos;
	if (pos == 2)
		return c; /* Current container on second line */

	if (pos == 3)
		p = &c->children;
	else
		p = &vc->child_link;
	p = p->next;
	if (p == &c->children)
		return NULL;
	return container_of(p, struct container, child_link);
}

static void container_proc_stop(struct seq_file *m, void *v)
{
	struct container *c = m->private;

	spin_unlock(&c->lock);
}

static int container_proc_show(struct seq_file *m, void *v)
{
	struct user_namespace *uns = current_user_ns();
	struct container *c = v;
	const char *name;

	if (v == (void *)1UL) {
		seq_puts(m, "NAME                               ID USE FL OWNER GROUP\n");
		return 0;
	}

	name = (c == m->private) ? "<current>" : c->name;
	seq_printf(m, "%-24s %12llu %3u %02lx %5d %5d\n",
		   name, c->id, refcount_read(&c->usage), c->flags,
		   from_kuid_munged(uns, c->cred->uid),
		   from_kgid_munged(uns, c->cred->gid));

	return 0;
}

static const struct seq_operations container_proc_ops = {
	.start	= container_proc_start,
	.next	= container_proc_next,
	.stop	= container_proc_stop,
	.show	= container_proc_show,
};

static int container_proc_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret = seq_open(file, &container_proc_ops);

	if (ret == 0) {
		m = file->private_data;
		m->private = current->container;
	}
	return ret;
}

static const struct file_operations container_proc_fops = {
	.open		= container_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/*
 * Allow the user to poll for the container dying.
 */
static unsigned int container_poll(struct file *file, poll_table *wait)
{
	struct container *container = file->private_data;
	unsigned int mask = 0;

	poll_wait(file, &container->waitq, wait);

	if (test_bit(CONTAINER_FLAG_DEAD, &container->flags))
		mask |= POLLHUP;

	return mask;
}

static int container_release(struct inode *inode, struct file *file)
{
	struct container *container = file->private_data;

	put_container(container);
	return 0;
}

const struct file_operations container_fops = {
	.poll		= container_poll,
	.release	= container_release,
};

/*
 * Handle fork/clone.
 *
 * A process inherits its parent's container.  The first process into the
 * container is its 'init' process and the life of everything else in there is
 * dependent upon that.
 */
int copy_container(unsigned long flags, struct task_struct *tsk,
		   struct container *container)
{
	struct container *c = container ?: tsk->container;
	int ret = -ECANCELED;

	spin_lock(&c->lock);

	if (!test_bit(CONTAINER_FLAG_DEAD, &c->flags)) {
		list_add_tail(&tsk->container_link, &c->members);
		get_container(c);
		tsk->container = c;
		if (!c->init) {
			set_bit(CONTAINER_FLAG_INIT_STARTED, &c->flags);
			c->init = tsk;
		}
		ret = 0;
	}

	spin_unlock(&c->lock);
	return ret;
}

/*
 * Remove a dead process from a container.
 *
 * If the 'init' process in a container dies, we kill off all the other
 * processes in the container.
 */
void exit_container(struct task_struct *tsk)
{
	struct task_struct *p;
	struct container *c = tsk->container;
	struct kernel_siginfo si = {
		.si_signo = SIGKILL,
		.si_code  = SI_KERNEL,
	};

	spin_lock(&c->lock);

	list_del(&tsk->container_link);

	if (c->init == tsk) {
		c->init = NULL;
		c->exit_code = tsk->exit_code;
		smp_wmb(); /* Order exit_code vs CONTAINER_DEAD. */
		set_bit(CONTAINER_FLAG_DEAD, &c->flags);
		wake_up_bit(&c->flags, CONTAINER_FLAG_DEAD);

		list_for_each_entry(p, &c->members, container_link) {
			si.si_pid = task_tgid_vnr(p);
			send_sig_info(SIGKILL, &si, p);
		}
	}

	spin_unlock(&c->lock);
	put_container(c);
}

/*
 * Allocate a container.
 */
static struct container *alloc_container(const char __user *name)
{
	struct container *c;
	long len;
	int ret;

	c = kzalloc(sizeof(struct container), GFP_KERNEL);
	if (!c)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&c->members);
	INIT_LIST_HEAD(&c->children);
	INIT_LIST_HEAD(&c->req_key_traps);
	init_waitqueue_head(&c->waitq);
	spin_lock_init(&c->lock);
	refcount_set(&c->usage, 1);

	ret = -EFAULT;
	len = strncpy_from_user(c->name, name, sizeof(c->name));
	if (len < 0)
		goto err;
	ret = -ENAMETOOLONG;
	if (len >= sizeof(c->name))
		goto err;
	ret = -EINVAL;
	if (strchr(c->name, '/'))
		goto err;

	c->name[len] = 0;
	return c;

err:
	kfree(c);
	return ERR_PTR(ret);
}

/*
 * Create some creds for the container.  We don't want to pin things we don't
 * have to, so drop all keyrings from the new cred.  The LSM gets to audit the
 * cred struct when security_container_alloc() is invoked.
 */
static const struct cred *create_container_creds(unsigned int flags)
{
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return ERR_PTR(-ENOMEM);

#ifdef CONFIG_KEYS
	key_put(new->thread_keyring);
	new->thread_keyring = NULL;
	key_put(new->process_keyring);
	new->process_keyring = NULL;
	key_put(new->session_keyring);
	new->session_keyring = NULL;
	key_put(new->request_key_auth);
	new->request_key_auth = NULL;
#endif

	if (flags & CONTAINER_NEW_USER_NS) {
		ret = create_user_ns(new);
		if (ret < 0)
			goto err;
		new->euid = new->user_ns->owner;
		new->egid = new->user_ns->group;
	}

	new->fsuid = new->suid = new->uid = new->euid;
	new->fsgid = new->sgid = new->gid = new->egid;
	return new;

err:
	abort_creds(new);
	return ERR_PTR(ret);
}

/*
 * Create a new container.
 */
static struct container *create_container(const char __user *name, unsigned int flags)
{
	struct container *parent, *c;
	struct fs_struct *fs;
	struct nsproxy *ns;
	const struct cred *cred;
	int ret;

	c = alloc_container(name);
	if (IS_ERR(c))
		return c;

	if (flags & CONTAINER_KILL_ON_CLOSE)
		__set_bit(CONTAINER_FLAG_KILL_ON_CLOSE, &c->flags);

	cred = create_container_creds(flags);
	if (IS_ERR(cred)) {
		ret = PTR_ERR(cred);
		goto err_cont;
	}
	c->cred = cred;

	ret = -ENOMEM;
	fs = copy_fs_struct(current->fs);
	if (!fs)
		goto err_cont;

	ns = create_new_namespaces(
		(flags & CONTAINER_NEW_FS_NS	 ? CLONE_NEWNS : 0) |
		(flags & CONTAINER_NEW_CGROUP_NS ? CLONE_NEWCGROUP : 0) |
		(flags & CONTAINER_NEW_UTS_NS	 ? CLONE_NEWUTS : 0) |
		(flags & CONTAINER_NEW_IPC_NS	 ? CLONE_NEWIPC : 0) |
		(flags & CONTAINER_NEW_PID_NS	 ? CLONE_NEWPID : 0) |
		(flags & CONTAINER_NEW_NET_NS	 ? CLONE_NEWNET : 0),
		current->nsproxy, cred->user_ns, fs);
	if (IS_ERR(ns)) {
		ret = PTR_ERR(ns);
		goto err_fs;
	}

	c->ns = ns;
	c->pid_ns = get_pid_ns(c->ns->pid_ns_for_children);
	c->root = fs->root;
	c->seq = fs->seq;
	fs->root.mnt = NULL;
	fs->root.dentry = NULL;

	if (flags & CONTAINER_NEW_EMPTY_FS_NS) {
		put_mnt_ns(ns->mnt_ns);
		ns->mnt_ns = NULL;
	}

	ret = security_container_alloc(c, flags);
	if (ret < 0)
		goto err_fs;

	parent = current->container;
	get_container(parent);
	c->parent = parent;
	c->id = atomic64_inc_return(&container_id_counter);
	spin_lock(&parent->lock);
	list_add_tail(&c->child_link, &parent->children);
	spin_unlock(&parent->lock);
	return c;

err_fs:
	free_fs_struct(fs);
err_cont:
	put_container(c);
	return ERR_PTR(ret);
}

/*
 * Create a new container object.
 */
SYSCALL_DEFINE5(container_create,
		const char __user *, name,
		unsigned int, flags,
		unsigned long, spare3,
		unsigned long, spare4,
		unsigned long, spare5)
{
	struct container *c;
	int fd;

	if (!name ||
	    flags & ~CONTAINER__FLAG_MASK ||
	    spare3 != 0 || spare4 != 0 || spare5 != 0)
		return -EINVAL;
	if ((flags & (CONTAINER_NEW_FS_NS | CONTAINER_NEW_EMPTY_FS_NS)) ==
	    (CONTAINER_NEW_FS_NS | CONTAINER_NEW_EMPTY_FS_NS))
		return -EINVAL;

	c = create_container(name, flags);
	if (IS_ERR(c))
		return PTR_ERR(c);

	fd = anon_inode_getfd("container", &container_fops, c,
			      O_RDWR | (flags & CONTAINER_FD_CLOEXEC ? O_CLOEXEC : 0));
	if (fd < 0)
		put_container(c);
	return fd;
}

static int __init init_container_fs(void)
{
	proc_create("containers", 0, NULL, &container_proc_fops);
	return 0;
}
fs_initcall(init_container_fs);

#endif /* CONFIG_CONTAINERS */
