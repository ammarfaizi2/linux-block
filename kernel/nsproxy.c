// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2006 IBM Corporation
 *
 *  Author: Serge Hallyn <serue@us.ibm.com>
 *
 *  Jun 2006 - namespaces support
 *             OpenVZ, SWsoft Inc.
 *             Pavel Emelianov <xemul@openvz.org>
 */

#include <linux/slab.h>
#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/init_task.h>
#include <linux/mnt_namespace.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <net/net_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/time_namespace.h>
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/cgroup.h>
#include <linux/perf_event.h>

static struct kmem_cache *nsproxy_cachep;

struct nsproxy init_nsproxy = {
	.count			= ATOMIC_INIT(1),
	.uts_ns			= &init_uts_ns,
#if defined(CONFIG_POSIX_MQUEUE) || defined(CONFIG_SYSVIPC)
	.ipc_ns			= &init_ipc_ns,
#endif
	.mnt_ns			= NULL,
	.pid_ns_for_children	= &init_pid_ns,
#ifdef CONFIG_NET
	.net_ns			= &init_net,
#endif
#ifdef CONFIG_CGROUPS
	.cgroup_ns		= &init_cgroup_ns,
#endif
#ifdef CONFIG_TIME_NS
	.time_ns		= &init_time_ns,
	.time_ns_for_children	= &init_time_ns,
#endif
};

static inline struct nsproxy *create_nsproxy(void)
{
	struct nsproxy *nsproxy;

	nsproxy = kmem_cache_alloc(nsproxy_cachep, GFP_KERNEL);
	if (nsproxy)
		atomic_set(&nsproxy->count, 1);
	return nsproxy;
}

/*
 * Create new nsproxy and all of its the associated namespaces.
 * Return the newly created nsproxy.  Do not attach this to the task,
 * leave it to the caller to do proper locking and attach it to task.
 */
static struct nsproxy *create_new_namespaces(unsigned long flags,
	struct task_struct *tsk, struct user_namespace *user_ns,
	struct fs_struct *new_fs)
{
	struct nsproxy *new_nsp;
	int err;

	new_nsp = create_nsproxy();
	if (!new_nsp)
		return ERR_PTR(-ENOMEM);

	new_nsp->mnt_ns = copy_mnt_ns(flags, tsk->nsproxy->mnt_ns, user_ns, new_fs);
	if (IS_ERR(new_nsp->mnt_ns)) {
		err = PTR_ERR(new_nsp->mnt_ns);
		goto out_ns;
	}

	new_nsp->uts_ns = copy_utsname(flags, user_ns, tsk->nsproxy->uts_ns);
	if (IS_ERR(new_nsp->uts_ns)) {
		err = PTR_ERR(new_nsp->uts_ns);
		goto out_uts;
	}

	new_nsp->ipc_ns = copy_ipcs(flags, user_ns, tsk->nsproxy->ipc_ns);
	if (IS_ERR(new_nsp->ipc_ns)) {
		err = PTR_ERR(new_nsp->ipc_ns);
		goto out_ipc;
	}

	new_nsp->pid_ns_for_children =
		copy_pid_ns(flags, user_ns, tsk->nsproxy->pid_ns_for_children);
	if (IS_ERR(new_nsp->pid_ns_for_children)) {
		err = PTR_ERR(new_nsp->pid_ns_for_children);
		goto out_pid;
	}

	new_nsp->cgroup_ns = copy_cgroup_ns(flags, user_ns,
					    tsk->nsproxy->cgroup_ns);
	if (IS_ERR(new_nsp->cgroup_ns)) {
		err = PTR_ERR(new_nsp->cgroup_ns);
		goto out_cgroup;
	}

	new_nsp->net_ns = copy_net_ns(flags, user_ns, tsk->nsproxy->net_ns);
	if (IS_ERR(new_nsp->net_ns)) {
		err = PTR_ERR(new_nsp->net_ns);
		goto out_net;
	}

	new_nsp->time_ns_for_children = copy_time_ns(flags, user_ns,
					tsk->nsproxy->time_ns_for_children);
	if (IS_ERR(new_nsp->time_ns_for_children)) {
		err = PTR_ERR(new_nsp->time_ns_for_children);
		goto out_time;
	}
	new_nsp->time_ns = get_time_ns(tsk->nsproxy->time_ns);

	return new_nsp;

out_time:
	put_net(new_nsp->net_ns);
out_net:
	put_cgroup_ns(new_nsp->cgroup_ns);
out_cgroup:
	if (new_nsp->pid_ns_for_children)
		put_pid_ns(new_nsp->pid_ns_for_children);
out_pid:
	if (new_nsp->ipc_ns)
		put_ipc_ns(new_nsp->ipc_ns);
out_ipc:
	if (new_nsp->uts_ns)
		put_uts_ns(new_nsp->uts_ns);
out_uts:
	if (new_nsp->mnt_ns)
		put_mnt_ns(new_nsp->mnt_ns);
out_ns:
	kmem_cache_free(nsproxy_cachep, new_nsp);
	return ERR_PTR(err);
}

/*
 * called from clone.  This now handles copy for nsproxy and all
 * namespaces therein.
 */
int copy_namespaces(unsigned long flags, struct task_struct *tsk)
{
	struct nsproxy *old_ns = tsk->nsproxy;
	struct user_namespace *user_ns = task_cred_xxx(tsk, user_ns);
	struct nsproxy *new_ns;
	int ret;

	if (likely(!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
			      CLONE_NEWPID | CLONE_NEWNET |
			      CLONE_NEWCGROUP | CLONE_NEWTIME)))) {
		if (likely(old_ns->time_ns_for_children == old_ns->time_ns)) {
			get_nsproxy(old_ns);
			return 0;
		}
	} else if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/*
	 * CLONE_NEWIPC must detach from the undolist: after switching
	 * to a new ipc namespace, the semaphore arrays from the old
	 * namespace are unreachable.  In clone parlance, CLONE_SYSVSEM
	 * means share undolist with parent, so we must forbid using
	 * it along with CLONE_NEWIPC.
	 */
	if ((flags & (CLONE_NEWIPC | CLONE_SYSVSEM)) ==
		(CLONE_NEWIPC | CLONE_SYSVSEM)) 
		return -EINVAL;

	new_ns = create_new_namespaces(flags, tsk, user_ns, tsk->fs);
	if (IS_ERR(new_ns))
		return  PTR_ERR(new_ns);

	ret = timens_on_fork(new_ns, tsk);
	if (ret) {
		free_nsproxy(new_ns);
		return ret;
	}

	tsk->nsproxy = new_ns;
	return 0;
}

void free_nsproxy(struct nsproxy *ns)
{
	if (ns->mnt_ns)
		put_mnt_ns(ns->mnt_ns);
	if (ns->uts_ns)
		put_uts_ns(ns->uts_ns);
	if (ns->ipc_ns)
		put_ipc_ns(ns->ipc_ns);
	if (ns->pid_ns_for_children)
		put_pid_ns(ns->pid_ns_for_children);
	if (ns->time_ns)
		put_time_ns(ns->time_ns);
	if (ns->time_ns_for_children)
		put_time_ns(ns->time_ns_for_children);
	put_cgroup_ns(ns->cgroup_ns);
	put_net(ns->net_ns);
	kmem_cache_free(nsproxy_cachep, ns);
}

/*
 * Called from unshare. Unshare all the namespaces part of nsproxy.
 * On success, returns the new nsproxy.
 */
int unshare_nsproxy_namespaces(unsigned long unshare_flags,
	struct nsproxy **new_nsp, struct cred *new_cred, struct fs_struct *new_fs)
{
	struct user_namespace *user_ns;
	int err = 0;

	if (!(unshare_flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
			       CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWCGROUP |
			       CLONE_NEWTIME)))
		return 0;

	user_ns = new_cred ? new_cred->user_ns : current_user_ns();
	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	*new_nsp = create_new_namespaces(unshare_flags, current, user_ns,
					 new_fs ? new_fs : current->fs);
	if (IS_ERR(*new_nsp)) {
		err = PTR_ERR(*new_nsp);
		goto out;
	}

out:
	return err;
}

void switch_task_namespaces(struct task_struct *p, struct nsproxy *new)
{
	struct nsproxy *ns;

	might_sleep();

	task_lock(p);
	ns = p->nsproxy;
	p->nsproxy = new;
	task_unlock(p);

	if (ns && atomic_dec_and_test(&ns->count))
		free_nsproxy(ns);
}

void exit_task_namespaces(struct task_struct *p)
{
	switch_task_namespaces(p, NULL);
}

static int check_setns_flags(unsigned long flags)
{
	if (!flags || (flags & ~(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
				 CLONE_NEWNET | CLONE_NEWUSER | CLONE_NEWPID |
				 CLONE_NEWCGROUP)))
		return -EINVAL;

	return 0;
}

static inline int __ns_install(struct nsset *nsset, struct ns_common *ns)
{
	return ns->ops->install(nsset, ns);
}

/*
 * This is the inverse operation to unshare().
 * Ordering is equivalent to the standard ordering used everywhere else
 * during unshare and process creation. The switch to the new set of
 * namespaces occurs at the point of no return after installation of
 * all requested namespaces was successful.
 */
static int ns_install(struct nsset *nsset, struct pid *pid)
{
	int ret = 0;
	unsigned flags = nsset->flags;
	struct task_struct *me = current;
	struct task_struct *tsk;
	struct nsproxy *nsp = NULL;

	tsk = get_pid_task(pid, PIDTYPE_PID);
	if (!tsk)
		return -ESRCH;

	if (!ptrace_may_access(tsk, PTRACE_MODE_READ_REALCREDS)) {
		ret = -EPERM;
		goto err;
	}

	task_lock(tsk);
	nsp = tsk->nsproxy;
	if (nsp)
		get_nsproxy(nsp);
	task_unlock(tsk);

	/* Target task has already exited. */
	if (!nsp) {
		ret = -ESRCH;
		goto err;
	}

	if (flags & CLONE_NEWUSER) {
#ifdef CONFIG_USER_NS
		struct user_namespace *user_ns;

		nsset->cred = prepare_creds();
		if (!nsset->cred) {
			ret = -ENOMEM;
			goto err;
		}

		user_ns = get_user_ns(__task_cred(tsk)->user_ns);
		ret = __ns_install(nsset, &user_ns->ns);
		put_user_ns(user_ns);
#else
		ret = -EINVAL;
#endif
		if (ret)
			goto err;
	}

	if (flags & CLONE_NEWNS) {
		nsset->fs = copy_fs_struct(me->fs);
		if (nsset->fs)
			ret = __ns_install(nsset, mnt_ns_to_common(nsp->mnt_ns));
		else
			ret = -ENOMEM;
		if (ret)
			goto err;
	}

	if (flags & CLONE_NEWUTS) {
#ifdef CONFIG_UTS_NS
		ret = __ns_install(nsset, &nsp->uts_ns->ns);
#else
		ret = -EINVAL;
#endif
		if (ret)
			goto err;
	}

	if (flags & CLONE_NEWIPC) {
#ifdef CONFIG_IPC_NS
		ret = __ns_install(nsset, &nsp->ipc_ns->ns);
#else
		ret = -EINVAL;
#endif
		if (ret)
			goto err;
	}

	if (flags & CLONE_NEWPID) {
#ifdef CONFIG_PID_NS
		struct pid_namespace *pidns;

		pidns = task_active_pid_ns(tsk);
		if (pidns) {
			get_pid_ns(pidns);
			ret = __ns_install(nsset, &pidns->ns);
			put_pid_ns(pidns);
		} else {
			ret = -ESRCH;
		}
#else
		ret = EINVAL;
#endif
		if (ret)
			goto err;
	}

	if (flags & CLONE_NEWCGROUP) {
#ifdef CONFIG_CGROUPS
		ret = __ns_install(nsset, &nsp->cgroup_ns->ns);
#else
		ret = EINVAL;
#endif
		if (ret)
			goto err;
	}

	if (flags & CLONE_NEWNET) {
#ifdef CONFIG_NET_NS
		ret = __ns_install(nsset, &nsp->net_ns->ns);
#else
		ret = -EINVAL;
#endif
		if (ret)
			goto err;
	}

err:
	put_task_struct(tsk);
	if (nsp)
		put_nsproxy(nsp);
	if (ret) {
		put_cred(nsset_cred(nsset));
		if (flags & CLONE_NEWUSER)
			free_fs_struct(nsset->fs);
	}

	return ret;
}

/*
 * This is the point of no return. There are just a few namespaces
 * that do some actual work here and it's sufficiently minimal that
 * a separate ns_common operation seems unnecessary. Unshare is doing
 * the same thing. If there'll be more interesting stuff we can
 * add a simple commit handler on ns_common.
 */
static void ns_attach(struct nsset *nsset)
{
	unsigned flags = nsset->flags;
	struct task_struct *me = current;

#ifdef CONFIG_USER_NS
	if (flags & CLONE_NEWUSER)
		commit_creds(nsset_cred(nsset));
#endif

	if ((flags & CLONE_NEWNS) && nsset->fs != me->fs) {
		set_fs_root(me->fs, &nsset->fs->root);
		set_fs_pwd(me->fs, &nsset->fs->pwd);
		free_fs_struct(nsset->fs);
	}

#ifdef CONFIG_IPC_NS
	if (flags & CLONE_NEWIPC)
		exit_sem(me);
#endif

	switch_task_namespaces(me, nsset->nsproxy);
}

SYSCALL_DEFINE2(setns, int, fd, int, flags)
{
	struct task_struct *tsk = current;
	struct file *file;
	struct ns_common *ns = NULL;
	struct nsset nsset = {};
	int err;

	file = fget(fd);
	if (!file)
		return -EBADF;

	if (proc_ns_file(file)) {
		ns = get_proc_ns(file_inode(file));
		if (flags && (ns->ops->type != flags))
			err = -EINVAL;
		flags = ns->ops->type;
	} else if (pidfd_pid(file)) {
		err = check_setns_flags(flags);
	} else {
		err = -EINVAL;
	}
	if (err)
		goto out;

	nsset.nsproxy = create_new_namespaces(0, tsk, current_user_ns(), tsk->fs);
	if (IS_ERR(nsset.nsproxy)) {
		err = PTR_ERR(nsset.nsproxy);
		goto out;
	}
	nsset.flags = flags;
	nsset.cred = current_cred();
	nsset.fs = current->fs;

	if (proc_ns_file(file)) {
		if (ns->ops->type == CLONE_NEWUSER)
			nsset.cred = prepare_creds();
		if (!nsset.cred)
			err = -ENOMEM;
		else
			err = ns->ops->install(&nsset, ns);
	} else {
		err = ns_install(&nsset, file->private_data);
	}
	if (err) {
		free_nsproxy(nsset.nsproxy);
		goto out;
	}
	ns_attach(&nsset);

	perf_event_namespaces(tsk);
out:
	fput(file);
	return err;
}

int __init nsproxy_cache_init(void)
{
	nsproxy_cachep = KMEM_CACHE(nsproxy, SLAB_PANIC);
	return 0;
}
