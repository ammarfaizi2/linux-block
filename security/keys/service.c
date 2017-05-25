// SPDX-License-Identifier: GPL-2.0-or-later
/* Service daemon interface
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/utsname.h>
#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/cgroup.h>
#include <net/net_namespace.h>
#include "internal.h"
#include "../fs/mount.h"

/*
 * Request service filter record.
 */
struct request_key_service {
	struct hlist_node	user_ns_link;	/* Link in the user_ns service list */
	struct key		*queue_keyring;	/* Keyring into which requests are placed */

	/* The following fields define the selection criteria that we select
	 * this record on.  All these references must be pinned just in case
	 * the fd gets passed to another process or the owning process changes
	 * its own namespaces.
	 *
	 * Most of the criteria can be NULL if that criterion is irrelevant to
	 * the filter.
	 */
	char			type[24];	/* Key type of interest (or "") */
	struct ns_tag		*uts_ns;	/* Matching UTS namespace (or NULL) */
	struct ns_tag		*ipc_ns;	/* Matching IPC namespace (or NULL) */
	struct ns_tag		*mnt_ns;	/* Matching mount namespace (or NULL) */
	struct ns_tag		*pid_ns;	/* Matching process namespace (or NULL) */
	struct ns_tag		*net_ns;	/* Matching network namespace (or NULL) */
	struct ns_tag		*cgroup_ns;	/* Matching cgroup namespace (or NULL) */
	u8			selectivity;	/* Number of exact-match fields */
	bool			dead;
};

/*
 * Free a request_key service record
 */
static void free_key_service(struct request_key_service *svc)
{
	if (svc) {
		put_ns_tag(svc->uts_ns);
		put_ns_tag(svc->ipc_ns);
		put_ns_tag(svc->mnt_ns);
		put_ns_tag(svc->pid_ns);
		put_ns_tag(svc->net_ns);
		put_ns_tag(svc->cgroup_ns);
		key_put(svc->queue_keyring);
		kfree(svc);
	}
}

/*
 * Allocate a service record.
 */
static struct request_key_service *alloc_key_service(key_serial_t queue_keyring,
						     const char __user *type_name,
						     unsigned int ns_mask)
{
	struct request_key_service *svc;
	struct key_type *type;
	key_ref_t key_ref;
	int ret;
	u8 selectivity = 0;

	svc = kzalloc(sizeof(struct request_key_service), GFP_KERNEL);
	if (!svc)
		return ERR_PTR(-ENOMEM);

	if (queue_keyring != 0) {
		key_ref = lookup_user_key(queue_keyring, 0, KEY_NEED_SEARCH);
		if (IS_ERR(key_ref)) {
			ret = PTR_ERR(key_ref);
			goto err_svc;
		}

		svc->queue_keyring = key_ref_to_ptr(key_ref);
	}

	/* Save the matching criteria.  Anything the caller doesn't care about
	 * we leave as NULL.
	 */
	if (type_name) {
		ret = strncpy_from_user(svc->type, type_name, sizeof(svc->type));
		if (ret < 0)
			goto err_keyring;
		if (ret >= sizeof(svc->type)) {
			ret = -EINVAL;
			goto err_keyring;
		}

		type = key_type_lookup(type_name);
		if (IS_ERR(type)) {
			ret = -EINVAL;
			goto err_keyring;
		}
		memcpy(svc->type, type->name, sizeof(svc->type));
		key_type_put(type);
	}

	if (ns_mask & KEY_SERVICE_NS_UTS) {
		svc->uts_ns = get_ns_tag(current->nsproxy->uts_ns->ns.tag);
		selectivity++;
	}
	if (ns_mask & KEY_SERVICE_NS_IPC) {
		svc->ipc_ns = get_ns_tag(current->nsproxy->ipc_ns->ns.tag);
		selectivity++;
	}
	if (ns_mask & KEY_SERVICE_NS_MNT) {
		svc->mnt_ns = get_ns_tag(current->nsproxy->mnt_ns->ns.tag);
		selectivity++;
	}
	if (ns_mask & KEY_SERVICE_NS_PID) {
		svc->pid_ns = get_ns_tag(task_active_pid_ns(current)->ns.tag);
		selectivity++;
	}
	if (ns_mask & KEY_SERVICE_NS_NET) {
		svc->net_ns = get_ns_tag(current->nsproxy->net_ns->ns.tag);
		selectivity++;
	}
	if (ns_mask & KEY_SERVICE_NS_CGROUP) {
		svc->cgroup_ns = get_ns_tag(current->nsproxy->cgroup_ns->ns.tag);
		selectivity++;
	}

	svc->selectivity = selectivity;
	return svc;

err_keyring:
	key_put(svc->queue_keyring);
err_svc:
	kfree(svc);
	return ERR_PTR(ret);
}

/*
 * Install a request_key service into the user namespace's list
 */
static int install_key_service(struct user_namespace *user_ns,
			       struct request_key_service *svc)
{
	struct request_key_service *p;
	struct hlist_node **pp;
	int ret = 0;

	spin_lock(&user_ns->request_key_services_lock);

	/* The services list is kept in order of selectivity.  The more exact
	 * matches a service requires, the earlier it is in the list.
	 */
	for (pp = &user_ns->request_key_services.first; *pp; pp = &(*pp)->next) {
		p = hlist_entry(*pp, struct request_key_service, user_ns_link);
		if (p->selectivity < svc->selectivity)
			goto insert_before;
		if (p->selectivity > svc->selectivity)
			continue;
		if (memcmp(p->type, svc->type, sizeof(p->type)) == 0 &&
		    p->uts_ns == svc->uts_ns &&
		    p->ipc_ns == svc->ipc_ns &&
		    p->mnt_ns == svc->mnt_ns &&
		    p->pid_ns == svc->pid_ns &&
		    p->net_ns == svc->net_ns &&
		    p->cgroup_ns == svc->cgroup_ns)
			goto duplicate;
	}

	svc->user_ns_link.pprev = pp;
	rcu_assign_pointer(*pp, &svc->user_ns_link);
	goto out;

insert_before:
	hlist_add_before_rcu(&svc->user_ns_link, &p->user_ns_link);
	goto out;

duplicate:
	free_key_service(svc);
	ret = -EEXIST;
out:
	spin_unlock(&user_ns->request_key_services_lock);
	return ret;
}

/*
 * Remove a request_key service interception from the user namespace's list
 */
static int remove_key_service(struct user_namespace *user_ns,
			      struct request_key_service *svc)
{
	struct request_key_service *p;
	struct hlist_node **pp;
	int ret = 0;

	spin_lock(&user_ns->request_key_services_lock);

	/* The services list is kept in order of selectivity.  The more exact
	 * matches a service requires, the earlier it is in the list.
	 */
	for (pp = &user_ns->request_key_services.first; *pp; pp = &(*pp)->next) {
		p = hlist_entry(*pp, struct request_key_service, user_ns_link);
		if (p->selectivity < svc->selectivity)
			break;
		if (p->selectivity > svc->selectivity)
			continue;
		if (memcmp(p->type, svc->type, sizeof(p->type)) == 0 &&
		    p->uts_ns == svc->uts_ns &&
		    p->ipc_ns == svc->ipc_ns &&
		    p->mnt_ns == svc->mnt_ns &&
		    p->pid_ns == svc->pid_ns &&
		    p->net_ns == svc->net_ns &&
		    p->cgroup_ns == svc->cgroup_ns)
			goto found;
	}

	p = NULL;
	ret = -ENOENT;
	goto out;

found:
	hlist_del_rcu(&p->user_ns_link);
out:
	spin_unlock(&user_ns->request_key_services_lock);
	free_key_service(p);
	free_key_service(svc);
	return ret;
}

/*
 * Add a request_key service handler for a subset of the calling process's
 * particular set of namespaces.
 */
long keyctl_service_intercept(key_serial_t queue_keyring,
			      int userns_fd,
			      const char __user *type_name,
			      unsigned int ns_mask)
{
	struct request_key_service *svc;
	struct user_namespace *user_ns = current_user_ns();

	if (ns_mask & ~KEY_SERVICE___ALL_NS)
		return -EINVAL;
	if (userns_fd != -1)
		return -EINVAL; /* Not supported yet */

	/* Require the caller to be the owner of the user namespace in which
	 * the fd was created if they're not the sysadmin.  Possibly we should
	 * be more strict about what namespaces one can select, but it's not
	 * clear how best to do that.
	 */
	if (!capable(CAP_SYS_ADMIN) &&
	    !uid_eq(user_ns->owner, current_cred()->euid))
		return -EPERM;

	svc = alloc_key_service(queue_keyring, type_name, ns_mask);
	if (IS_ERR(svc))
		return PTR_ERR(svc);

	if (queue_keyring == 0)
		return remove_key_service(user_ns, svc);

	return install_key_service(user_ns, svc);
}

/*
 * Queue a construction record if we can find a queue to punt it off to.
 */
int queue_request_key(struct key *key, struct key *auth_key)
{
	struct request_key_service *svc;
	struct user_namespace *user_ns = current_user_ns();
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	struct nsproxy *nsproxy = current->nsproxy;
	struct key *queue_keyring = NULL;
	int ret;

	if (hlist_empty(&user_ns->request_key_services))
		return false;

	rcu_read_lock();

	hlist_for_each_entry_rcu(svc, &user_ns->request_key_services, user_ns_link) {
		if (svc->type[0] &&
		    memcmp(svc->type, key->type->name, sizeof(svc->type)) != 0)
			continue;
		if ((svc->uts_ns && svc->uts_ns != nsproxy->uts_ns->ns.tag) ||
		    (svc->ipc_ns && svc->ipc_ns != nsproxy->ipc_ns->ns.tag) ||
		    (svc->mnt_ns && svc->mnt_ns != nsproxy->mnt_ns->ns.tag) ||
		    (svc->pid_ns && svc->pid_ns != pid_ns->ns.tag) ||
		    (svc->net_ns && svc->net_ns != nsproxy->net_ns->ns.tag) ||
		    (svc->cgroup_ns && svc->cgroup_ns != nsproxy->cgroup_ns->ns.tag))
			continue;
		goto found_match;
	}

	rcu_read_unlock();
	return -ENOPARAM;

found_match:
	spin_lock(&user_ns->request_key_services_lock);
	if (!svc->dead)
		queue_keyring = key_get(svc->queue_keyring);
	spin_unlock(&user_ns->request_key_services_lock);
	rcu_read_unlock();

	ret = -ENOPARAM;
	if (queue_keyring) {
		ret = key_link(queue_keyring, auth_key);
		if (ret < 0)
			key_reject_and_link(key, 0, ret, NULL, auth_key);
		key_put(queue_keyring);
	}

	return ret;
}

/*
 * Clear all the service intercept records on a user namespace.
 */
void clear_request_key_services(struct user_namespace *user_ns)
{
	struct request_key_service *svc;

	while (!hlist_empty(&user_ns->request_key_services)) {
		svc = hlist_entry(user_ns->request_key_services.first,
				  struct request_key_service, user_ns_link);
		hlist_del(&svc->user_ns_link);
		free_key_service(svc);
	}
}
