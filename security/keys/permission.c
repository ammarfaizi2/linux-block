/* Key permission checking
 *
 * Copyright (C) 2005 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/export.h>
#include <linux/security.h>
#include <linux/user_namespace.h>
#include <linux/uaccess.h>
#include <linux/container.h>
#include "internal.h"

struct key_acl default_key_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.possessor_viewable = true,
	.aces = {
		KEY_POSSESSOR_ACE(KEY_ACE__PERMS & ~KEY_ACE_JOIN),
		KEY_OWNER_ACE(KEY_ACE_VIEW),
	}
};

struct key_acl joinable_keyring_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.possessor_viewable = true,
	.aces	= {
		KEY_POSSESSOR_ACE(KEY_ACE__PERMS & ~KEY_ACE_JOIN),
		KEY_OWNER_ACE(KEY_ACE_VIEW | KEY_ACE_READ | KEY_ACE_LINK | KEY_ACE_JOIN),
	}
};

struct key_acl internal_key_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.aces = {
		KEY_POSSESSOR_ACE(KEY_ACE_SEARCH),
		KEY_OWNER_ACE(KEY_ACE_VIEW | KEY_ACE_READ | KEY_ACE_SEARCH),
	}
};

struct key_acl internal_keyring_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.aces = {
		KEY_POSSESSOR_ACE(KEY_ACE_SEARCH),
		KEY_OWNER_ACE(KEY_ACE_VIEW | KEY_ACE_READ | KEY_ACE_SEARCH),
	}
};

struct key_acl internal_writable_keyring_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.aces = {
		KEY_POSSESSOR_ACE(KEY_ACE_SEARCH | KEY_ACE_WRITE),
		KEY_OWNER_ACE(KEY_ACE_VIEW | KEY_ACE_READ | KEY_ACE_WRITE | KEY_ACE_SEARCH),
	}
};

/**
 * key_task_permission - Check a key can be used
 * @key_ref: The key to check.
 * @cred: The credentials to use.
 * @desired_perm: The permission to check for.
 *
 * Check to see whether permission is granted to use a key in the desired way,
 * but permit the security modules to override.
 *
 * The caller must hold either a ref on cred or must hold the RCU readlock.
 *
 * Returns 0 if successful, -EACCES if access is denied based on the
 * permissions bits or the LSM check.
 */
int key_task_permission(const key_ref_t key_ref, const struct cred *cred,
			unsigned int desired_perm)
{
	const struct key_acl *acl;
	const struct key *key;
	unsigned int allow = 0;
	int i;

	BUILD_BUG_ON(KEY_NEED_VIEW	!= KEY_ACE_VIEW		||
		     KEY_NEED_READ	!= KEY_ACE_READ		||
		     KEY_NEED_WRITE	!= KEY_ACE_WRITE	||
		     KEY_NEED_SEARCH	!= KEY_ACE_SEARCH	||
		     KEY_NEED_LINK	!= KEY_ACE_LINK		||
		     KEY_NEED_SETSEC	!= KEY_ACE_SET_SECURITY	||
		     KEY_NEED_INVAL	!= KEY_ACE_INVAL	||
		     KEY_NEED_REVOKE	!= KEY_ACE_REVOKE	||
		     KEY_NEED_JOIN	!= KEY_ACE_JOIN		||
		     KEY_NEED_CLEAR	!= KEY_ACE_CLEAR);

	key = key_ref_to_ptr(key_ref);

	rcu_read_lock();

	acl = rcu_dereference(key->acl);
	if (!acl || acl->nr_ace == 0)
		goto no_access_rcu;

	for (i = 0; i < acl->nr_ace; i++) {
		const struct key_ace *ace = &acl->aces[i];

		switch (ace->type) {
		case KEY_ACE_SUBJ_STANDARD:
			switch (ace->subject_id) {
			case KEY_ACE_POSSESSOR:
				if (is_key_possessed(key_ref))
					allow |= ace->perm;
				break;
			case KEY_ACE_OWNER:
				if (uid_eq(key->uid, cred->fsuid))
					allow |= ace->perm;
				break;
			case KEY_ACE_GROUP:
				if (gid_valid(key->gid)) {
					if (gid_eq(key->gid, cred->fsgid))
						allow |= ace->perm;
					else if (groups_search(cred->group_info, key->gid))
						allow |= ace->perm;
				}
				break;
			case KEY_ACE_EVERYONE:
				allow |= ace->perm;
				break;
			}
			break;
#ifdef CONFIG_CONTAINERS
		case KEY_ACE_SUBJ_CONTAINER: {
			const struct key_tag *tag = rcu_dereference(ace->container_tag);

			if (!tag->removed && current->container->tag == tag)
				allow |= ace->perm;
			break;
		}
#endif
		}
	}

	rcu_read_unlock();

	if (!(allow & desired_perm))
		goto no_access;

	return security_key_permission(key_ref, cred, desired_perm);

no_access_rcu:
	rcu_read_unlock();
no_access:
	return -EACCES;
}
EXPORT_SYMBOL(key_task_permission);

/**
 * key_validate - Validate a key.
 * @key: The key to be validated.
 *
 * Check that a key is valid, returning 0 if the key is okay, -ENOKEY if the
 * key is invalidated, -EKEYREVOKED if the key's type has been removed or if
 * the key has been revoked or -EKEYEXPIRED if the key has expired.
 */
int key_validate(const struct key *key)
{
	unsigned long flags = READ_ONCE(key->flags);
	time64_t expiry = READ_ONCE(key->expiry);

	if (flags & (1 << KEY_FLAG_INVALIDATED))
		return -ENOKEY;

	/* check it's still accessible */
	if (flags & ((1 << KEY_FLAG_REVOKED) |
		     (1 << KEY_FLAG_DEAD)))
		return -EKEYREVOKED;

	/* check it hasn't expired */
	if (expiry) {
		if (ktime_get_real_seconds() >= expiry)
			return -EKEYEXPIRED;
	}

	return 0;
}
EXPORT_SYMBOL(key_validate);

/*
 * Roughly render an ACL to an old-style permissions mask.  We cannot
 * accurately render what the ACL, particularly if it has ACEs that represent
 * subjects outside of { poss, user, group, other }.
 */
unsigned int key_acl_to_perm(const struct key_acl *acl)
{
	unsigned int perm = 0, tperm, i;

	BUILD_BUG_ON(KEY_OTH_VIEW	!= KEY_ACE_VIEW		||
		     KEY_OTH_READ	!= KEY_ACE_READ		||
		     KEY_OTH_WRITE	!= KEY_ACE_WRITE	||
		     KEY_OTH_SEARCH	!= KEY_ACE_SEARCH	||
		     KEY_OTH_LINK	!= KEY_ACE_LINK		||
		     KEY_OTH_SETATTR	!= KEY_ACE_SET_SECURITY);

	if (!acl || acl->nr_ace == 0)
		return 0;

	for (i = 0; i < acl->nr_ace; i++) {
		const struct key_ace *ace = &acl->aces[i];

		switch (ace->type) {
		case KEY_ACE_SUBJ_STANDARD:
			tperm = ace->perm & KEY_OTH_ALL;

			/* Invalidation and joining were allowed by SEARCH */
			if (ace->perm & (KEY_ACE_INVAL | KEY_ACE_JOIN))
				tperm |= KEY_OTH_SEARCH;

			/* Revocation was allowed by either SETATTR or WRITE */
			if ((ace->perm & KEY_ACE_REVOKE) && !(tperm & KEY_OTH_SETATTR))
				tperm |= KEY_OTH_WRITE;

			/* Clearing was allowed by WRITE */
			if (ace->perm & KEY_ACE_CLEAR)
				tperm |= KEY_OTH_WRITE;

			switch (ace->subject_id) {
			case KEY_ACE_POSSESSOR:
				perm |= tperm << 24;
				break;
			case KEY_ACE_OWNER:
				perm |= tperm << 16;
				break;
			case KEY_ACE_GROUP:
				perm |= tperm << 8;
				break;
			case KEY_ACE_EVERYONE:
				perm |= tperm << 0;
				break;
			}
		}
	}

	return perm;
}

/*
 * Clean up an ACL.
 */
static void key_free_acl(struct rcu_head *rcu)
{
	struct key_acl *acl = container_of(rcu, struct key_acl, rcu);
#ifdef CONFIG_CONTAINERS
	struct key_tag *tag;
	unsigned int i;

	for (i = 0; i < acl->nr_ace; i++) {
		const struct key_ace *ace = &acl->aces[i];
		switch (ace->type) {
		case KEY_ACE_SUBJ_CONTAINER:
			tag = rcu_access_pointer(ace->container_tag);
			key_put_tag(ace->container_tag);
			break;
		}
	}
#endif

	kfree(acl);
}

/*
 * Destroy a key's ACL.
 */
void key_put_acl(struct key_acl *acl)
{
	if (acl && refcount_dec_and_test(&acl->usage))
		call_rcu(&acl->rcu, key_free_acl);
}

/*
 * Try to set the ACL.  This either attaches or discards the proposed ACL.
 */
long key_set_acl(struct key *key, struct key_acl *acl)
{
	int i;

	/* If we're not the sysadmin, we can only change a key that we own. */
	if (!capable(CAP_SYS_ADMIN) && !uid_eq(key->uid, current_fsuid())) {
		key_put_acl(acl);
		return -EACCES;
	}

	for (i = 0; i < acl->nr_ace; i++) {
		const struct key_ace *ace = &acl->aces[i];
		if (ace->type == KEY_ACE_SUBJ_STANDARD &&
		    ace->subject_id == KEY_ACE_POSSESSOR) {
			if (ace->perm & KEY_ACE_VIEW)
				acl->possessor_viewable = true;
			break;
		}
	}

	rcu_swap_protected(key->acl, acl, lockdep_is_held(&key->sem));
	notify_key(key, NOTIFY_KEY_SETATTR, 0);
	key_put_acl(acl);
	return 0;
}

/*
 * Allocate a new ACL with an extra ACE slot.
 */
static struct key_acl *key_alloc_acl(const struct key_acl *old_acl, int nr, int skip)
{
	struct key_acl *acl;
	int nr_ace, i, j = 0;

	nr_ace = old_acl->nr_ace + nr;
	if (nr_ace > 16)
		return ERR_PTR(-EINVAL);

	acl = kzalloc(struct_size(acl, aces, nr_ace), GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);

	refcount_set(&acl->usage, 1);
	acl->nr_ace = nr_ace;
	for (i = 0; i < old_acl->nr_ace; i++) {
		if (i == skip)
			continue;
		acl->aces[j] = old_acl->aces[i];
#ifdef CONFIG_CONTAINERS
		if (acl->aces[j].type == KEY_ACE_SUBJ_CONTAINER)
			refcount_inc(&acl->aces[j].container_tag->usage);
#endif
		j++;
	}
	return acl;
}

/*
 * Generate the revised ACL.
 */
static long key_change_acl(struct key *key, struct key_ace *new_ace)
{
	struct key_acl *acl, *old;
	int i;

	old = rcu_dereference_protected(key->acl, lockdep_is_held(&key->sem));

	for (i = 0; i < old->nr_ace; i++) {
		if (old->aces[i].type != new_ace->type)
			continue;
		switch (old->aces[i].type) {
		case KEY_ACE_SUBJ_STANDARD:
			if (old->aces[i].subject_id == new_ace->subject_id)
				goto replace_ace;
			break;
#ifdef CONFIG_CONTAINERS
		case KEY_ACE_SUBJ_CONTAINER:
			if (old->aces[i].container_tag == new_ace->container_tag)
				goto replace_ace;
			break;
#endif
		default:
			break;
		}
	}

	if (new_ace->perm == 0)
		return 0; /* No permissions to cancel.  Add deny record? */

	acl = key_alloc_acl(old, 1, -1);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	acl->aces[i] = *new_ace;
#ifdef CONFIG_CONTAINERS
	if (acl->aces[i].type == KEY_ACE_SUBJ_CONTAINER)
		refcount_inc(&acl->aces[i].container_tag->usage);
#endif
	goto change;

replace_ace:
	if (new_ace->perm == 0)
		goto delete_ace;
	if (new_ace->perm == old->aces[i].perm)
		return 0;
	acl = key_alloc_acl(old, 0, -1);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	acl->aces[i].perm = new_ace->perm;
	goto change;

delete_ace:
	acl = key_alloc_acl(old, -1, i);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	goto change;

change:
	return key_set_acl(key, acl);
}

/*
 * Add, alter or remove (if perm == 0) an ACE in a key's ACL.
 */
long keyctl_grant_permission(key_serial_t keyid,
			     enum key_ace_subject_type type,
			     unsigned int subject,
			     unsigned int perm)
{
	struct key_ace new_ace;
	struct key *key;
	key_ref_t key_ref;
	long ret;

	memset(&new_ace, 0, sizeof(new_ace));
	new_ace.type = type;
	new_ace.perm = perm;

	switch (type) {
	case KEY_ACE_SUBJ_STANDARD:
		if (subject >= nr__key_ace_standard_subject)
			return -ENOENT;
		new_ace.subject_id = subject;
		break;

#ifdef CONFIG_CONTAINERS
	case KEY_ACE_SUBJ_CONTAINER: {
		struct container *c = fd_to_container(subject);
		if (IS_ERR(c))
			return -EINVAL;
		refcount_inc(&c->tag->usage);
		new_ace.container_tag = c->tag;
		put_container(c);
		break;
	}
#endif

	default:
		return -ENOENT;
	}

	key_ref = lookup_user_key(keyid, KEY_LOOKUP_PARTIAL, KEY_NEED_SETSEC);
	if (IS_ERR(key_ref)) {
		ret = PTR_ERR(key_ref);
		goto error;
	}

	key = key_ref_to_ptr(key_ref);

	down_write(&key->sem);

	/* If we're not the sysadmin, we can only change a key that we own */
	ret = -EACCES;
	if (capable(CAP_SYS_ADMIN) || uid_eq(key->uid, current_fsuid()))
		ret = key_change_acl(key, &new_ace);
	up_write(&key->sem);
	key_put(key);
error:
#ifdef CONFIG_CONTAINERS
	if (new_ace.type == KEY_ACE_SUBJ_CONTAINER && new_ace.container_tag)
		key_put_tag(new_ace.container_tag);
#endif
	return ret;
}
