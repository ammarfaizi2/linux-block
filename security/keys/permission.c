// SPDX-License-Identifier: GPL-2.0-or-later
/* Key permission checking
 *
 * Copyright (C) 2005, 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/security.h>
#include <keys/request_key_auth-type.h>
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
EXPORT_SYMBOL(default_key_acl);

struct key_acl joinable_keyring_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.possessor_viewable = true,
	.aces	= {
		KEY_POSSESSOR_ACE(KEY_ACE__PERMS & ~KEY_ACE_JOIN),
		KEY_OWNER_ACE(KEY_ACE_VIEW | KEY_ACE_READ | KEY_ACE_LINK | KEY_ACE_JOIN),
	}
};
EXPORT_SYMBOL(joinable_keyring_acl);

struct key_acl internal_key_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.aces = {
		KEY_POSSESSOR_ACE(KEY_ACE_SEARCH),
		KEY_OWNER_ACE(KEY_ACE_VIEW | KEY_ACE_READ | KEY_ACE_SEARCH),
	}
};
EXPORT_SYMBOL(internal_key_acl);

struct key_acl internal_keyring_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.aces = {
		KEY_POSSESSOR_ACE(KEY_ACE_SEARCH | KEY_ACE_WRITE),
		KEY_OWNER_ACE(KEY_ACE_VIEW | KEY_ACE_READ | KEY_ACE_SEARCH),
	}
};
EXPORT_SYMBOL(internal_keyring_acl);

struct key_acl internal_writable_keyring_acl = {
	.usage	= REFCOUNT_INIT(1),
	.nr_ace	= 2,
	.aces = {
		KEY_POSSESSOR_ACE(KEY_ACE_SEARCH | KEY_ACE_WRITE),
		KEY_OWNER_ACE(KEY_ACE_VIEW | KEY_ACE_READ | KEY_ACE_WRITE | KEY_ACE_SEARCH),
	}
};
EXPORT_SYMBOL(internal_writable_keyring_acl);

/*
 * Determine if we have sufficient permission to perform an operation.
 */
static int check_key_permission(const key_ref_t key_ref, const struct cred *cred,
				unsigned int allow, enum key_need_perm need_perm,
				unsigned int *_notes)
{
	struct request_key_auth *rka;
	const struct key *key = key_ref_to_ptr(key_ref);

	switch (need_perm) {
	case KEY_NEED_ASSUME_AUTHORITY:
		return 0;

	case KEY_NEED_DESCRIBE:
	case KEY_NEED_GET_SECURITY:
		if (allow & KEY_ACE_VIEW)
			return 0;
		goto check_auth_override;

	case KEY_NEED_CHANGE_ACL:
	case KEY_NEED_CHOWN:
	case KEY_NEED_SET_RESTRICTION:
		return allow & KEY_ACE_SETSEC ? 0 : -EACCES;

	case KEY_NEED_INSTANTIATE:
		goto check_auth_override;

	case KEY_NEED_INVALIDATE:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		if (allow & KEY_ACE_INVAL)
			return 0;
		if (test_bit(KEY_FLAG_ROOT_CAN_INVAL, &key->flags))
			goto check_sysadmin_override;
		return -EACCES;

	case KEY_NEED_JOIN:
		return allow & KEY_ACE_JOIN ? 0 : -EACCES;

	case KEY_NEED_LINK:
		return allow & KEY_ACE_LINK ? 0 : -EACCES;

	case KEY_NEED_KEYRING_DELETE:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		/* Fall through. */
	case KEY_NEED_KEYRING_ADD:
		return allow & KEY_ACE_WRITE ? 0 : -EACCES;

	case KEY_NEED_KEYRING_CLEAR:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		if (allow & KEY_ACE_CLEAR)
			return 0;
		if (test_bit(KEY_FLAG_ROOT_CAN_CLEAR, &key->flags))
			goto check_sysadmin_override;
		return -EACCES;

	case KEY_NEED_READ:
		return allow & (KEY_ACE_READ | KEY_ACE_SEARCH) ? 0 : -EACCES;

	case KEY_NEED_REVOKE:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		return allow & KEY_ACE_REVOKE ? 0 : -EACCES;

	case KEY_NEED_SEARCH:
		return allow & KEY_ACE_SEARCH ? 0 : -EACCES;

	case KEY_NEED_SET_TIMEOUT:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		if (allow & KEY_ACE_SETSEC)
			return 0;
		goto check_auth_override;

	case KEY_NEED_UNLINK:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		return 0;

	case KEY_NEED_UPDATE:
		return allow & KEY_ACE_WRITE ? 0 : -EACCES;

	case KEY_NEED_USE:
		return allow & (KEY_ACE_READ | KEY_ACE_SEARCH) ? 0 : -EACCES;

	case KEY_NEED_WATCH:
		return allow & KEY_ACE_VIEW ? 0 : -EACCES;

	default:
		WARN_ON(1);
		return -EACCES;
	}

check_auth_override:
	if (!cred->request_key_auth)
		return -EACCES;
	rka = cred->request_key_auth->payload.data[0];
	if (rka->target_key != key)
		return -EACCES;
	*_notes |= KEY_PERMISSION_USED_AUTH_OVERRIDE;
	return 0;

check_sysadmin_override:
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	*_notes |= KEY_PERMISSION_USED_SYSADMIN_OVERRIDE;
	return 0;
}

/*
 * Resolve an ACL to a mask.
 */
static unsigned int key_resolve_acl(const key_ref_t key_ref, const struct cred *cred)
{
	const struct key *key = key_ref_to_ptr(key_ref);
	const struct key_acl *acl;
	unsigned int i, allow = 0;
	bool possessed = is_key_possessed(key_ref);

	acl = rcu_dereference(key->acl);
	if (!acl || acl->nr_ace == 0)
		return 0;

	for (i = 0; i < acl->nr_ace; i++) {
		const struct key_ace *ace = &acl->aces[i];

		switch (ace->type) {
		case KEY_ACE_SUBJ_STANDARD:
			switch (ace->subject_id) {
			case KEY_ACE_POSSESSOR:
				if (possessed)
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
		}
	}

	return allow;
}

/**
 * key_task_permission - Check a key can be used
 * @key_ref: The key to check.
 * @cred: The credentials to use.
 * @need_perm: The permission required.
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
			enum key_need_perm need_perm)
{
	unsigned int allow, notes = 0;
	int ret;

	rcu_read_lock();
	allow = key_resolve_acl(key_ref, cred);
	rcu_read_unlock();

	ret = check_key_permission(key_ref, cred, allow, need_perm, &notes);
	if (ret < 0)
		return ret;

	/* Let the LSMs be the final arbiter */
	return security_key_permission(key_ref, cred, need_perm, notes);
}

/**
 * key_search_permission - Check a key can be searched for
 * @key_ref: The key to check.
 * @cred: The credentials to use.
 * @need_perm: The permission required.
 *
 * Check to see whether permission is granted to use a key in the desired way,
 * but permit the security modules to override.
 *
 * The caller must hold the RCU readlock.
 *
 * Returns 0 if successful, -EACCES if access is denied based on the
 * permissions bits or the LSM check.
 */
int key_search_permission(const key_ref_t key_ref,
			  struct keyring_search_context *ctx,
			  enum key_need_perm need_perm)
{
	unsigned int allow, notes = 0;
	int ret;

	allow = key_resolve_acl(key_ref, ctx->cred);

	ret = check_key_permission(key_ref, ctx->cred, allow, need_perm, &notes);
	if (ret < 0)
		return ret;

	/* Let the LSMs be the final arbiter */
	return security_key_permission(key_ref, ctx->cred, need_perm, notes);
}

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
	unsigned int perm = 0, tperm;
	int i;

	BUILD_BUG_ON(KEY_OTH_VIEW	!= KEY_ACE_VIEW		||
		     KEY_OTH_READ	!= KEY_ACE_READ		||
		     KEY_OTH_WRITE	!= KEY_ACE_WRITE	||
		     KEY_OTH_SEARCH	!= KEY_ACE_SEARCH	||
		     KEY_OTH_LINK	!= KEY_ACE_LINK		||
		     KEY_OTH_SETATTR	!= KEY_ACE_SETSEC);

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
 * Destroy a key's ACL.
 */
void key_put_acl(struct key_acl *acl)
{
	if (acl && refcount_dec_and_test(&acl->usage))
		kfree_rcu(acl, rcu);
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

	acl = rcu_replace_pointer(key->acl, acl, lockdep_is_held(&key->sem));
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

	for (i = 0; i < old->nr_ace; i++)
		if (old->aces[i].type == new_ace->type &&
		    old->aces[i].subject_id == new_ace->subject_id)
			goto found_match;

	if (new_ace->perm == 0)
		return 0; /* No permissions to remove.  Add deny record? */

	acl = key_alloc_acl(old, 1, -1);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	acl->aces[i] = *new_ace;
	goto change;

found_match:
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

	new_ace.type = type;
	new_ace.perm = perm;

	switch (type) {
	case KEY_ACE_SUBJ_STANDARD:
		if (subject >= nr__key_ace_standard_subject)
			return -ENOENT;
		new_ace.subject_id = subject;
		break;

	default:
		return -ENOENT;
	}

	key_ref = lookup_user_key(keyid, KEY_LOOKUP_PARTIAL, KEY_NEED_CHANGE_ACL);
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
	return ret;
}
