// SPDX-License-Identifier: GPL-2.0-or-later
/* Key permission checking
 *
 * Copyright (C) 2005 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/security.h>
#include <keys/request_key_auth-type.h>
#include "internal.h"

/*
 * Determine if we have sufficient permission to perform an operation.
 */
static int check_key_permission(struct key *key, const struct cred *cred,
				key_perm_t perms, enum key_need_perm need_perm,
				unsigned int *_notes)
{
	struct request_key_auth *rka;

	switch (need_perm) {
	case KEY_NEED_ASSUME_AUTHORITY:
		return 0;

	case KEY_NEED_DESCRIBE:
	case KEY_NEED_GET_SECURITY:
		if (perms & KEY_OTH_VIEW)
			return 0;
		goto check_auth_override;

	case KEY_NEED_CHOWN:
	case KEY_NEED_SETPERM:
	case KEY_NEED_SET_RESTRICTION:
		return perms & KEY_OTH_SETATTR ? 0 : -EACCES;

	case KEY_NEED_INSTANTIATE:
		goto check_auth_override;

	case KEY_NEED_INVALIDATE:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		if (perms & KEY_OTH_SEARCH)
			return 0;
		if (test_bit(KEY_FLAG_ROOT_CAN_INVAL, &key->flags))
			goto check_sysadmin_override;
		return -EACCES;

	case KEY_NEED_JOIN:
	case KEY_NEED_LINK:
		return perms & KEY_OTH_LINK ? 0 : -EACCES;

	case KEY_NEED_KEYRING_DELETE:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		/* Fall through. */
	case KEY_NEED_KEYRING_ADD:
		return perms & KEY_OTH_WRITE ? 0 : -EACCES;

	case KEY_NEED_KEYRING_CLEAR:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		if (perms & KEY_OTH_WRITE)
			return 0;
		if (test_bit(KEY_FLAG_ROOT_CAN_CLEAR, &key->flags))
			goto check_sysadmin_override;
		return -EACCES;

	case KEY_NEED_READ:
		return perms & (KEY_OTH_READ | KEY_OTH_SEARCH) ? 0 : -EACCES;

	case KEY_NEED_REVOKE:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		return perms & (KEY_OTH_WRITE | KEY_OTH_SETATTR) ? 0 : -EACCES;

	case KEY_NEED_SEARCH:
		return perms & KEY_OTH_SEARCH ? 0 : -EACCES;

	case KEY_NEED_SET_TIMEOUT:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		if (perms & KEY_OTH_SETATTR)
			return 0;
		goto check_auth_override;

	case KEY_NEED_UNLINK:
		if (test_bit(KEY_FLAG_KEEP, &key->flags))
			return -EPERM;
		return 0;

	case KEY_NEED_UPDATE:
		return perms & KEY_OTH_WRITE ? 0 : -EACCES;

	case KEY_NEED_USE:
		return perms & (KEY_OTH_READ | KEY_OTH_SEARCH) ? 0 : -EACCES;

	case KEY_NEED_WATCH:
		return perms & KEY_OTH_VIEW ? 0 : -EACCES;

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
	struct key *key;
	unsigned int notes = 0;
	key_perm_t kperm;
	int ret;

	key = key_ref_to_ptr(key_ref);

	/* use the second 8-bits of permissions for keys the caller owns */
	if (uid_eq(key->uid, cred->fsuid)) {
		kperm = key->perm >> 16;
		goto use_these_perms;
	}

	/* use the third 8-bits of permissions for keys the caller has a group
	 * membership in common with */
	if (gid_valid(key->gid) && key->perm & KEY_GRP_ALL) {
		if (gid_eq(key->gid, cred->fsgid)) {
			kperm = key->perm >> 8;
			goto use_these_perms;
		}

		ret = groups_search(cred->group_info, key->gid);
		if (ret) {
			kperm = key->perm >> 8;
			goto use_these_perms;
		}
	}

	/* otherwise use the least-significant 8-bits */
	kperm = key->perm;

use_these_perms:
	/* use the top 8-bits of permissions for keys the caller possesses
	 * - possessor permissions are additive with other permissions
	 */
	if (is_key_possessed(key_ref))
		kperm |= key->perm >> 24;

	ret = check_key_permission(key, cred, kperm & KEY_OTH_ALL, need_perm,
				   &notes);
	if (ret < 0)
		return ret;

	/* Let the LSMs be the final arbiter */
	return security_key_permission(key_ref, cred, need_perm, notes);
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
