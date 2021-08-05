/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Authentication token and access key management
 *
 * Copyright (C) 2004, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * See Documentation/security/keys/core.rst for information on keys/keyrings.
 */

#ifndef _LINUX_KEY_TYPES_H
#define _LINUX_KEY_TYPES_H

#ifdef __KERNEL__

/*
 * The permissions required on a key that we're looking up.
 */
enum key_need_perm {
	KEY_NEED_UNSPECIFIED,	/* Needed permission unspecified */
	KEY_NEED_VIEW,		/* Require permission to view attributes */
	KEY_NEED_READ,		/* Require permission to read content */
	KEY_NEED_WRITE,		/* Require permission to update / modify */
	KEY_NEED_SEARCH,	/* Require permission to search (keyring) or find (key) */
	KEY_NEED_LINK,		/* Require permission to link */
	KEY_NEED_SETATTR,	/* Require permission to change attributes */
	KEY_NEED_UNLINK,	/* Require permission to unlink key */
	KEY_SYSADMIN_OVERRIDE,	/* Special: override by CAP_SYS_ADMIN */
	KEY_AUTHTOKEN_OVERRIDE,	/* Special: override by possession of auth token */
	KEY_DEFER_PERM_CHECK,	/* Special: permission check is deferred */
};

#endif /* __KERNEL__ */

#endif /* _LINUX_KEY_TYPES_H */
