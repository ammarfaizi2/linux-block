/* scm_identity.c - SCM_IDENTITY implementation
 * Copyright (c) 2014 Andy Lutomirski
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/signal.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/stat.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/net.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/security.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include <net/protocol.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/compat.h>
#include <net/scm.h>
#include <net/cls_cgroup.h>

#define SCMID_UID 0
#define SCMID_GID 1
#define SCMID_PID 2

#define SCMIDF_AUTOFILL 0	/* autofill the payload */
#define SCMIDF_IGNORE_UNKNOWN 1	/* silently drop unknown values */

struct scmid_type {
	/* userval == NULL means autofill. */
	struct scm_identity_entry *(*send)(const void *userval, size_t len);
};

static const struct scmid_type scmid_types[];

struct scm_identity_header {
	u32 type;
	u32 flags;
};

struct scm_identity_entry {
	struct list_head list;
	u32 type;
	unsigned char value[];
};

static struct scm_identity_entry *send_uid(const void *userval, size_t len)
{
	const struct cred *cred = current_cred();
	struct scm_identity_entry *entry;
	kuid_t uid;

	if (userval) {
		if (len != sizeof(u32))
			return ERR_PTR(-EINVAL);
		uid = make_kuid(cred->user_ns, *(u32 *)userval);
		if (!uid_valid(uid))
			return ERR_PTR(-EPERM);
		if (!uid_eq(uid, cred->uid) && !uid_eq(uid, cred->euid) &&
		    !uid_eq(uid, cred->suid) &&
		    !ns_capable(cred->user_ns, CAP_SETUID))
			return ERR_PTR(-EPERM);
	} else {
		uid = cred->euid;
	}

	entry = kmalloc(sizeof(struct scm_identity_entry) + sizeof(kuid_t),
			GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	*(kuid_t *)(&entry->value) = uid;
	return entry;
}

static const struct scmid_type scmid_types[] = {
	[SCMID_UID] = {.send = send_uid},
};

int scm_add_identity(struct list_head *cookie_list, const struct cmsghdr *cmsg)
{
	struct scm_identity_entry *entry;
	const struct scm_identity_header *header;
	size_t total_len, value_len;

	total_len = cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr));
	if (total_len < sizeof(struct scm_identity_header))
		return -EINVAL;

	header = CMSG_DATA(cmsg);
	value_len = total_len - sizeof(struct scm_identity_header);

	/* Validate. */
	if (header->flags & ~(SCMIDF_AUTOFILL | SCMIDF_IGNORE_UNKNOWN))
		return -EINVAL;
	if ((header->flags & SCMIDF_AUTOFILL) && value_len != 0)
		return -EINVAL;
	if (header >= ARRAY_SIZE(scmid_types))
		return (header->flags & SCMIDF_IGNORE_UNKNOWN) ? 0 : -EINVAL;

	/* Handle this entry. */
	entry = scmid_types[header->type].send(
		(header->flags & SCMIDF_AUTOFILL) ? NULL : (header + 1),
		value_len);
	if (IS_ERR(entry))
		return PTR_ERR(entry);

	entry->type = header->type;
	list_add_tail(&entry->list, cookie_list);
	return 0;
}
