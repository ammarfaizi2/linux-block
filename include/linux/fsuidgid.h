/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FSUIDGID_H
#define _LINUX_FSUIDGID_H

#include <linux/uidgid.h>

#ifdef CONFIG_USER_NS_FSID

extern kuid_t make_kfsuid(struct user_namespace *from, uid_t fsuid);
extern kgid_t make_kfsgid(struct user_namespace *from, gid_t fsgid);
extern uid_t from_kfsuid(struct user_namespace *to, kuid_t kfsuid);
extern gid_t from_kfsgid(struct user_namespace *to, kgid_t kfsgid);
extern uid_t from_kfsuid_munged(struct user_namespace *to, kuid_t kfsuid);
extern gid_t from_kfsgid_munged(struct user_namespace *to, kgid_t kfsgid);

static inline bool kfsuid_has_mapping(struct user_namespace *ns, kuid_t kfsuid)
{
	return from_kfsuid(ns, kfsuid) != (uid_t) -1;
}

static inline bool kfsgid_has_mapping(struct user_namespace *ns, kgid_t kfsgid)
{
	return from_kfsgid(ns, kfsgid) != (gid_t) -1;
}

static inline kuid_t kfsuid_to_kuid(struct user_namespace *to, kuid_t kfsuid)
{
	uid_t fsuid = from_kfsuid(to, kfsuid);
	if (fsuid == (uid_t) -1)
		return INVALID_UID;
	return make_kuid(to, fsuid);
}

static inline kgid_t kfsgid_to_kgid(struct user_namespace *to, kgid_t kfsgid)
{
	gid_t fsgid = from_kfsgid(to, kfsgid);
	if (fsgid == (gid_t) -1)
		return INVALID_GID;
	return make_kgid(to, fsgid);
}

static inline kuid_t kuid_to_kfsuid(struct user_namespace *to, kuid_t kuid)
{
	uid_t uid = from_kuid(to, kuid);
	if (uid == (uid_t) -1)
		return INVALID_UID;
	return make_kfsuid(to, uid);
}

static inline kgid_t kgid_to_kfsgid(struct user_namespace *to, kgid_t kgid)
{
	gid_t gid = from_kgid(to, kgid);
	if (gid == (gid_t) -1)
		return INVALID_GID;
	return make_kfsgid(to, gid);
}

#else

static inline kuid_t make_kfsuid(struct user_namespace *from, uid_t fsuid)
{
	return make_kuid(from, fsuid);
}

static inline kgid_t make_kfsgid(struct user_namespace *from, gid_t fsgid)
{
	return make_kgid(from, fsgid);
}

static inline uid_t from_kfsuid(struct user_namespace *to, kuid_t kfsuid)
{
	return from_kuid(to, kfsuid);
}

static inline gid_t from_kfsgid(struct user_namespace *to, kgid_t kfsgid)
{
	return from_kgid(to, kfsgid);
}

static inline uid_t from_kfsuid_munged(struct user_namespace *to, kuid_t kfsuid)
{
	return from_kuid_munged(to, kfsuid);
}

static inline gid_t from_kfsgid_munged(struct user_namespace *to, kgid_t kfsgid)
{
	return from_kgid_munged(to, kfsgid);
}

static inline bool kfsuid_has_mapping(struct user_namespace *ns, kuid_t kfsuid)
{
	return kuid_has_mapping(ns, kfsuid);
}

static inline bool kfsgid_has_mapping(struct user_namespace *ns, kgid_t kfsgid)
{
	return kgid_has_mapping(ns, kfsgid);
}

static inline kuid_t kfsuid_to_kuid(struct user_namespace *to, kuid_t kfsuid)
{
	return kfsuid;
}

static inline kgid_t kfsgid_to_kgid(struct user_namespace *to, kgid_t kfsgid)
{
	return kfsgid;
}

static inline kuid_t kuid_to_kfsuid(struct user_namespace *to, kuid_t kuid)
{
	return kuid;
}

static inline kgid_t kgid_to_kfsgid(struct user_namespace *to, kgid_t kgid)
{
	return kgid;
}

#endif /* CONFIG_USER_NS_FSID */

#endif /* _LINUX_FSUIDGID_H */
