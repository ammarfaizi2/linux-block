/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FSUIDGID_H
#define _LINUX_FSUIDGID_H

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

typedef struct {
	uid_t val;
} kfsuid_t;

typedef struct {
	gid_t val;
} kfsgid_t;

#define KFSUIDT_INIT(value) (kfsuid_t){ value }
#define KFSGIDT_INIT(value) (kfsgid_t){ value }
#define INVALID_KFSUID KFSUIDT_INIT(-1)
#define INVALID_KFSGID KFSGIDT_INIT(-1)

#ifdef CONFIG_MULTIUSER
static inline uid_t __kfsuid_val(kfsuid_t uid)
{
	return uid.val;
}

static inline gid_t __kfsgid_val(kfsgid_t gid)
{
	return gid.val;
}
#else
static inline uid_t __kfsuid_val(kfsuid_t uid)
{
	return 0;
}

static inline gid_t __kfsgid_val(kfsgid_t gid)
{
	return 0;
}
#endif

static inline bool kfsuid_valid(kfsuid_t uid)
{
	return __kfsuid_val(uid) != (uid_t)-1;
}

static inline bool kfsgid_valid(kfsgid_t gid)
{
	return __kfsgid_val(gid) != (gid_t)-1;
}

static inline bool kfsuid_eq(kfsuid_t left, kfsuid_t right)
{
	return __kfsuid_val(left) == __kfsuid_val(right);
}

#define __fsuid_val(fsuid) _Generic((fsuid), \
		kuid_t:   __kuid_val, \
		kfsuid_t: __kfsuid_val)(fsuid)

#define __fsgid_val(fsgid) _Generic((fsgid), \
		kgid_t:   __kgid_val, \
		kfsgid_t: __kfsgid_val)(fsgid)

#define __id_val(id) _Generic(id, \
		kfsuid_t:   __kfsuid_val, \
		kfsgid_t:   __kfsgid_val, \
		kuid_t:	    __kuid_val, \
		kgid_t:	    __kgid_val)(id)

#define to_idtype(id) _Generic((id),			\
		kuid_t:   KFSUIDT_INIT(__id_val(id)),	\
		kgid_t:   KFSGIDT_INIT(__id_val(id)),	\
		kfsuid_t: KUIDT_INIT(__id_val(id)),	\
		kfsgid_t: KGIDT_INIT(__id_val(id)))

/*
 * Allows to compare kfsuid and kuids by automatically selecting the correct
 * function based on the type.
 * This is handy for filesystems that do provide a uid and gid mount option
 * that is global to the filesystem and won't be idmapped. The alternative is
 * to simply change the type temporarily but this solution here is cleaner.
 */
#define fsuid_eq(left, right)                                                  \
	({                                                                     \
		BUILD_BUG_ON_MSG(__same_type(left, right),                     \
				 "Must compare kfsuid_t and kuid_t type");     \
		__fsuid_val(left) == __fsuid_val(right);                       \
	})

#define fsgid_eq(left, right)                                                  \
	({                                                                     \
		BUILD_BUG_ON_MSG(__same_type(left, right),                     \
				 "Must compare kfsgid_t and kgid_t type");     \
		__fsgid_val(left) == __fsgid_val(right);                       \
	})

static inline bool kfsuid_has_mapping(struct user_namespace *user_ns,
				      kfsuid_t kfsuid)
{
	return kuid_has_mapping(user_ns, to_idtype(kfsuid));
}

static inline bool kfsgid_has_mapping(struct user_namespace *user_ns,
				      kfsgid_t kfsgid)
{
	return kgid_has_mapping(user_ns, to_idtype(kfsgid));
}

/**
 * kuid_into_mnt - map a kuid down into a mnt_userns
 * @mnt_userns: user namespace of the relevant mount
 * @kuid: kuid to be mapped
 *
 * Return: @kuid mapped according to @mnt_userns.
 * If @kuid has no mapping INVALID_UID is returned.
 */
static inline kuid_t kuid_into_mnt(struct user_namespace *mnt_userns,
				   kuid_t kuid)
{
	return make_kuid(mnt_userns, __kuid_val(kuid));
}

/**
 * kgid_into_mnt - map a kgid down into a mnt_userns
 * @mnt_userns: user namespace of the relevant mount
 * @kgid: kgid to be mapped
 *
 * Return: @kgid mapped according to @mnt_userns.
 * If @kgid has no mapping INVALID_GID is returned.
 */
static inline kgid_t kgid_into_mnt(struct user_namespace *mnt_userns,
				   kgid_t kgid)
{
	return make_kgid(mnt_userns, __kgid_val(kgid));
}

/**
 * kuid_from_mnt - map a kuid up into a mnt_userns
 * @mnt_userns: user namespace of the relevant mount
 * @kuid: kuid to be mapped
 *
 * Return: @kuid mapped up according to @mnt_userns.
 * If @kuid has no mapping INVALID_UID is returned.
 */
static inline kuid_t kuid_from_mnt(struct user_namespace *mnt_userns,
				   kuid_t kuid)
{
	return KUIDT_INIT(from_kuid(mnt_userns, kuid));
}

/**
 * kgid_from_mnt - map a kgid up into a mnt_userns
 * @mnt_userns: user namespace of the relevant mount
 * @kgid: kgid to be mapped
 *
 * Return: @kgid mapped up according to @mnt_userns.
 * If @kgid has no mapping INVALID_GID is returned.
 */
static inline kgid_t kgid_from_mnt(struct user_namespace *mnt_userns,
				   kgid_t kgid)
{
	return KGIDT_INIT(from_kgid(mnt_userns, kgid));
}

/**
 * make_fs_kfsuid - create a kfsuid from a kuid created by a filesystem/vfs
 */
static inline kfsuid_t make_fs_kfsuid(struct user_namespace *mnt_userns,
				      struct user_namespace *fs_userns,
				      kuid_t kuid)
{
	uid_t uid;

	uid = from_kuid(fs_userns, kuid);
	if (uid == (uid_t)-1)
		return INVALID_KFSUID;

	kuid = make_kuid(mnt_userns, uid);
	return KFSUIDT_INIT(__kuid_val(kuid));
}

static inline kfsgid_t make_fs_kfsgid(struct user_namespace *mnt_userns,
				      struct user_namespace *fs_userns,
				      kgid_t kgid)
{
	gid_t gid;

	gid = from_kgid(fs_userns, kgid);
	if (gid == (gid_t)-1)
		return INVALID_KFSGID;

	kgid = make_kgid(mnt_userns, gid);
	return KFSGIDT_INIT(__kgid_val(kgid));
}

/**
 * make_user_kfsuid - create a kfsuid from a kuid created from userspace
 */
static inline kfsuid_t make_user_kfsuid(struct user_namespace *mnt_userns,
					struct user_namespace *fs_userns,
					kuid_t kuid)
{
	uid_t uid;

	uid = from_kuid(mnt_userns, kuid);
	if (uid == (uid_t)-1)
		return INVALID_KFSUID;

	kuid = make_kuid(fs_userns, uid);
	return KFSUIDT_INIT(__kuid_val(kuid));
}

static inline kfsgid_t make_user_kfsgid(struct user_namespace *mnt_userns,
					struct user_namespace *fs_userns,
					kgid_t kgid)
{
	gid_t gid;

	gid = from_kgid(mnt_userns, kgid);
	if (gid == (gid_t)-1)
		return INVALID_KFSGID;

	kgid = make_kgid(fs_userns, gid);
	return KFSGIDT_INIT(__kgid_val(kgid));
}

static inline uid_t from_kfsuid(struct user_namespace *to, kfsuid_t kfsuid)
{
	return from_kuid(to, to_idtype(kfsuid));
}

static inline gid_t from_kfsgid(struct user_namespace *to, kfsgid_t kfsgid)
{
	return from_kgid(to, to_idtype(kfsgid));
}

static inline uid_t from_kfsuid_munged(struct user_namespace *to, kfsuid_t kfsuid)
{
	return from_kuid_munged(to, to_idtype(kfsuid));
}

static inline gid_t from_kfsgid_munged(struct user_namespace *to, kfsgid_t kfsgid)
{
	return from_kgid_munged(to, to_idtype(kfsgid));
}

/**
 * mapped_fsuid - return caller's fsuid mapped up into a mnt_userns
 * @mnt_userns: user namespace of the relevant mount
 *
 * Use this helper to initialize a new vfs or filesystem object based on
 * the caller's fsuid. A common example is initializing the i_uid field of
 * a newly allocated inode triggered by a creation event such as mkdir or
 * O_CREAT. Other examples include the allocation of quotas for a specific
 * user.
 *
 * Return: the caller's current fsuid mapped up according to @mnt_userns.
 */
static inline kuid_t mapped_fsuid(struct user_namespace *mnt_userns)
{
	return kuid_from_mnt(mnt_userns, current_fsuid());
}

/**
 * mapped_fsgid - return caller's fsgid mapped up into a mnt_userns
 * @mnt_userns: user namespace of the relevant mount
 *
 * Use this helper to initialize a new vfs or filesystem object based on
 * the caller's fsgid. A common example is initializing the i_gid field of
 * a newly allocated inode triggered by a creation event such as mkdir or
 * O_CREAT. Other examples include the allocation of quotas for a specific
 * user.
 *
 * Return: the caller's current fsgid mapped up according to @mnt_userns.
 */
static inline kgid_t mapped_fsgid(struct user_namespace *mnt_userns)
{
	return kgid_from_mnt(mnt_userns, current_fsgid());
}

#ifdef CONFIG_MULTIUSER
static inline int kfsgid_in_group_p(kfsgid_t grp)
{
	return in_group_p(to_idtype(grp));
}
#else
static inline int kfsgid_in_group_p(kfsgid_t grp)
{
	return 1;
}
#endif

#endif /* _LINUX_FSUIDGID_H */
