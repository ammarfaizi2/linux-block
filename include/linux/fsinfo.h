// SPDX-License-Identifier: GPL-2.0
/* Filesystem information query
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_FSINFO_H
#define _LINUX_FSINFO_H

#ifdef CONFIG_FSINFO

#include <uapi/linux/fsinfo.h>

#define FSINFO_NORMAL_ATTR_MAX_SIZE 4096
#define FSINFO_SCRATCH_BUFFER_SIZE 4096

struct fsinfo_kparams {
	__u32			at_flags;	/* AT_SYMLINK_NOFOLLOW and similar */
	enum fsinfo_attribute	request;	/* What is being asking for */
	__u32			Nth;		/* Instance of it (some may have multiple) */
	__u32			Mth;		/* Subinstance */
	bool			overlarge;	/* T if the buffer may be resized */
	unsigned int		usage;		/* Amount of buffer used (if overlarge=T) */
	unsigned int		buf_size;	/* Size of ->buffer[] */
	void			*buffer;	/* Where to place the reply */
	char			*scratch_buffer; /* 4K scratch buffer (if overlarge=T) */
};

extern int generic_fsinfo(struct path *, struct fsinfo_kparams *);

static inline void fsinfo_set_cap(struct fsinfo_capabilities *c,
				  enum fsinfo_capability cap)
{
	c->capabilities[cap / 8] |= 1 << (cap % 8);
}

static inline void fsinfo_clear_cap(struct fsinfo_capabilities *c,
				    enum fsinfo_capability cap)
{
	c->capabilities[cap / 8] &= ~(1 << (cap % 8));
}

/**
 * fsinfo_set_unix_caps - Set standard UNIX capabilities.
 * @c: The capabilities mask to alter
 */
static inline void fsinfo_set_unix_caps(struct fsinfo_capabilities *caps)
{
	fsinfo_set_cap(caps, FSINFO_CAP_UIDS);
	fsinfo_set_cap(caps, FSINFO_CAP_GIDS);
	fsinfo_set_cap(caps, FSINFO_CAP_DIRECTORIES);
	fsinfo_set_cap(caps, FSINFO_CAP_SYMLINKS);
	fsinfo_set_cap(caps, FSINFO_CAP_HARD_LINKS);
	fsinfo_set_cap(caps, FSINFO_CAP_DEVICE_FILES);
	fsinfo_set_cap(caps, FSINFO_CAP_UNIX_SPECIALS);
	fsinfo_set_cap(caps, FSINFO_CAP_SPARSE);
	fsinfo_set_cap(caps, FSINFO_CAP_HAS_ATIME);
	fsinfo_set_cap(caps, FSINFO_CAP_HAS_CTIME);
	fsinfo_set_cap(caps, FSINFO_CAP_HAS_MTIME);
}

#endif /* CONFIG_FSINFO */

#endif /* _LINUX_FSINFO_H */
