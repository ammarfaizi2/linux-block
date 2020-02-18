/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Common windows attributes
 */
#ifndef _UAPI_LINUX_WINDOWS_H
#define _UAPI_LINUX_WINDOWS_H

/*
 * File Attribute flags
 */
#define ATTR_READONLY		0x0001
#define ATTR_HIDDEN		0x0002
#define ATTR_SYSTEM		0x0004
#define ATTR_VOLUME		0x0008
#define ATTR_DIRECTORY		0x0010
#define ATTR_ARCHIVE		0x0020
#define ATTR_DEVICE		0x0040
#define ATTR_NORMAL		0x0080
#define ATTR_TEMPORARY		0x0100
#define ATTR_SPARSE		0x0200
#define ATTR_REPARSE		0x0400
#define ATTR_COMPRESSED		0x0800
#define ATTR_OFFLINE		0x1000	/* ie file not immediately available -
					   on offline storage */
#define ATTR_NOT_CONTENT_INDEXED 0x2000
#define ATTR_ENCRYPTED		0x4000
#define ATTR_POSIX_SEMANTICS	0x01000000
#define ATTR_BACKUP_SEMANTICS	0x02000000
#define ATTR_DELETE_ON_CLOSE	0x04000000
#define ATTR_SEQUENTIAL_SCAN	0x08000000
#define ATTR_RANDOM_ACCESS	0x10000000
#define ATTR_NO_BUFFERING	0x20000000
#define ATTR_WRITE_THROUGH	0x80000000

#endif /* _UAPI_LINUX_WINDOWS_H */
