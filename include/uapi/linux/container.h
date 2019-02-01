/* Container UAPI
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _UAPI_LINUX_CONTAINER_H
#define _UAPI_LINUX_CONTAINER_H


#define CONTAINER_NEW_FS_NS		0x00000001 /* Dup current fs namespace */
#define CONTAINER_NEW_EMPTY_FS_NS	0x00000002 /* Provide new empty fs namespace */
#define CONTAINER_NEW_CGROUP_NS		0x00000004 /* Dup current cgroup namespace */
#define CONTAINER_NEW_UTS_NS		0x00000008 /* Dup current uts namespace */
#define CONTAINER_NEW_IPC_NS		0x00000010 /* Dup current ipc namespace */
#define CONTAINER_NEW_USER_NS		0x00000020 /* Dup current user namespace */
#define CONTAINER_NEW_PID_NS		0x00000040 /* Dup current pid namespace */
#define CONTAINER_NEW_NET_NS		0x00000080 /* Dup current net namespace */
#define CONTAINER_KILL_ON_CLOSE		0x00000100 /* Kill all member processes when fd closed */
#define CONTAINER_FD_CLOEXEC		0x00000200 /* Close the fd on exec */
#define CONTAINER__FLAG_MASK		0x000003ff

#endif /* _UAPI_LINUX_CONTAINER_H */
