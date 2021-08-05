/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_NET_SCM_TYPES_H
#define __LINUX_NET_SCM_TYPES_H

#include <linux/uidgid.h>

struct scm_creds {
	u32	pid;
	kuid_t	uid;
	kgid_t	gid;
};

#endif /* __LINUX_NET_SCM_TYPES_H */

