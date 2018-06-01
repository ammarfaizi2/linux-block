/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_WAIT_H
#define _UAPI_LINUX_WAIT_H

#define WNOHANG		0x00000001
#define WUNTRACED	0x00000002
#define WSTOPPED	WUNTRACED
#define WEXITED		0x00000004
#define WCONTINUED	0x00000008
#define WNOWAIT		0x01000000	/* Don't reap, just poll status.  */

#define __WNOTHREAD	0x20000000	/* Don't wait on children of other threads in this group */
#define __WALL		0x40000000	/* Wait on all children, regardless of type */
#define __WCLONE	0x80000000	/* Wait only on non-SIGCHLD children */

/* First argument to waitid: */
#define P_ALL		0
#define P_PID		1
#define P_PGID		2

/* Commands to pass to pidctl() */
enum pidcmd {
	PIDCMD_QUERY_PID   = 0, /* Get pid in target pid namespace */
	PIDCMD_QUERY_PIDNS = 1, /* Determine relationship between pid namespaces */
	PIDCMD_GET_PIDFD   = 2, /* Get pidfd for a process */
};

/* Return values of PIDCMD_QUERY_PIDNS */
enum pidcmd_query_pidns {
	PIDNS_UNRELATED          = 0, /* The pid namespaces are unrelated */
	PIDNS_EQUAL              = 1, /* The pid namespaces are equal */
	PIDNS_SOURCE_IS_ANCESTOR = 2, /* Source pid namespace is ancestor of target pid namespace */
	PIDNS_TARGET_IS_ANCESTOR = 3, /* Target pid namespace is ancestor of source pid namespace */
};

#endif /* _UAPI_LINUX_WAIT_H */
