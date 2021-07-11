/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PTRACE_TYPES_H
#define _LINUX_PTRACE_TYPES_H

#include <uapi/linux/seccomp.h>

/* Add sp to seccomp_data, as seccomp is user API, we don't want to modify it */
struct syscall_info {
	__u64			sp;
	struct seccomp_data	data;
};

/*
 * Ptrace flags
 *
 * The owner ship rules for task->ptrace which holds the ptrace
 * flags is simple.  When a task is running it owns it's task->ptrace
 * flags.  When the a task is stopped the ptracer owns task->ptrace.
 */

#define PT_SEIZED	0x00010000	/* SEIZE used, enable new behavior */
#define PT_PTRACED	0x00000001
#define PT_DTRACE	0x00000002	/* delayed trace (used on m68k, i386) */

#define PT_OPT_FLAG_SHIFT	3
/* PT_TRACE_* event enable flags */
#define PT_EVENT_FLAG(event)	(1 << (PT_OPT_FLAG_SHIFT + (event)))
#define PT_TRACESYSGOOD		PT_EVENT_FLAG(0)
#define PT_TRACE_FORK		PT_EVENT_FLAG(PTRACE_EVENT_FORK)
#define PT_TRACE_VFORK		PT_EVENT_FLAG(PTRACE_EVENT_VFORK)
#define PT_TRACE_CLONE		PT_EVENT_FLAG(PTRACE_EVENT_CLONE)
#define PT_TRACE_EXEC		PT_EVENT_FLAG(PTRACE_EVENT_EXEC)
#define PT_TRACE_VFORK_DONE	PT_EVENT_FLAG(PTRACE_EVENT_VFORK_DONE)
#define PT_TRACE_EXIT		PT_EVENT_FLAG(PTRACE_EVENT_EXIT)
#define PT_TRACE_SECCOMP	PT_EVENT_FLAG(PTRACE_EVENT_SECCOMP)

#define PT_EXITKILL		(PTRACE_O_EXITKILL << PT_OPT_FLAG_SHIFT)
#define PT_SUSPEND_SECCOMP	(PTRACE_O_SUSPEND_SECCOMP << PT_OPT_FLAG_SHIFT)

/* single stepping state bits (used on ARM and PA-RISC) */
#define PT_SINGLESTEP_BIT	31
#define PT_SINGLESTEP		(1<<PT_SINGLESTEP_BIT)
#define PT_BLOCKSTEP_BIT	30
#define PT_BLOCKSTEP		(1<<PT_BLOCKSTEP_BIT)

#define PTRACE_MODE_READ	0x01
#define PTRACE_MODE_ATTACH	0x02
#define PTRACE_MODE_NOAUDIT	0x04
#define PTRACE_MODE_FSCREDS	0x08
#define PTRACE_MODE_REALCREDS	0x10

/* shorthands for READ/ATTACH and FSCREDS/REALCREDS combinations */
#define PTRACE_MODE_READ_FSCREDS (PTRACE_MODE_READ | PTRACE_MODE_FSCREDS)
#define PTRACE_MODE_READ_REALCREDS (PTRACE_MODE_READ | PTRACE_MODE_REALCREDS)
#define PTRACE_MODE_ATTACH_FSCREDS (PTRACE_MODE_ATTACH | PTRACE_MODE_FSCREDS)
#define PTRACE_MODE_ATTACH_REALCREDS (PTRACE_MODE_ATTACH | PTRACE_MODE_REALCREDS)

#endif /* _LINUX_PTRACE_TYPES_H */
