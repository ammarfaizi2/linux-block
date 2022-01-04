/*
 * We generate the PER_TASK_OFFSET_ offsets early during the build, using this file.
 */

#define __PER_TASK_GEN

#include <linux/sched.h>

#include <linux/pid.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/mutex.h>
#include <linux/plist.h>
#include <linux/hrtimer.h>
#include <linux/irqflags.h>
#include <linux/seccomp.h>
#include <linux/nodemask.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/resource.h>
#include <linux/latencytop.h>
#include <linux/sched/prio.h>
#include <linux/sched/types.h>
#include <linux/signal_types.h>
#include <linux/syscall_user_dispatch.h>
#include <linux/mm_types_task.h>
#include <linux/posix-timers.h>
#include <linux/rseq.h>
#include <linux/seqlock.h>
#include <linux/kcsan.h>
#include <linux/perf_event_api.h>
#include <linux/highmem.h>
#include <linux/cache.h>

#include <net/sock.h>

#include <asm/kmap_size.h>

#include "sched.h"

/* Simple struct members: */
#define DEF(type, name)			type name

/* Array members: */
#define DEF_A(type, name, size)		type name size

struct task_struct_per_task {
#include "per_task_area_struct_template.h"
};

#undef DEF_A
#undef DEF

