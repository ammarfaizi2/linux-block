#undef TRACE_SYSTEM
#define TRACE_SYSTEM vfs

#if !defined(_TRACE_VFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VFS_H_

#include <linux/tracepoint.h>
#include <linux/ftrace.h>

TRACE_EVENT(vfs_getname,

	TP_PROTO(const char *filename),

	TP_ARGS(filename),

	TP_STRUCT__entry(
		__string(	filename, filename);
	),

	TP_fast_assign(
		__assign_str(filename, filename);
	),

	TP_printk("vfs_getname %s", __get_str(filename))
);

#undef NO_DEV

#endif /* _TRACE_VFS_H_ */

/* This part must be outside protection */
#include <trace/define_trace.h>
