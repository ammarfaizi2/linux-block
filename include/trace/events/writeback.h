#undef TRACE_SYSTEM
#define TRACE_SYSTEM writeback

#if !defined(_TRACE_WRITEBACK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_WRITEBACK_H

#include <linux/backing-dev.h>
#include <linux/writeback.h>

TRACE_EVENT(writeback_queue,

	TP_PROTO(struct wb_writeback_args *args),

	TP_ARGS(args),

	TP_STRUCT__entry(
		__field(long,		nr_pages)
		__field(int,		sb)
		__field(int,		sync_mode)
		__field(int,		for_kupdate)
		__field(int,		range_cyclic)
		__field(int,		for_background)
	),

	TP_fast_assign(
		__entry->nr_pages	= args->nr_pages;
		__entry->sb		= !!args->sb;
		__entry->for_kupdate	= args->for_kupdate;
		__entry->range_cyclic	= args->range_cyclic;
		__entry->for_background	= args->for_background;
	),

	TP_printk("pages=%ld, sb=%d, kupdate=%d, range_cyclic=%d "
		  "for_background=%d", __entry->nr_pages, __entry->sb,
			__entry->for_kupdate, __entry->range_cyclic,
			__entry->for_background)
);

TRACE_EVENT(writeback_sched,

	TP_PROTO(struct bdi_work *work, const char *msg),

	TP_ARGS(work, msg),

	TP_STRUCT__entry(
		__field(struct bdi_work *,	work)
		__array(char,			task,		8)
	),

	TP_fast_assign(
		__entry->work		= work;
		snprintf(__entry->task, 8, "%s", msg);
	),

	TP_printk("work=%p, task=%s", __entry->work, __entry->task)
);

TRACE_EVENT(writeback_exec,

	TP_PROTO(struct bdi_work *work),

	TP_ARGS(work),

	TP_STRUCT__entry(
		__field(struct bdi_work *,	work)
		__field(long,		nr_pages)
		__field(int,		sb)
		__field(int,		sync_mode)
		__field(int,		for_kupdate)
		__field(int,		range_cyclic)
		__field(int,		for_background)
	),

	TP_fast_assign(
		__entry->work		= work;
		__entry->nr_pages	= work->args.nr_pages;
		__entry->sb		= !!work->args.sb;
		__entry->for_kupdate	= work->args.for_kupdate;
		__entry->range_cyclic	= work->args.range_cyclic;
		__entry->for_background	= work->args.for_background;

	),

	TP_printk("work=%p pages=%ld, sb=%d, kupdate=%d, range_cyclic=%d"
		  " for_background=%d", __entry->work,
			__entry->nr_pages, __entry->sb, __entry->for_kupdate,
			__entry->range_cyclic, __entry->for_background)
);

TRACE_EVENT(writeback_clear,

	TP_PROTO(struct bdi_work *work),

	TP_ARGS(work),

	TP_STRUCT__entry(
		__field(struct bdi_work *,	work)
		__field(int,			refs)
	),

	TP_fast_assign(
		__entry->work		= work;
		__entry->refs		= atomic_read(&work->pending);
	),

	TP_printk("work=%p, refs=%d", __entry->work, __entry->refs)
);

TRACE_EVENT(writeback_pages_written,

	TP_PROTO(long pages_written),

	TP_ARGS(pages_written),

	TP_STRUCT__entry(
		__field(long,		pages)
	),

	TP_fast_assign(
		__entry->pages		= pages_written;
	),

	TP_printk("%ld", __entry->pages)
);


TRACE_EVENT(writeback_thread_start,

	TP_PROTO(int start),

	TP_ARGS(start),

	TP_STRUCT__entry(
		__field(int,	start)
	),

	TP_fast_assign(
		__entry->start = start;
	),

	TP_printk("%s", __entry->start ? "started" : "exited")
);

TRACE_EVENT(writeback_bdi_register,

	TP_PROTO(const char *name, int start),

	TP_ARGS(name, start),

	TP_STRUCT__entry(
		__array(char,	name,		16)
		__field(int,	start)
	),

	TP_fast_assign(
		strncpy(__entry->name, name, 16);
		__entry->start = start;
	),

	TP_printk("%s: %s", __entry->name,
			__entry->start ? "registered" : "unregistered")
);

#endif /* _TRACE_WRITEBACK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
