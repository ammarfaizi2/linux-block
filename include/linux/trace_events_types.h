/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_TRACE_EVENT_TYPES_H
#define _LINUX_TRACE_EVENT_TYPES_H

#include <linux/trace_seq.h>

struct trace_array;
struct trace_event;
struct array_buffer;
struct tracer;
struct dentry;
struct bpf_prog;
struct perf_event;

/*
 * The trace entry - the most basic unit of tracing. This is what
 * is printed in the end as a single line in the trace output, such as:
 *
 *     bash-15816 [01]   235.197585: idle_cpu <- irq_enter
 */
struct trace_entry {
	unsigned short		type;
	unsigned char		flags;
	unsigned char		preempt_count;
	int			pid;
};

#define TRACE_EVENT_TYPE_MAX						\
	((1 << (sizeof(((struct trace_entry *)0)->type) * 8)) - 1)

struct trace_iterator;

typedef enum print_line_t (*trace_print_func)(struct trace_iterator *iter,
				      int flags, struct trace_event *event);

struct trace_event_functions {
	trace_print_func	trace;
	trace_print_func	raw;
	trace_print_func	hex;
	trace_print_func	binary;
};

struct trace_event {
	struct hlist_node		node;
	struct list_head		list;
	int				type;
	struct trace_event_functions	*funcs;
};

/* Return values for print_line callback */
enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE	= 0,	/* Retry after flushing the seq */
	TRACE_TYPE_HANDLED	= 1,
	TRACE_TYPE_UNHANDLED	= 2,	/* Relay to other output functions */
	TRACE_TYPE_NO_CONSUME	= 3	/* Handled but ask to not consume */
};

enum trace_flag_type {
	TRACE_FLAG_IRQS_OFF		= 0x01,
	TRACE_FLAG_IRQS_NOSUPPORT	= 0x02,
	TRACE_FLAG_NEED_RESCHED		= 0x04,
	TRACE_FLAG_HARDIRQ		= 0x08,
	TRACE_FLAG_SOFTIRQ		= 0x10,
	TRACE_FLAG_PREEMPT_RESCHED	= 0x20,
	TRACE_FLAG_NMI			= 0x40,
	TRACE_FLAG_BH_OFF		= 0x80,
};

#define TRACE_RECORD_CMDLINE	BIT(0)
#define TRACE_RECORD_TGID	BIT(1)

struct event_filter;

enum trace_reg {
	TRACE_REG_REGISTER,
	TRACE_REG_UNREGISTER,
#ifdef CONFIG_PERF_EVENTS
	TRACE_REG_PERF_REGISTER,
	TRACE_REG_PERF_UNREGISTER,
	TRACE_REG_PERF_OPEN,
	TRACE_REG_PERF_CLOSE,
	/*
	 * These (ADD/DEL) use a 'boolean' return value, where 1 (true) means a
	 * custom action was taken and the default action is not to be
	 * performed.
	 */
	TRACE_REG_PERF_ADD,
	TRACE_REG_PERF_DEL,
#endif
};

struct trace_event_call;

#define TRACE_FUNCTION_TYPE ((const char *)~0UL)

struct trace_event_fields {
	const char *type;
	union {
		struct {
			const char *name;
			const int  size;
			const int  align;
			const int  is_signed;
			const int  filter_type;
		};
		int (*define_fields)(struct trace_event_call *);
	};
};

struct trace_event_class {
	const char		*system;
	void			*probe;
#ifdef CONFIG_PERF_EVENTS
	void			*perf_probe;
#endif
	int			(*reg)(struct trace_event_call *event,
				       enum trace_reg type, void *data);
	struct trace_event_fields *fields_array;
	struct list_head	*(*get_fields)(struct trace_event_call *);
	struct list_head	fields;
	int			(*raw_init)(struct trace_event_call *);
};

struct trace_event_buffer {
	struct trace_buffer		*buffer;
	struct ring_buffer_event	*event;
	struct trace_event_file		*trace_file;
	void				*entry;
	unsigned int			trace_ctx;
	struct pt_regs			*regs;
};

enum {
	TRACE_EVENT_FL_FILTERED_BIT,
	TRACE_EVENT_FL_CAP_ANY_BIT,
	TRACE_EVENT_FL_NO_SET_FILTER_BIT,
	TRACE_EVENT_FL_IGNORE_ENABLE_BIT,
	TRACE_EVENT_FL_TRACEPOINT_BIT,
	TRACE_EVENT_FL_DYNAMIC_BIT,
	TRACE_EVENT_FL_KPROBE_BIT,
	TRACE_EVENT_FL_UPROBE_BIT,
	TRACE_EVENT_FL_EPROBE_BIT,
};

/*
 * Event flags:
 *  FILTERED	  - The event has a filter attached
 *  CAP_ANY	  - Any user can enable for perf
 *  NO_SET_FILTER - Set when filter has error and is to be ignored
 *  IGNORE_ENABLE - For trace internal events, do not enable with debugfs file
 *  TRACEPOINT    - Event is a tracepoint
 *  DYNAMIC       - Event is a dynamic event (created at run time)
 *  KPROBE        - Event is a kprobe
 *  UPROBE        - Event is a uprobe
 *  EPROBE        - Event is an event probe
 */
enum {
	TRACE_EVENT_FL_FILTERED		= (1 << TRACE_EVENT_FL_FILTERED_BIT),
	TRACE_EVENT_FL_CAP_ANY		= (1 << TRACE_EVENT_FL_CAP_ANY_BIT),
	TRACE_EVENT_FL_NO_SET_FILTER	= (1 << TRACE_EVENT_FL_NO_SET_FILTER_BIT),
	TRACE_EVENT_FL_IGNORE_ENABLE	= (1 << TRACE_EVENT_FL_IGNORE_ENABLE_BIT),
	TRACE_EVENT_FL_TRACEPOINT	= (1 << TRACE_EVENT_FL_TRACEPOINT_BIT),
	TRACE_EVENT_FL_DYNAMIC		= (1 << TRACE_EVENT_FL_DYNAMIC_BIT),
	TRACE_EVENT_FL_KPROBE		= (1 << TRACE_EVENT_FL_KPROBE_BIT),
	TRACE_EVENT_FL_UPROBE		= (1 << TRACE_EVENT_FL_UPROBE_BIT),
	TRACE_EVENT_FL_EPROBE		= (1 << TRACE_EVENT_FL_EPROBE_BIT),
};

#define TRACE_EVENT_FL_UKPROBE (TRACE_EVENT_FL_KPROBE | TRACE_EVENT_FL_UPROBE)

struct trace_event_call {
	struct list_head	list;
	struct trace_event_class *class;
	union {
		char			*name;
		/* Set TRACE_EVENT_FL_TRACEPOINT flag when using "tp" */
		struct tracepoint	*tp;
	};
	struct trace_event	event;
	char			*print_fmt;
	struct event_filter	*filter;
	/*
	 * Static events can disappear with modules,
	 * where as dynamic ones need their own ref count.
	 */
	union {
		void				*module;
		atomic_t			refcnt;
	};
	void			*data;

	/* See the TRACE_EVENT_FL_* flags above */
	int			flags; /* static flags of different events */

#ifdef CONFIG_PERF_EVENTS
	int				perf_refcount;
	struct hlist_head __percpu	*perf_events;
	struct bpf_prog_array __rcu	*prog_array;

	int	(*perf_perm)(struct trace_event_call *,
			     struct perf_event *);
#endif
};

#endif /* _LINUX_TRACE_EVENT_TYPES_H */
