/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ftrace header.  For implementation details beyond the random comments
 * scattered below, see: Documentation/trace/ftrace-design.rst
 */

#ifndef _LINUX_FTRACE_PAUSE_H
#define _LINUX_FTRACE_PAUSE_H

#include <linux/atomic_api.h>
#include <linux/sched.h>
#include <linux/atomic.h>

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

DECLARE_PER_TASK(atomic_t, tracing_graph_pause);

static inline void pause_graph_tracing(void)
{
	atomic_inc(&per_task(current, tracing_graph_pause));
}

static inline void unpause_graph_tracing(void)
{
	atomic_dec(&per_task(current, tracing_graph_pause));
}
#else /* !CONFIG_FUNCTION_GRAPH_TRACER */

static inline void pause_graph_tracing(void) { }
static inline void unpause_graph_tracing(void) { }

#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

#endif /* _LINUX_FTRACE_PAUSE_H */
