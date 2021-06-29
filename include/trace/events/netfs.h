/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Network filesystem support module tracepoints
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM netfs

#if !defined(_TRACE_NETFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NETFS_H

#include <linux/tracepoint.h>

/*
 * Define enums for tracing information.
 */
#ifndef __NETFS_DECLARE_TRACE_ENUMS_ONCE_ONLY
#define __NETFS_DECLARE_TRACE_ENUMS_ONCE_ONLY

enum netfs_read_trace {
	netfs_read_trace_expanded,
	netfs_read_trace_readahead,
	netfs_read_trace_readpage,
	netfs_read_trace_write_begin,
	netfs_read_trace_prefetch_for_write,
};

enum netfs_rreq_trace {
	netfs_rreq_trace_assess,
	netfs_rreq_trace_done,
	netfs_rreq_trace_free,
	netfs_rreq_trace_resubmit,
	netfs_rreq_trace_unlock,
	netfs_rreq_trace_unmark,
	netfs_rreq_trace_write,
};

enum netfs_sreq_trace {
	netfs_sreq_trace_download_instead,
	netfs_sreq_trace_free,
	netfs_sreq_trace_prepare,
	netfs_sreq_trace_resubmit_short,
	netfs_sreq_trace_submit,
	netfs_sreq_trace_terminated,
	netfs_sreq_trace_write,
	netfs_sreq_trace_write_skip,
	netfs_sreq_trace_write_term,
};

enum netfs_failure {
	netfs_fail_check_write_begin,
	netfs_fail_copy_to_cache,
	netfs_fail_read,
	netfs_fail_short_readpage,
	netfs_fail_short_write_begin,
	netfs_fail_prepare_write,
};

enum netfs_dirty_trace {
	netfs_dirty_trace_active,
	netfs_dirty_trace_activate,
	netfs_dirty_trace_commit,
	netfs_dirty_trace_complete,
	netfs_dirty_trace_flush_conflict,
	netfs_dirty_trace_flush_dsync,
	netfs_dirty_trace_flush_writepages,
	netfs_dirty_trace_flushing,
	netfs_dirty_trace_merged_back,
	netfs_dirty_trace_merged_forw,
	netfs_dirty_trace_merged_sub,
	netfs_dirty_trace_modified,
	netfs_dirty_trace_new,
	netfs_dirty_trace_reserved,
	netfs_dirty_trace_split,
	netfs_dirty_trace_start_pending,
	netfs_dirty_trace_superseded,
	netfs_dirty_trace_supersedes,
	netfs_dirty_trace_wait_active,
	netfs_dirty_trace_wait_pend,
};

enum netfs_region_trace {
	netfs_region_trace_get_dirty,
	netfs_region_trace_get_wait_active,
	netfs_region_trace_get_wreq,
	netfs_region_trace_put_dirty,
	netfs_region_trace_put_discard,
	netfs_region_trace_put_merged,
	netfs_region_trace_put_wait_active,
	netfs_region_trace_put_wreq,
	netfs_region_trace_put_write_iter,
	netfs_region_trace_free,
	netfs_region_trace_new,
};

enum netfs_wreq_trace {
	netfs_wreq_trace_free,
	netfs_wreq_trace_get_debug,
	netfs_wreq_trace_get_for_op,
	netfs_wreq_trace_get_for_outstanding,
	netfs_wreq_trace_get_op_work,
	netfs_wreq_trace_put_discard,
	netfs_wreq_trace_put_for_outstanding,
	netfs_wreq_trace_put_op_work,
	netfs_wreq_trace_put_wip,
	netfs_wreq_trace_put_work,
	netfs_wreq_trace_see_lock_conflict,
	netfs_wreq_trace_see_pages_missing,
	netfs_wreq_trace_see_wb_work,
	netfs_wreq_trace_see_work,
	netfs_wreq_trace_new,
};

enum netfs_write_op_trace {
	netfs_write_op_complete,
	netfs_write_op_free,
	netfs_write_op_new,
	netfs_write_op_submit,
};

#endif

#define netfs_read_traces					\
	EM(netfs_read_trace_expanded,		"EXPANDED ")	\
	EM(netfs_read_trace_readahead,		"READAHEAD")	\
	EM(netfs_read_trace_readpage,		"READPAGE ")	\
	EM(netfs_read_trace_prefetch_for_write,	"PREFETCHW")	\
	E_(netfs_read_trace_write_begin,	"WRITEBEGN")

#define netfs_rreq_traces					\
	EM(netfs_rreq_trace_assess,		"ASSESS")	\
	EM(netfs_rreq_trace_done,		"DONE  ")	\
	EM(netfs_rreq_trace_free,		"FREE  ")	\
	EM(netfs_rreq_trace_resubmit,		"RESUBM")	\
	EM(netfs_rreq_trace_unlock,		"UNLOCK")	\
	EM(netfs_rreq_trace_unmark,		"UNMARK")	\
	E_(netfs_rreq_trace_write,		"WRITE ")

#define netfs_sreq_sources					\
	EM(NETFS_FILL_WITH_ZEROES,		"ZERO")		\
	EM(NETFS_DOWNLOAD_FROM_SERVER,		"DOWN")		\
	EM(NETFS_READ_FROM_CACHE,		"READ")		\
	E_(NETFS_INVALID_READ,			"INVL")		\

#define netfs_sreq_traces					\
	EM(netfs_sreq_trace_download_instead,	"RDOWN")	\
	EM(netfs_sreq_trace_free,		"FREE ")	\
	EM(netfs_sreq_trace_prepare,		"PREP ")	\
	EM(netfs_sreq_trace_resubmit_short,	"SHORT")	\
	EM(netfs_sreq_trace_submit,		"SUBMT")	\
	EM(netfs_sreq_trace_terminated,		"TERM ")	\
	EM(netfs_sreq_trace_write,		"WRITE")	\
	EM(netfs_sreq_trace_write_skip,		"SKIP ")	\
	E_(netfs_sreq_trace_write_term,		"WTERM")

#define netfs_failures							\
	EM(netfs_fail_check_write_begin,	"check-write-begin")	\
	EM(netfs_fail_copy_to_cache,		"copy-to-cache")	\
	EM(netfs_fail_read,			"read")			\
	EM(netfs_fail_short_readpage,		"short-readpage")	\
	EM(netfs_fail_short_write_begin,	"short-write-begin")	\
	E_(netfs_fail_prepare_write,		"prep-write")

#define netfs_region_types					\
	EM(NETFS_REGION_ORDINARY,		"ORD")		\
	EM(NETFS_REGION_DIO,			"DIO")		\
	E_(NETFS_REGION_DSYNC,			"DSY")

#define netfs_region_states					\
	EM(NETFS_REGION_IS_PENDING,		"pend")		\
	EM(NETFS_REGION_IS_RESERVED,		"resv")		\
	EM(NETFS_REGION_IS_ACTIVE,		"actv")		\
	EM(NETFS_REGION_IS_DIRTY,		"drty")		\
	EM(NETFS_REGION_IS_FLUSHING,		"flsh")		\
	E_(NETFS_REGION_IS_COMPLETE,		"done")

#define netfs_dirty_traces					\
	EM(netfs_dirty_trace_active,		"ACTIVE    ")	\
	EM(netfs_dirty_trace_activate,		"ACTIVATE  ")	\
	EM(netfs_dirty_trace_commit,		"COMMIT    ")	\
	EM(netfs_dirty_trace_complete,		"COMPLETE  ")	\
	EM(netfs_dirty_trace_flush_conflict,	"FLSH CONFL")	\
	EM(netfs_dirty_trace_flush_dsync,	"FLSH DSYNC")	\
	EM(netfs_dirty_trace_flush_writepages,	"WRITEPAGES")	\
	EM(netfs_dirty_trace_flushing,		"FLUSHING  ")	\
	EM(netfs_dirty_trace_merged_back,	"MERGE BACK")	\
	EM(netfs_dirty_trace_merged_forw,	"MERGE FORW")	\
	EM(netfs_dirty_trace_merged_sub,	"SUBSUMED  ")	\
	EM(netfs_dirty_trace_modified,		"MODIFIED  ")	\
	EM(netfs_dirty_trace_new,		"NEW       ")	\
	EM(netfs_dirty_trace_reserved,		"RESERVED  ")	\
	EM(netfs_dirty_trace_split,		"SPLIT     ")	\
	EM(netfs_dirty_trace_start_pending,	"START PEND")	\
	EM(netfs_dirty_trace_superseded,	"SUPERSEDED")	\
	EM(netfs_dirty_trace_supersedes,	"SUPERSEDES")	\
	EM(netfs_dirty_trace_wait_active,	"WAIT ACTV ")	\
	E_(netfs_dirty_trace_wait_pend,		"WAIT PEND ")

#define netfs_region_traces					\
	EM(netfs_region_trace_get_dirty,	"GET DIRTY  ")	\
	EM(netfs_region_trace_get_wait_active,	"GET WT ACTV")	\
	EM(netfs_region_trace_get_wreq,		"GET WREQ   ")	\
	EM(netfs_region_trace_put_dirty,	"PUT DIRTY  ")	\
	EM(netfs_region_trace_put_discard,	"PUT DISCARD")	\
	EM(netfs_region_trace_put_merged,	"PUT MERGED ")	\
	EM(netfs_region_trace_put_wait_active,	"PUT WT ACTV")	\
	EM(netfs_region_trace_put_wreq,		"PUT WREQ   ")	\
	EM(netfs_region_trace_put_write_iter,	"PUT WRITER ")	\
	EM(netfs_region_trace_free,		"FREE       ")	\
	E_(netfs_region_trace_new,		"NEW        ")

#define netfs_wreq_traces					\
	EM(netfs_wreq_trace_free,		"FREE       ")	\
	EM(netfs_wreq_trace_get_debug,		"GET DEBUG  ")	\
	EM(netfs_wreq_trace_get_for_op,		"GET OP     ")	\
	EM(netfs_wreq_trace_get_for_outstanding,"GET OUTSTND")	\
	EM(netfs_wreq_trace_get_op_work,	"GET OP WORK")	\
	EM(netfs_wreq_trace_put_discard,	"PUT DISCARD")	\
	EM(netfs_wreq_trace_put_for_outstanding,"PUT OUTSTND")	\
	EM(netfs_wreq_trace_put_op_work,	"PUT OP WORK")	\
	EM(netfs_wreq_trace_put_wip,		"PUT WIP    ")	\
	EM(netfs_wreq_trace_put_work,		"PUT WORK   ")	\
	EM(netfs_wreq_trace_see_lock_conflict,	"SEE PG BUSY")	\
	EM(netfs_wreq_trace_see_pages_missing,	"SEE PG MISS")	\
	EM(netfs_wreq_trace_see_wb_work,	"SEE WB WORK")	\
	EM(netfs_wreq_trace_see_work,		"SEE WORK   ")	\
	E_(netfs_wreq_trace_new,		"NEW        ")

#define netfs_write_destinations				\
	EM(NETFS_UPLOAD_TO_SERVER,		"UPLD")		\
	EM(NETFS_WRITE_TO_CACHE,		"WRIT")		\
	E_(NETFS_INVALID_WRITE,			"INVL")

#define netfs_write_op_traces					\
	EM(netfs_write_op_complete,		"DONE")	\
	EM(netfs_write_op_free,			"FREE")	\
	EM(netfs_write_op_new,			"NEW ")	\
	E_(netfs_write_op_submit,		"SUBM")

/*
 * Export enum symbols via userspace.
 */
#undef EM
#undef E_
#define EM(a, b) TRACE_DEFINE_ENUM(a);
#define E_(a, b) TRACE_DEFINE_ENUM(a);

netfs_read_traces;
netfs_rreq_traces;
netfs_sreq_sources;
netfs_sreq_traces;
netfs_failures;
netfs_region_types;
netfs_region_states;
netfs_dirty_traces;
netfs_wreq_traces;
netfs_write_destinations;
netfs_write_op_traces;

/*
 * Now redefine the EM() and E_() macros to map the enums to the strings that
 * will be printed in the output.
 */
#undef EM
#undef E_
#define EM(a, b)	{ a, b },
#define E_(a, b)	{ a, b }

TRACE_EVENT(netfs_read,
	    TP_PROTO(struct netfs_read_request *rreq,
		     loff_t start, size_t len,
		     enum netfs_read_trace what),

	    TP_ARGS(rreq, start, len, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(unsigned int,		cookie		)
		    __field(loff_t,			start		)
		    __field(size_t,			len		)
		    __field(enum netfs_read_trace,	what		)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= rreq->debug_id;
		    __entry->cookie	= rreq->cache_resources.debug_id;
		    __entry->start	= start;
		    __entry->len	= len;
		    __entry->what	= what;
			   ),

	    TP_printk("R=%08x %s c=%08x s=%llx %zx",
		      __entry->rreq,
		      __print_symbolic(__entry->what, netfs_read_traces),
		      __entry->cookie,
		      __entry->start, __entry->len)
	    );

TRACE_EVENT(netfs_rreq,
	    TP_PROTO(struct netfs_read_request *rreq,
		     enum netfs_rreq_trace what),

	    TP_ARGS(rreq, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(unsigned short,		flags		)
		    __field(enum netfs_rreq_trace,	what		)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= rreq->debug_id;
		    __entry->flags	= rreq->flags;
		    __entry->what	= what;
			   ),

	    TP_printk("R=%08x %s f=%02x",
		      __entry->rreq,
		      __print_symbolic(__entry->what, netfs_rreq_traces),
		      __entry->flags)
	    );

TRACE_EVENT(netfs_sreq,
	    TP_PROTO(struct netfs_read_subrequest *sreq,
		     enum netfs_sreq_trace what),

	    TP_ARGS(sreq, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(unsigned short,		index		)
		    __field(short,			error		)
		    __field(unsigned short,		flags		)
		    __field(enum netfs_read_source,	source		)
		    __field(enum netfs_sreq_trace,	what		)
		    __field(size_t,			len		)
		    __field(size_t,			transferred	)
		    __field(loff_t,			start		)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= sreq->rreq->debug_id;
		    __entry->index	= sreq->debug_index;
		    __entry->error	= sreq->error;
		    __entry->flags	= sreq->flags;
		    __entry->source	= sreq->source;
		    __entry->what	= what;
		    __entry->len	= sreq->len;
		    __entry->transferred = sreq->transferred;
		    __entry->start	= sreq->start;
			   ),

	    TP_printk("R=%08x[%u] %s %s f=%02x s=%llx %zx/%zx e=%d",
		      __entry->rreq, __entry->index,
		      __print_symbolic(__entry->what, netfs_sreq_traces),
		      __print_symbolic(__entry->source, netfs_sreq_sources),
		      __entry->flags,
		      __entry->start, __entry->transferred, __entry->len,
		      __entry->error)
	    );

TRACE_EVENT(netfs_failure,
	    TP_PROTO(struct netfs_read_request *rreq,
		     struct netfs_read_subrequest *sreq,
		     int error, enum netfs_failure what),

	    TP_ARGS(rreq, sreq, error, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(unsigned short,		index		)
		    __field(short,			error		)
		    __field(unsigned short,		flags		)
		    __field(enum netfs_read_source,	source		)
		    __field(enum netfs_failure,		what		)
		    __field(size_t,			len		)
		    __field(size_t,			transferred	)
		    __field(loff_t,			start		)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= rreq->debug_id;
		    __entry->index	= sreq ? sreq->debug_index : 0;
		    __entry->error	= error;
		    __entry->flags	= sreq ? sreq->flags : 0;
		    __entry->source	= sreq ? sreq->source : NETFS_INVALID_READ;
		    __entry->what	= what;
		    __entry->len	= sreq ? sreq->len : 0;
		    __entry->transferred = sreq ? sreq->transferred : 0;
		    __entry->start	= sreq ? sreq->start : 0;
			   ),

	    TP_printk("R=%08x[%u] %s f=%02x s=%llx %zx/%zx %s e=%d",
		      __entry->rreq, __entry->index,
		      __print_symbolic(__entry->source, netfs_sreq_sources),
		      __entry->flags,
		      __entry->start, __entry->transferred, __entry->len,
		      __print_symbolic(__entry->what, netfs_failures),
		      __entry->error)
	    );

TRACE_EVENT(netfs_write_iter,
	    TP_PROTO(struct netfs_dirty_region *region, struct kiocb *iocb,
		     struct iov_iter *from),

	    TP_ARGS(region, iocb, from),

	    TP_STRUCT__entry(
		    __field(unsigned int,		region		)
		    __field(unsigned long long,		start		)
		    __field(size_t,			len		)
		    __field(unsigned int,		flags		)
			     ),

	    TP_fast_assign(
		    __entry->region	= region->debug_id;
		    __entry->start	= iocb->ki_pos;
		    __entry->len	= iov_iter_count(from);
		    __entry->flags	= iocb->ki_flags;
			   ),

	    TP_printk("D=%x WRITE-ITER s=%llx l=%zx f=%x",
		      __entry->region, __entry->start, __entry->len, __entry->flags)
	    );

TRACE_EVENT(netfs_ref_region,
	    TP_PROTO(unsigned int region_debug_id, int ref,
		     enum netfs_region_trace what),

	    TP_ARGS(region_debug_id, ref, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		region		)
		    __field(int,			ref		)
		    __field(enum netfs_region_trace,	what		)
			     ),

	    TP_fast_assign(
		    __entry->region	= region_debug_id;
		    __entry->ref	= ref;
		    __entry->what	= what;
			   ),

	    TP_printk("D=%x %s r=%u",
		      __entry->region,
		      __print_symbolic(__entry->what, netfs_region_traces),
		      __entry->ref)
	    );

TRACE_EVENT(netfs_dirty,
	    TP_PROTO(struct netfs_i_context *ctx,
		     struct netfs_dirty_region *region,
		     struct netfs_dirty_region *region2,
		     enum netfs_dirty_trace why),

	    TP_ARGS(ctx, region, region2, why),

	    TP_STRUCT__entry(
		    __field(ino_t,			ino		)
		    __field(unsigned long long,		bounds_start	)
		    __field(unsigned long long,		bounds_end	)
		    __field(unsigned long long,		reserved_start	)
		    __field(unsigned long long,		reserved_end	)
		    __field(unsigned long long,		dirty_start	)
		    __field(unsigned long long,		dirty_end	)
		    __field(unsigned int,		debug_id	)
		    __field(unsigned int,		debug_id2	)
		    __field(enum netfs_region_type,	type		)
		    __field(enum netfs_region_state,	state		)
		    __field(unsigned short,		flags		)
		    __field(unsigned int,		ref		)
		    __field(enum netfs_dirty_trace,	why		)
			     ),

	    TP_fast_assign(
		    __entry->ino		= (((struct inode *)ctx) - 1)->i_ino;
		    __entry->why		= why;
		    __entry->bounds_start	= region->bounds.start;
		    __entry->bounds_end		= region->bounds.end;
		    __entry->reserved_start	= region->reserved.start;
		    __entry->reserved_end	= region->reserved.end;
		    __entry->dirty_start	= region->dirty.start;
		    __entry->dirty_end		= region->dirty.end;
		    __entry->debug_id		= region->debug_id;
		    __entry->type		= region->type;
		    __entry->state		= region->state;
		    __entry->flags		= region->flags;
		    __entry->debug_id2		= region2 ? region2->debug_id : 0;
			   ),

	    TP_printk("i=%lx D=%x %s %s dt=%04llx-%04llx bb=%04llx-%04llx rs=%04llx-%04llx %s f=%x XD=%x",
		      __entry->ino, __entry->debug_id,
		      __print_symbolic(__entry->why, netfs_dirty_traces),
		      __print_symbolic(__entry->type, netfs_region_types),
		      __entry->dirty_start,
		      __entry->dirty_end,
		      __entry->bounds_start,
		      __entry->bounds_end,
		      __entry->reserved_start,
		      __entry->reserved_end,
		      __print_symbolic(__entry->state, netfs_region_states),
		      __entry->flags,
		      __entry->debug_id2
		      )
	    );

TRACE_EVENT(netfs_wreq,
	    TP_PROTO(struct netfs_write_request *wreq),

	    TP_ARGS(wreq),

	    TP_STRUCT__entry(
		    __field(unsigned int,		wreq		)
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		region		)
		    __field(loff_t,			start		)
		    __field(loff_t,			end		)
			     ),

	    TP_fast_assign(
		    struct netfs_dirty_region *__region =
		    list_first_entry(&wreq->regions, struct netfs_dirty_region, flush_link);
		    __entry->wreq	= wreq->debug_id;
		    __entry->cookie	= wreq->cache_resources.debug_id;
		    __entry->region	= __region->debug_id;
		    __entry->start	= wreq->coverage.start;
		    __entry->end	= wreq->coverage.end;
			   ),

	    TP_printk("W=%08x c=%08x D=%x %llx-%llx",
		      __entry->wreq,
		      __entry->cookie,
		      __entry->region,
		      __entry->start, __entry->end)
	    );

TRACE_EVENT(netfs_ref_wreq,
	    TP_PROTO(unsigned int wreq_debug_id, int ref,
		     enum netfs_wreq_trace what),

	    TP_ARGS(wreq_debug_id, ref, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		wreq		)
		    __field(int,			ref		)
		    __field(enum netfs_wreq_trace,	what		)
			     ),

	    TP_fast_assign(
		    __entry->wreq	= wreq_debug_id;
		    __entry->ref	= ref;
		    __entry->what	= what;
			   ),

	    TP_printk("W=%08x %s r=%u",
		      __entry->wreq,
		      __print_symbolic(__entry->what, netfs_wreq_traces),
		      __entry->ref)
	    );

TRACE_EVENT(netfs_wrop,
	    TP_PROTO(struct netfs_write_operation *op,
		     enum netfs_write_op_trace what),

	    TP_ARGS(op, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		wreq		)
		    __field(unsigned short,		index		)
		    __field(short,			error		)
		    __field(unsigned short,		flags		)
		    __field(enum netfs_write_dest,	dest		)
		    __field(enum netfs_write_op_trace,	what		)
			     ),

	    TP_fast_assign(
		    __entry->wreq	= op->wreq->debug_id;
		    __entry->index	= op->debug_index;
		    __entry->error	= op->error;
		    __entry->dest	= op->dest;
		    __entry->what	= what;
			   ),

	    TP_printk("W=%08x[%x] %s %s e=%d",
		      __entry->wreq, __entry->index,
		      __print_symbolic(__entry->what, netfs_write_op_traces),
		      __print_symbolic(__entry->dest, netfs_write_destinations),
		      __entry->error)
	    );

#endif /* _TRACE_NETFS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
