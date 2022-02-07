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
#define netfs_read_traces					\
	EM(netfs_read_trace_dio_read,		"DIO-READ ")	\
	EM(netfs_read_trace_expanded,		"EXPANDED ")	\
	EM(netfs_read_trace_readahead,		"READAHEAD")	\
	EM(netfs_read_trace_readpage,		"READPAGE ")	\
	E_(netfs_read_trace_write_begin,	"WRITEBEGN")

#define netfs_rreq_origins					\
	EM(NETFS_READAHEAD,			"RA")		\
	EM(NETFS_READPAGE,			"RP")		\
	EM(NETFS_READ_FOR_WRITE,		"RW")		\
	EM(NETFS_WRITEBACK,			"WB")		\
	EM(NETFS_DIO_READ,			"DR")		\
	E_(NETFS_DIO_WRITE,			"DW")

#define netfs_rreq_traces					\
	EM(netfs_rreq_trace_assess,		"ASSESS ")	\
	EM(netfs_rreq_trace_copy,		"COPY   ")	\
	EM(netfs_rreq_trace_decrypt,		"DECRYPT")	\
	EM(netfs_rreq_trace_done,		"DONE   ")	\
	EM(netfs_rreq_trace_encrypt,		"ENCRYPT")	\
	EM(netfs_rreq_trace_free,		"FREE   ")	\
	EM(netfs_rreq_trace_redirty,		"REDIRTY")	\
	EM(netfs_rreq_trace_resubmit,		"RESUBMT")	\
	EM(netfs_rreq_trace_unlock,		"UNLOCK ")	\
	EM(netfs_rreq_trace_unmark,		"UNMARK ")	\
	EM(netfs_rreq_trace_wait_ip,		"WAIT-IP")	\
	EM(netfs_rreq_trace_wake_ip,		"WAKE-IP")	\
	E_(netfs_rreq_trace_write_done,		"WR-DONE")

#define netfs_sreq_sources					\
	EM(NETFS_FILL_WITH_ZEROES,		"ZERO")		\
	EM(NETFS_DOWNLOAD_FROM_SERVER,		"DOWN")		\
	EM(NETFS_READ_FROM_CACHE,		"READ")		\
	EM(NETFS_INVALID_READ,			"INVL")		\
	EM(NETFS_UPLOAD_TO_SERVER,		"UPLD")		\
	EM(NETFS_WRITE_TO_CACHE,		"WRIT")		\
	E_(NETFS_INVALID_WRITE,			"INVL")

#define netfs_sreq_traces					\
	EM(netfs_sreq_trace_download_instead,	"RDOWN")	\
	EM(netfs_sreq_trace_free,		"FREE ")	\
	EM(netfs_sreq_trace_invalid,		"INVAL")	\
	EM(netfs_sreq_trace_limited,		"LIMIT")	\
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
	EM(netfs_fail_decryption,		"decryption")		\
	EM(netfs_fail_dio_read_short,		"dio-read-short")	\
	EM(netfs_fail_dio_read_zero,		"dio-read-zero")	\
	EM(netfs_fail_encryption,		"encryption")		\
	EM(netfs_fail_read,			"read")			\
	EM(netfs_fail_short_read,		"short-read")		\
	EM(netfs_fail_prepare_write,		"prep-write")		\
	E_(netfs_fail_write,			"write")

#define netfs_rreq_ref_traces					\
	EM(netfs_rreq_trace_get_for_outstanding,"GET OUTSTND")	\
	EM(netfs_rreq_trace_get_hold,		"GET HOLD   ")	\
	EM(netfs_rreq_trace_get_subreq,		"GET SUBREQ ")	\
	EM(netfs_rreq_trace_put_complete,	"PUT COMPLT ")	\
	EM(netfs_rreq_trace_put_discard,	"PUT DISCARD")	\
	EM(netfs_rreq_trace_put_failed,		"PUT FAILED ")	\
	EM(netfs_rreq_trace_put_hold,		"PUT HOLD   ")	\
	EM(netfs_rreq_trace_put_subreq,		"PUT SUBREQ ")	\
	EM(netfs_rreq_trace_put_work,		"PUT WORK   ")	\
	EM(netfs_rreq_trace_put_zero_len,	"PUT ZEROLEN")	\
	EM(netfs_rreq_trace_see_work,		"SEE WORK   ")	\
	E_(netfs_rreq_trace_new,		"NEW        ")

#define netfs_sreq_ref_traces					\
	EM(netfs_sreq_trace_get_copy_to_cache,	"GET COPY2C ")	\
	EM(netfs_sreq_trace_get_resubmit,	"GET RESUBMIT")	\
	EM(netfs_sreq_trace_get_short_read,	"GET SHORTRD")	\
	EM(netfs_sreq_trace_new,		"NEW        ")	\
	EM(netfs_sreq_trace_put_clear,		"PUT CLEAR  ")	\
	EM(netfs_sreq_trace_put_discard,	"PUT DISCARD")	\
	EM(netfs_sreq_trace_put_failed,		"PUT FAILED ")	\
	EM(netfs_sreq_trace_put_merged,		"PUT MERGED ")	\
	EM(netfs_sreq_trace_put_no_copy,	"PUT NO COPY")	\
	EM(netfs_sreq_trace_put_wip,		"PUT WIP    ")	\
	EM(netfs_sreq_trace_put_work,		"PUT WORK   ")	\
	E_(netfs_sreq_trace_put_terminated,	"PUT TERM   ")

#define netfs_region_traces					\
	EM(netfs_region_trace_free,		"FREE       ")	\
	E_(netfs_region_trace_put_clear,	"PUT CLEAR  ")

#ifndef __NETFS_DECLARE_TRACE_ENUMS_ONCE_ONLY
#define __NETFS_DECLARE_TRACE_ENUMS_ONCE_ONLY

#undef EM
#undef E_
#define EM(a, b) a,
#define E_(a, b) a

enum netfs_read_trace { netfs_read_traces } __mode(byte);
enum netfs_rreq_trace { netfs_rreq_traces } __mode(byte);
enum netfs_sreq_trace { netfs_sreq_traces } __mode(byte);
enum netfs_failure { netfs_failures } __mode(byte);
enum netfs_rreq_ref_trace { netfs_rreq_ref_traces } __mode(byte);
enum netfs_sreq_ref_trace { netfs_sreq_ref_traces } __mode(byte);
enum netfs_region_trace { netfs_region_traces } __mode(byte);

#endif

/*
 * Export enum symbols via userspace.
 */
#undef EM
#undef E_
#define EM(a, b) TRACE_DEFINE_ENUM(a);
#define E_(a, b) TRACE_DEFINE_ENUM(a);

netfs_read_traces;
netfs_rreq_origins;
netfs_rreq_traces;
netfs_sreq_sources;
netfs_sreq_traces;
netfs_failures;
netfs_rreq_ref_traces;
netfs_sreq_ref_traces;
netfs_region_traces;

/*
 * Now redefine the EM() and E_() macros to map the enums to the strings that
 * will be printed in the output.
 */
#undef EM
#undef E_
#define EM(a, b)	{ a, b },
#define E_(a, b)	{ a, b }

TRACE_EVENT(netfs_read,
	    TP_PROTO(struct netfs_io_request *rreq,
		     loff_t start, size_t len,
		     enum netfs_read_trace what),

	    TP_ARGS(rreq, start, len, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(unsigned int,		cookie		)
		    __field(loff_t,			start		)
		    __field(size_t,			len		)
		    __field(enum netfs_read_trace,	what		)
		    __field(unsigned int,		netfs_inode	)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= rreq->debug_id;
		    __entry->cookie	= rreq->cache_resources.debug_id;
		    __entry->start	= start;
		    __entry->len	= len;
		    __entry->what	= what;
		    __entry->netfs_inode = rreq->inode->i_ino;
			   ),

	    TP_printk("R=%08x %s c=%08x ni=%x s=%llx %zx",
		      __entry->rreq,
		      __print_symbolic(__entry->what, netfs_read_traces),
		      __entry->cookie,
		      __entry->netfs_inode,
		      __entry->start, __entry->len)
	    );

TRACE_EVENT(netfs_rreq,
	    TP_PROTO(struct netfs_io_request *rreq,
		     enum netfs_rreq_trace what),

	    TP_ARGS(rreq, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(unsigned int,		flags		)
		    __field(enum netfs_io_origin,	origin		)
		    __field(enum netfs_rreq_trace,	what		)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= rreq->debug_id;
		    __entry->flags	= rreq->flags;
		    __entry->origin	= rreq->origin;
		    __entry->what	= what;
			   ),

	    TP_printk("R=%08x %s %s f=%02x",
		      __entry->rreq,
		      __print_symbolic(__entry->origin, netfs_rreq_origins),
		      __print_symbolic(__entry->what, netfs_rreq_traces),
		      __entry->flags)
	    );

TRACE_EVENT(netfs_sreq,
	    TP_PROTO(struct netfs_io_subrequest *sreq,
		     enum netfs_sreq_trace what),

	    TP_ARGS(sreq, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(unsigned short,		index		)
		    __field(short,			error		)
		    __field(unsigned short,		flags		)
		    __field(enum netfs_io_source,	source		)
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
		      __print_symbolic(__entry->source, netfs_sreq_sources),
		      __print_symbolic(__entry->what, netfs_sreq_traces),
		      __entry->flags,
		      __entry->start, __entry->transferred, __entry->len,
		      __entry->error)
	    );

TRACE_EVENT(netfs_failure,
	    TP_PROTO(struct netfs_io_request *rreq,
		     struct netfs_io_subrequest *sreq,
		     int error, enum netfs_failure what),

	    TP_ARGS(rreq, sreq, error, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(short,			index		)
		    __field(short,			error		)
		    __field(unsigned short,		flags		)
		    __field(enum netfs_io_source,	source		)
		    __field(enum netfs_failure,		what		)
		    __field(size_t,			len		)
		    __field(size_t,			transferred	)
		    __field(loff_t,			start		)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= rreq->debug_id;
		    __entry->index	= sreq ? sreq->debug_index : -1;
		    __entry->error	= error;
		    __entry->flags	= sreq ? sreq->flags : 0;
		    __entry->source	= sreq ? sreq->source : NETFS_INVALID_READ;
		    __entry->what	= what;
		    __entry->len	= sreq ? sreq->len : rreq->len;
		    __entry->transferred = sreq ? sreq->transferred : 0;
		    __entry->start	= sreq ? sreq->start : 0;
			   ),

	    TP_printk("R=%08x[%d] %s f=%02x s=%llx %zx/%zx %s e=%d",
		      __entry->rreq, __entry->index,
		      __print_symbolic(__entry->source, netfs_sreq_sources),
		      __entry->flags,
		      __entry->start, __entry->transferred, __entry->len,
		      __print_symbolic(__entry->what, netfs_failures),
		      __entry->error)
	    );

TRACE_EVENT(netfs_rreq_ref,
	    TP_PROTO(unsigned int rreq_debug_id, int ref,
		     enum netfs_rreq_ref_trace what),

	    TP_ARGS(rreq_debug_id, ref, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(int,			ref		)
		    __field(enum netfs_rreq_ref_trace,	what		)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= rreq_debug_id;
		    __entry->ref	= ref;
		    __entry->what	= what;
			   ),

	    TP_printk("R=%08x %s r=%u",
		      __entry->rreq,
		      __print_symbolic(__entry->what, netfs_rreq_ref_traces),
		      __entry->ref)
	    );

TRACE_EVENT(netfs_sreq_ref,
	    TP_PROTO(unsigned int rreq_debug_id, unsigned int subreq_debug_index,
		     int ref, enum netfs_sreq_ref_trace what),

	    TP_ARGS(rreq_debug_id, subreq_debug_index, ref, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		rreq		)
		    __field(unsigned int,		subreq		)
		    __field(int,			ref		)
		    __field(enum netfs_sreq_ref_trace,	what		)
			     ),

	    TP_fast_assign(
		    __entry->rreq	= rreq_debug_id;
		    __entry->subreq	= subreq_debug_index;
		    __entry->ref	= ref;
		    __entry->what	= what;
			   ),

	    TP_printk("R=%08x[%x] %s r=%u",
		      __entry->rreq,
		      __entry->subreq,
		      __print_symbolic(__entry->what, netfs_sreq_ref_traces),
		      __entry->ref)
	    );

TRACE_EVENT(netfs_wback,
	    TP_PROTO(const struct netfs_io_request *wreq),

	    TP_ARGS(wreq),

	    TP_STRUCT__entry(
		    __field(unsigned int,		wreq		)
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		region		)
		    __field(unsigned long long,		start		)
		    __field(size_t,			len		)
		    __field(pgoff_t,			first		)
		    __field(pgoff_t,			last		)
			     ),

	    TP_fast_assign(
		    struct netfs_inode *__ctx = netfs_inode(wreq->inode);
		    struct fscache_cookie *__cookie = netfs_i_cookie(__ctx);
		    struct netfs_dirty_region *__region =
		    list_first_entry_or_null((struct list_head *)&wreq->regions,
					     struct netfs_dirty_region, dirty_link);
		    __entry->wreq	= wreq->debug_id;
		    __entry->cookie	= __cookie ? __cookie->debug_id : 0;
		    __entry->region	= __region ? __region->debug_id : 0;
		    __entry->start	= wreq->start;
		    __entry->len	= wreq->len;
		    __entry->first	= wreq->first;
		    __entry->last	= wreq->last;
			   ),

	    TP_printk("R=%08x c=%08x D=%x by=%llx-%llx pg=%lx-%lx",
		      __entry->wreq,
		      __entry->cookie,
		      __entry->region,
		      __entry->start, __entry->start + __entry->len - 1,
		      __entry->first, __entry->last)
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

#undef EM
#undef E_
#endif /* _TRACE_NETFS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
