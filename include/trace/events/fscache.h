/* SPDX-License-Identifier: GPL-2.0-or-later */
/* FS-Cache tracepoints
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM fscache

#if !defined(_TRACE_FSCACHE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FSCACHE_H

#include <linux/fscache.h>
#include <linux/tracepoint.h>

/*
 * Define enums for tracing information.
 */
#ifndef __FSCACHE_DECLARE_TRACE_ENUMS_ONCE_ONLY
#define __FSCACHE_DECLARE_TRACE_ENUMS_ONCE_ONLY

enum fscache_cookie_trace {
	fscache_cookie_collision,
	fscache_cookie_discard,
	fscache_cookie_get_acquire_parent,
	fscache_cookie_get_attach_object,
	fscache_cookie_get_hash_collision,
	fscache_cookie_get_ioreq,
	fscache_cookie_get_register_netfs,
	fscache_cookie_get_work,
	fscache_cookie_new_acquire,
	fscache_cookie_new_netfs,
	fscache_cookie_put_dup_netfs,
	fscache_cookie_put_hash_collision,
	fscache_cookie_put_ioreq,
	fscache_cookie_put_object,
	fscache_cookie_put_parent,
	fscache_cookie_put_relinquish,
	fscache_cookie_put_work,
	fscache_cookie_see_discard,
};

#endif

/*
 * Declare tracing information enums and their string mappings for display.
 */
#define fscache_cookie_traces						\
	EM(fscache_cookie_collision,		"*COLLIDE*")		\
	EM(fscache_cookie_discard,		"DISCARD  ")		\
	EM(fscache_cookie_get_acquire_parent,	"GET paren")		\
	EM(fscache_cookie_get_attach_object,	"GET attch")		\
	EM(fscache_cookie_get_hash_collision,	"GET hcoll")		\
	EM(fscache_cookie_get_ioreq,		"GET ioreq")		\
	EM(fscache_cookie_get_register_netfs,	"GET rgstr")		\
	EM(fscache_cookie_get_work,		"GET work ")		\
	EM(fscache_cookie_new_acquire,		"NEW acq  ")		\
	EM(fscache_cookie_new_netfs,		"NEW netfs")		\
	EM(fscache_cookie_put_dup_netfs,	"PUT dupnf")		\
	EM(fscache_cookie_put_hash_collision,	"PUT hcoll")		\
	EM(fscache_cookie_put_ioreq,		"PUT ioreq")		\
	EM(fscache_cookie_put_object,		"PUT obj  ")		\
	EM(fscache_cookie_put_parent,		"PUT paren")		\
	EM(fscache_cookie_put_relinquish,	"PUT relnq")		\
	EM(fscache_cookie_put_work,		"PUT work ")		\
	E_(fscache_cookie_see_discard,		"SEE discd")

/*
 * Export enum symbols via userspace.
 */
#undef EM
#undef E_
#define EM(a, b) TRACE_DEFINE_ENUM(a);
#define E_(a, b) TRACE_DEFINE_ENUM(a);

fscache_cookie_traces;

/*
 * Now redefine the EM() and E_() macros to map the enums to the strings that
 * will be printed in the output.
 */
#undef EM
#undef E_
#define EM(a, b)	{ a, b },
#define E_(a, b)	{ a, b }


TRACE_EVENT(fscache_cookie,
	    TP_PROTO(struct fscache_cookie *cookie,
		     enum fscache_cookie_trace where,
		     int usage),

	    TP_ARGS(cookie, where, usage),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		parent		)
		    __field(enum fscache_cookie_trace,	where		)
		    __field(int,			usage		)
		    __field(int,			n_children	)
		    __field(int,			n_active	)
		    __field(u8,				flags		)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie->debug_id;
		    __entry->parent	= cookie->parent ? cookie->parent->debug_id : 0;
		    __entry->where	= where;
		    __entry->usage	= usage;
		    __entry->n_children	= atomic_read(&cookie->n_children);
		    __entry->n_active	= atomic_read(&cookie->n_active);
		    __entry->flags	= cookie->flags;
			   ),

	    TP_printk("c=%08x %s u=%d p=%08x Nc=%d Na=%d f=%02x",
		      __entry->cookie,
		      __print_symbolic(__entry->where, fscache_cookie_traces),
		      __entry->usage,
		      __entry->parent, __entry->n_children, __entry->n_active,
		      __entry->flags)
	    );

TRACE_EVENT(fscache_netfs,
	    TP_PROTO(struct fscache_netfs *netfs),

	    TP_ARGS(netfs),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __array(char,			name, 8		)
			     ),

	    TP_fast_assign(
		    __entry->cookie		= netfs->primary_index->debug_id;
		    strncpy(__entry->name, netfs->name, 8);
		    __entry->name[7]		= 0;
			   ),

	    TP_printk("c=%08x n=%s",
		      __entry->cookie, __entry->name)
	    );

TRACE_EVENT(fscache_acquire,
	    TP_PROTO(struct fscache_cookie *cookie),

	    TP_ARGS(cookie),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		parent		)
		    __array(char,			name, 8		)
		    __field(int,			p_usage		)
		    __field(int,			p_n_children	)
		    __field(u8,				p_flags		)
			     ),

	    TP_fast_assign(
		    __entry->cookie		= cookie->debug_id;
		    __entry->parent		= cookie->parent->debug_id;
		    __entry->p_usage		= atomic_read(&cookie->parent->usage);
		    __entry->p_n_children	= atomic_read(&cookie->parent->n_children);
		    __entry->p_flags		= cookie->parent->flags;
		    memcpy(__entry->name, cookie->type_name, 8);
		    __entry->name[7]		= 0;
			   ),

	    TP_printk("c=%08x p=%08x pu=%d pc=%d pf=%02x n=%s",
		      __entry->cookie, __entry->parent, __entry->p_usage,
		      __entry->p_n_children, __entry->p_flags, __entry->name)
	    );

TRACE_EVENT(fscache_relinquish,
	    TP_PROTO(struct fscache_cookie *cookie, bool retire),

	    TP_ARGS(cookie, retire),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		parent		)
		    __field(int,			usage		)
		    __field(int,			n_children	)
		    __field(int,			n_active	)
		    __field(u8,				flags		)
		    __field(bool,			retire		)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie->debug_id;
		    __entry->parent	= cookie->parent->debug_id;
		    __entry->usage	= atomic_read(&cookie->usage);
		    __entry->n_children	= atomic_read(&cookie->n_children);
		    __entry->n_active	= atomic_read(&cookie->n_active);
		    __entry->flags	= cookie->flags;
		    __entry->retire	= retire;
			   ),

	    TP_printk("c=%08x u=%d p=%08x Nc=%d Na=%d f=%02x r=%u",
		      __entry->cookie, __entry->usage,
		      __entry->parent, __entry->n_children, __entry->n_active,
		      __entry->flags, __entry->retire)
	    );

TRACE_EVENT(fscache_invalidate,
	    TP_PROTO(struct fscache_cookie *cookie, loff_t new_size),

	    TP_ARGS(cookie, new_size),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(loff_t,			new_size	)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie->debug_id;
		    __entry->new_size	= new_size;
			   ),

	    TP_printk("c=%08x sz=%llx",
		      __entry->cookie, __entry->new_size)
	    );

TRACE_EVENT(fscache_resize,
	    TP_PROTO(struct fscache_cookie *cookie, loff_t new_size),

	    TP_ARGS(cookie, new_size),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(loff_t,			old_size	)
		    __field(loff_t,			zero_point	)
		    __field(loff_t,			new_size	)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie->debug_id;
		    __entry->old_size	= cookie->object_size;
		    __entry->zero_point	= cookie->zero_point;
		    __entry->new_size	= new_size;
			   ),

	    TP_printk("c=%08x os=%08llx zp=%08llx sz=%08llx",
		      __entry->cookie,
		      __entry->old_size,
		      __entry->zero_point,
		      __entry->new_size)
	    );

#endif /* _TRACE_FSCACHE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
