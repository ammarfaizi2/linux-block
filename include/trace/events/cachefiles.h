/* SPDX-License-Identifier: GPL-2.0-or-later */
/* CacheFiles tracepoints
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM cachefiles

#if !defined(_TRACE_CACHEFILES_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CACHEFILES_H

#include <linux/tracepoint.h>

/*
 * Define enums for tracing information.
 */
#ifndef __CACHEFILES_DECLARE_TRACE_ENUMS_ONCE_ONLY
#define __CACHEFILES_DECLARE_TRACE_ENUMS_ONCE_ONLY

enum cachefiles_obj_ref_trace {
	cachefiles_obj_put_wait_retry = fscache_obj_ref__nr_traces,
	cachefiles_obj_put_wait_timeo,
	cachefiles_obj_ref__nr_traces
};

enum cachefiles_coherency_trace {
	cachefiles_coherency_check_aux,
	cachefiles_coherency_check_content,
	cachefiles_coherency_check_dirty,
	cachefiles_coherency_check_len,
	cachefiles_coherency_check_objsize,
	cachefiles_coherency_check_ok,
	cachefiles_coherency_check_type,
	cachefiles_coherency_check_xattr,
	cachefiles_coherency_set_fail,
	cachefiles_coherency_set_ok,
};

#endif

/*
 * Define enum -> string mappings for display.
 */
#define cachefiles_obj_kill_traces				\
	EM(FSCACHE_OBJECT_IS_STALE,	"stale")		\
	EM(FSCACHE_OBJECT_NO_SPACE,	"no_space")		\
	EM(FSCACHE_OBJECT_WAS_RETIRED,	"was_retired")		\
	E_(FSCACHE_OBJECT_WAS_CULLED,	"was_culled")

#define cachefiles_obj_ref_traces					\
	EM(fscache_obj_get_attach,		"GET attach")		\
	EM(fscache_obj_get_exists,		"GET exists")		\
	EM(fscache_obj_get_inval,		"GET inval")		\
	EM(fscache_obj_get_ioreq,		"GET ioreq")		\
	EM(fscache_obj_get_wait,		"GET wait")		\
	EM(fscache_obj_get_withdraw,		"GET withdraw")		\
	EM(fscache_obj_new,			"NEW obj")		\
	EM(fscache_obj_put,			"PUT general")		\
	EM(fscache_obj_put_alloc_dup,		"PUT alloc_dup")	\
	EM(fscache_obj_put_alloc_fail,		"PUT alloc_fail")	\
	EM(fscache_obj_put_attach_fail,		"PUT attach_fail")	\
	EM(fscache_obj_put_drop_child,		"PUT drop_child")	\
	EM(fscache_obj_put_drop_obj,		"PUT drop_obj")		\
	EM(fscache_obj_put_inval,		"PUT inval")		\
	EM(fscache_obj_put_ioreq,		"PUT ioreq")		\
	EM(fscache_obj_put_withdraw,		"PUT withdraw")		\
	EM(fscache_obj_put_lookup_fail,		"PUT lookup_fail")	\
	EM(cachefiles_obj_put_wait_retry,	"PUT wait_retry")	\
	E_(cachefiles_obj_put_wait_timeo,	"PUT wait_timeo")

#define cachefiles_coherency_traces					\
	EM(cachefiles_coherency_check_aux,	"BAD aux ")		\
	EM(cachefiles_coherency_check_content,	"BAD cont")		\
	EM(cachefiles_coherency_check_dirty,	"BAD dirt")		\
	EM(cachefiles_coherency_check_len,	"BAD len ")		\
	EM(cachefiles_coherency_check_objsize,	"BAD osiz")		\
	EM(cachefiles_coherency_check_ok,	"OK      ")		\
	EM(cachefiles_coherency_check_type,	"BAD type")		\
	EM(cachefiles_coherency_check_xattr,	"BAD xatt")		\
	EM(cachefiles_coherency_set_fail,	"SET fail")		\
	E_(cachefiles_coherency_set_ok,		"SET ok  ")

/*
 * Export enum symbols via userspace.
 */
#undef EM
#undef E_
#define EM(a, b) TRACE_DEFINE_ENUM(a);
#define E_(a, b) TRACE_DEFINE_ENUM(a);

cachefiles_obj_kill_traces;
cachefiles_obj_ref_traces;
cachefiles_coherency_traces;

/*
 * Now redefine the EM() and E_() macros to map the enums to the strings that
 * will be printed in the output.
 */
#undef EM
#undef E_
#define EM(a, b)	{ a, b },
#define E_(a, b)	{ a, b }


TRACE_EVENT(cachefiles_ref,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct fscache_cookie *cookie,
		     enum cachefiles_obj_ref_trace why,
		     int usage),

	    TP_ARGS(obj, cookie, why, usage),

	    /* Note that obj may be NULL */
	    TP_STRUCT__entry(
		    __field(unsigned int,			obj		)
		    __field(unsigned int,			cookie		)
		    __field(enum cachefiles_obj_ref_trace,	why		)
		    __field(int,				usage		)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->cookie	= cookie->debug_id;
		    __entry->usage	= usage;
		    __entry->why	= why;
			   ),

	    TP_printk("c=%08x o=%08x u=%d %s",
		      __entry->cookie, __entry->obj, __entry->usage,
		      __print_symbolic(__entry->why, cachefiles_obj_ref_traces))
	    );

TRACE_EVENT(cachefiles_lookup,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct dentry *de,
		     struct inode *inode),

	    TP_ARGS(obj, de, inode),

	    TP_STRUCT__entry(
		    __field(unsigned int,		obj	)
		    __field(struct dentry *,		de	)
		    __field(struct inode *,		inode	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->de		= de;
		    __entry->inode	= inode;
			   ),

	    TP_printk("o=%08x d=%p i=%p",
		      __entry->obj, __entry->de, __entry->inode)
	    );

TRACE_EVENT(cachefiles_mkdir,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct dentry *de, int ret),

	    TP_ARGS(obj, de, ret),

	    TP_STRUCT__entry(
		    __field(unsigned int,		obj	)
		    __field(struct dentry *,		de	)
		    __field(int,			ret	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->de		= de;
		    __entry->ret	= ret;
			   ),

	    TP_printk("o=%08x d=%p r=%u",
		      __entry->obj, __entry->de, __entry->ret)
	    );

TRACE_EVENT(cachefiles_create,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct dentry *de, int ret),

	    TP_ARGS(obj, de, ret),

	    TP_STRUCT__entry(
		    __field(unsigned int,		obj	)
		    __field(struct dentry *,		de	)
		    __field(int,			ret	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->de		= de;
		    __entry->ret	= ret;
			   ),

	    TP_printk("o=%08x d=%p r=%u",
		      __entry->obj, __entry->de, __entry->ret)
	    );

TRACE_EVENT(cachefiles_unlink,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct dentry *de,
		     enum fscache_why_object_killed why),

	    TP_ARGS(obj, de, why),

	    /* Note that obj may be NULL */
	    TP_STRUCT__entry(
		    __field(unsigned int,		obj		)
		    __field(struct dentry *,		de		)
		    __field(enum fscache_why_object_killed, why		)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->de		= de;
		    __entry->why	= why;
			   ),

	    TP_printk("o=%08x d=%p w=%s",
		      __entry->obj, __entry->de,
		      __print_symbolic(__entry->why, cachefiles_obj_kill_traces))
	    );

TRACE_EVENT(cachefiles_rename,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct dentry *de,
		     struct dentry *to,
		     enum fscache_why_object_killed why),

	    TP_ARGS(obj, de, to, why),

	    /* Note that obj may be NULL */
	    TP_STRUCT__entry(
		    __field(unsigned int,		obj		)
		    __field(struct dentry *,		de		)
		    __field(struct dentry *,		to		)
		    __field(enum fscache_why_object_killed, why		)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->de		= de;
		    __entry->to		= to;
		    __entry->why	= why;
			   ),

	    TP_printk("o=%08x d=%p t=%p w=%s",
		      __entry->obj, __entry->de, __entry->to,
		      __print_symbolic(__entry->why, cachefiles_obj_kill_traces))
	    );

TRACE_EVENT(cachefiles_mark_active,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct dentry *de),

	    TP_ARGS(obj, de),

	    /* Note that obj may be NULL */
	    TP_STRUCT__entry(
		    __field(unsigned int,		obj		)
		    __field(struct dentry *,		de		)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->de		= de;
			   ),

	    TP_printk("o=%08x d=%p",
		      __entry->obj, __entry->de)
	    );

TRACE_EVENT(cachefiles_mark_inactive,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct dentry *de,
		     struct inode *inode),

	    TP_ARGS(obj, de, inode),

	    /* Note that obj may be NULL */
	    TP_STRUCT__entry(
		    __field(unsigned int,		obj		)
		    __field(struct dentry *,		de		)
		    __field(struct inode *,		inode		)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->de		= de;
		    __entry->inode	= inode;
			   ),

	    TP_printk("o=%08x d=%p i=%p",
		      __entry->obj, __entry->de, __entry->inode)
	    );

TRACE_EVENT(cachefiles_mark_buried,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct dentry *de,
		     enum fscache_why_object_killed why),

	    TP_ARGS(obj, de, why),

	    /* Note that obj may be NULL */
	    TP_STRUCT__entry(
		    __field(unsigned int,		obj		)
		    __field(struct dentry *,		de		)
		    __field(enum fscache_why_object_killed, why		)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->de		= de;
		    __entry->why	= why;
			   ),

	    TP_printk("o=%08x d=%p w=%s",
		      __entry->obj, __entry->de,
		      __print_symbolic(__entry->why, cachefiles_obj_kill_traces))
	    );

TRACE_EVENT(cachefiles_coherency,
	    TP_PROTO(struct cachefiles_object *obj,
		     ino_t ino,
		     enum cachefiles_content content,
		     enum cachefiles_coherency_trace why),

	    TP_ARGS(obj, ino, content, why),

	    /* Note that obj may be NULL */
	    TP_STRUCT__entry(
		    __field(unsigned int,			obj	)
		    __field(enum cachefiles_coherency_trace,	why	)
		    __field(enum cachefiles_content,		content	)
		    __field(u64,				ino	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->why	= why;
		    __entry->content	= content;
		    __entry->ino	= ino;
			   ),

	    TP_printk("o=%08x %s i=%llx c=%u",
		      __entry->obj,
		      __print_symbolic(__entry->why, cachefiles_coherency_traces),
		      __entry->ino,
		      __entry->content)
	    );

TRACE_EVENT(cachefiles_read,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct inode *backer,
		     loff_t start,
		     size_t len),

	    TP_ARGS(obj, backer, start, len),

	    TP_STRUCT__entry(
		    __field(unsigned int,			obj	)
		    __field(unsigned int,			backer	)
		    __field(size_t,				len	)
		    __field(loff_t,				start	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->backer	= backer->i_ino;
		    __entry->start	= start;
		    __entry->len	= len;
			   ),

	    TP_printk("o=%08x b=%08x s=%llx l=%zx",
		      __entry->obj,
		      __entry->backer,
		      __entry->start,
		      __entry->len)
	    );

TRACE_EVENT(cachefiles_write,
	    TP_PROTO(struct cachefiles_object *obj,
		     struct inode *backer,
		     loff_t start,
		     size_t len),

	    TP_ARGS(obj, backer, start, len),

	    TP_STRUCT__entry(
		    __field(unsigned int,			obj	)
		    __field(unsigned int,			backer	)
		    __field(size_t,				len	)
		    __field(loff_t,				start	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->backer	= backer->i_ino;
		    __entry->start	= start;
		    __entry->len	= len;
			   ),

	    TP_printk("o=%08x b=%08x s=%llx l=%zx",
		      __entry->obj,
		      __entry->backer,
		      __entry->start,
		      __entry->len)
	    );

TRACE_EVENT(cachefiles_trunc,
	    TP_PROTO(struct cachefiles_object *obj, struct inode *backer,
		     loff_t from, loff_t to),

	    TP_ARGS(obj, backer, from, to),

	    TP_STRUCT__entry(
		    __field(unsigned int,			obj	)
		    __field(unsigned int,			backer	)
		    __field(loff_t,				from	)
		    __field(loff_t,				to	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->backer	= backer->i_ino;
		    __entry->from	= from;
		    __entry->to		= to;
			   ),

	    TP_printk("o=%08x b=%08x l=%llx->%llx",
		      __entry->obj,
		      __entry->backer,
		      __entry->from,
		      __entry->to)
	    );

TRACE_EVENT(cachefiles_tmpfile,
	    TP_PROTO(struct cachefiles_object *obj, struct inode *backer),

	    TP_ARGS(obj, backer),

	    TP_STRUCT__entry(
		    __field(unsigned int,			obj	)
		    __field(unsigned int,			backer	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->backer	= backer->i_ino;
			   ),

	    TP_printk("o=%08x b=%08x",
		      __entry->obj,
		      __entry->backer)
	    );

TRACE_EVENT(cachefiles_link,
	    TP_PROTO(struct cachefiles_object *obj, struct inode *backer),

	    TP_ARGS(obj, backer),

	    TP_STRUCT__entry(
		    __field(unsigned int,			obj	)
		    __field(unsigned int,			backer	)
			     ),

	    TP_fast_assign(
		    __entry->obj	= obj->fscache.debug_id;
		    __entry->backer	= backer->i_ino;
			   ),

	    TP_printk("o=%08x b=%08x",
		      __entry->obj,
		      __entry->backer)
	    );

#endif /* _TRACE_CACHEFILES_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
