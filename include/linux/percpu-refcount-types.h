/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Percpu refcounts:
 * (C) 2012 Google, Inc.
 * Author: Kent Overstreet <koverstreet@google.com>
 *
 * This implements a refcount with similar semantics to atomic_t - atomic_inc(),
 * atomic_dec_and_test() - but percpu.
 *
 * There's one important difference between percpu refs and normal atomic_t
 * refcounts; you have to keep track of your initial refcount, and then when you
 * start shutting down you call percpu_ref_kill() _before_ dropping the initial
 * refcount.
 *
 * The refcount will have a range of 0 to ((1U << 31) - 1), i.e. one bit less
 * than an atomic_t - this is because of the way shutdown works, see
 * percpu_ref_kill()/PERCPU_COUNT_BIAS.
 *
 * Before you call percpu_ref_kill(), percpu_ref_put() does not check for the
 * refcount hitting 0 - it can't, if it was in percpu mode. percpu_ref_kill()
 * puts the ref back in single atomic_t mode, collecting the per cpu refs and
 * issuing the appropriate barriers, and then marks the ref as shutting down so
 * that percpu_ref_put() will check for the ref hitting 0.  After it returns,
 * it's safe to drop the initial ref.
 *
 * USAGE:
 *
 * See fs/aio.c for some example usage; it's used there for struct kioctx, which
 * is created when userspaces calls io_setup(), and destroyed when userspace
 * calls io_destroy() or the process exits.
 *
 * In the aio code, kill_ioctx() is called when we wish to destroy a kioctx; it
 * removes the kioctx from the proccess's table of kioctxs and kills percpu_ref.
 * After that, there can't be any new users of the kioctx (from lookup_ioctx())
 * and it's then safe to drop the initial ref with percpu_ref_put().
 *
 * Note that the free path, free_ioctx(), needs to go through explicit call_rcu()
 * to synchronize with RCU protected lookup_ioctx().  percpu_ref operations don't
 * imply RCU grace periods of any kind and if a user wants to combine percpu_ref
 * with RCU protection, it must be done explicitly.
 *
 * Code that does a two stage shutdown like this often needs some kind of
 * explicit synchronization to ensure the initial refcount can only be dropped
 * once - percpu_ref_kill() does this for you, it returns true once and false if
 * someone else already called it. The aio code uses it this way, but it's not
 * necessary if the code has some other mechanism to synchronize teardown.
 * around.
 */

#ifndef _LINUX_PERCPU_REFCOUNT_TYPES_H
#define _LINUX_PERCPU_REFCOUNT_TYPES_H

#include <linux/atomic.h>

struct percpu_ref;
typedef void (percpu_ref_func_t)(struct percpu_ref *);

/* flags set in the lower bits of percpu_ref->percpu_count_ptr */
enum {
	__PERCPU_REF_ATOMIC	= 1LU << 0,	/* operating in atomic mode */
	__PERCPU_REF_DEAD	= 1LU << 1,	/* (being) killed */
	__PERCPU_REF_ATOMIC_DEAD = __PERCPU_REF_ATOMIC | __PERCPU_REF_DEAD,

	__PERCPU_REF_FLAG_BITS	= 2,
};

/* @flags for percpu_ref_init() */
enum {
	/*
	 * Start w/ ref == 1 in atomic mode.  Can be switched to percpu
	 * operation using percpu_ref_switch_to_percpu().  If initialized
	 * with this flag, the ref will stay in atomic mode until
	 * percpu_ref_switch_to_percpu() is invoked on it.
	 * Implies ALLOW_REINIT.
	 */
	PERCPU_REF_INIT_ATOMIC	= 1 << 0,

	/*
	 * Start dead w/ ref == 0 in atomic mode.  Must be revived with
	 * percpu_ref_reinit() before used.  Implies INIT_ATOMIC and
	 * ALLOW_REINIT.
	 */
	PERCPU_REF_INIT_DEAD	= 1 << 1,

	/*
	 * Allow switching from atomic mode to percpu mode.
	 */
	PERCPU_REF_ALLOW_REINIT	= 1 << 2,
};

struct percpu_ref_data {
	atomic_long_t		count;
	percpu_ref_func_t	*release;
	percpu_ref_func_t	*confirm_switch;
	bool			force_atomic:1;
	bool			allow_reinit:1;
	struct rcu_head		rcu;
	struct percpu_ref	*ref;
};

struct percpu_ref {
	/*
	 * The low bit of the pointer indicates whether the ref is in percpu
	 * mode; if set, then get/put will manipulate the atomic_t.
	 */
	unsigned long		percpu_count_ptr;

	/*
	 * 'percpu_ref' is often embedded into user structure, and only
	 * 'percpu_count_ptr' is required in fast path, move other fields
	 * into 'percpu_ref_data', so we can reduce memory footprint in
	 * fast path.
	 */
	struct percpu_ref_data  *data;
};

#endif /* _LINUX_PERCPU_REFCOUNT_TYPES_H */
