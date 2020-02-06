// SPDX-License-Identifier: GPL-2.0-or-later
/* Object dispatcher
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/freezer.h>
#include "internal.h"

#define FSCACHE_DISPATCHER_POOL_SIZE 8

static LIST_HEAD(fscache_pending_work);
static DEFINE_SPINLOCK(fscache_work_lock);
static DECLARE_WAIT_QUEUE_HEAD(fscache_dispatcher_pool);
static struct completion fscache_dispatcher_pool_done[FSCACHE_DISPATCHER_POOL_SIZE];
static bool fscache_dispatcher_stop;

struct fscache_work {
	struct list_head	link;
	struct fscache_cookie	*cookie;
	struct fscache_object	*object;
	int			param;
	void (*func)(struct fscache_cookie *, struct fscache_object *, int);
};

/*
 * Attempt to queue some work to do.  If there's too much asynchronous work
 * already queued, we'll do it here in this thread instead.
 */
void fscache_dispatch(struct fscache_cookie *cookie,
		      struct fscache_object *object,
		      int param,
		      void (*func)(struct fscache_cookie *,
				   struct fscache_object *, int))
{
	struct fscache_work *work;
	bool queued = false;

	fscache_stat(&fscache_n_dispatch_count);

	work = kzalloc(sizeof(struct fscache_work), GFP_KERNEL);
	if (work) {
		work->cookie = cookie;
		work->object = object;
		work->param = param;
		work->func = func;

		spin_lock(&fscache_work_lock);
		if (waitqueue_active(&fscache_dispatcher_pool) ||
		    list_empty(&fscache_pending_work)) {
			fscache_cookie_get(cookie, fscache_cookie_get_work);
			list_add_tail(&work->link, &fscache_pending_work);
			wake_up(&fscache_dispatcher_pool);
			queued = true;
		}
		spin_unlock(&fscache_work_lock);
		if (queued)
			fscache_stat(&fscache_n_dispatch_deferred);
	}

	if (!queued) {
		kfree(work);
		fscache_stat(&fscache_n_dispatch_inline);
		func(cookie, object, param);
	}
}

/*
 * A dispatcher thread.
 */
static int fscache_dispatcher(void *data)
{
	struct completion *done = data;

	for (;;) {
		if (!list_empty(&fscache_pending_work)) {
			struct fscache_work *work = NULL;

			spin_lock(&fscache_work_lock);
			if (!list_empty(&fscache_pending_work)) {
				work = list_entry(fscache_pending_work.next,
						  struct fscache_work, link);
				list_del_init(&work->link);
			}
			spin_unlock(&fscache_work_lock);

			if (work) {
				work->func(work->cookie, work->object, work->param);
				fscache_stat(&fscache_n_dispatch_in_pool);
				fscache_cookie_put(work->cookie, fscache_cookie_put_work);
				kfree(work);
			}
			continue;
		} else if (fscache_dispatcher_stop) {
			break;
		}

		wait_event_freezable(fscache_dispatcher_pool,
				     (fscache_dispatcher_stop ||
				      !list_empty(&fscache_pending_work)));
	}

	complete_and_exit(done, 0);
}

/*
 * Start up the dispatcher threads.
 */
int fscache_init_dispatchers(void)
{
	struct task_struct *t;
	int i;

	for (i = 0; i < FSCACHE_DISPATCHER_POOL_SIZE; i++) {
		init_completion(&fscache_dispatcher_pool_done[i]);
		t = kthread_create(fscache_dispatcher,
				   &fscache_dispatcher_pool_done[i],
				   "kfsc/%d", i);
		if (IS_ERR(t))
			goto failed;
		wake_up_process(t);
	}

	return 0;

failed:
	fscache_dispatcher_stop = true;
	wake_up_all(&fscache_dispatcher_pool);
	for (i--; i >= 0; i--)
		wait_for_completion(&fscache_dispatcher_pool_done[i]);
	return PTR_ERR(t);
}

/*
 * Kill off the dispatcher threads.
 */
void fscache_kill_dispatchers(void)
{
	int i;

	fscache_dispatcher_stop = true;
	wake_up_all(&fscache_dispatcher_pool);

	for (i = 0; i < FSCACHE_DISPATCHER_POOL_SIZE; i++)
		wait_for_completion(&fscache_dispatcher_pool_done[i]);
}
