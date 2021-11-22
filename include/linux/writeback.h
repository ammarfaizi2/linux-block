/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/writeback.h
 */
#ifndef WRITEBACK_H
#define WRITEBACK_H

#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/flex_proportions.h>
#include <linux/backing-dev-defs.h>
#include <linux/blk_types.h>

struct bio;

DECLARE_PER_CPU(int, dirty_throttle_leaks);

/*
 * The 1/4 region under the global dirty thresh is for smooth dirty throttling:
 *
 *	(thresh - thresh/DIRTY_FULL_SCOPE, thresh)
 *
 * Further beyond, all dirtier tasks will enter a loop waiting (possibly long
 * time) for the dirty pages to drop, unless written enough pages.
 *
 * The global dirty threshold is normally equal to the global dirty limit,
 * except when the system suddenly allocates a lot of anonymous memory and
 * knocks down the global dirty threshold quickly, in which case the global
 * dirty limit will follow down slowly to prevent livelocking all dirtier tasks.
 */
#define DIRTY_SCOPE		8
#define DIRTY_FULL_SCOPE	(DIRTY_SCOPE / 2)

struct backing_dev_info;

/*
 * fs/fs-writeback.c
 */
enum writeback_sync_modes {
	WB_SYNC_NONE,	/* Don't wait on anything */
	WB_SYNC_ALL,	/* Wait on every mapping */
};

/*
 * A control structure which tells the writeback code what to do.  These are
 * always on the stack, and hence need no locking.  They are always initialised
 * in a manner such that unspecified fields are set to zero.
 */
struct writeback_control {
	long nr_to_write;		/* Write this many pages, and decrement
					   this for each page written */
	long pages_skipped;		/* Pages which were not written */

	/*
	 * For a_ops->writepages(): if start or end are non-zero then this is
	 * a hint that the filesystem need only write out the pages inside that
	 * byterange.  The byte at `end' is included in the writeout request.
	 */
	loff_t range_start;
	loff_t range_end;

	enum writeback_sync_modes sync_mode;

	unsigned for_kupdate:1;		/* A kupdate writeback */
	unsigned for_background:1;	/* A background writeback */
	unsigned tagged_writepages:1;	/* tag-and-write to avoid livelock */
	unsigned for_reclaim:1;		/* Invoked from the page allocator */
	unsigned range_cyclic:1;	/* range_start is cyclic */
	unsigned for_sync:1;		/* sync(2) WB_SYNC_ALL writeback */
	unsigned unpinned_fscache_wb:1;	/* Cleared I_PINNING_FSCACHE_WB */

	/*
	 * When writeback IOs are bounced through async layers, only the
	 * initial synchronous phase should be accounted towards inode
	 * cgroup ownership arbitration to avoid confusion.  Later stages
	 * can set the following flag to disable the accounting.
	 */
	unsigned no_cgroup_owner:1;

	unsigned punt_to_cgroup:1;	/* cgrp punting, see __REQ_CGROUP_PUNT */

#ifdef CONFIG_CGROUP_WRITEBACK
	struct bdi_writeback *wb;	/* wb this writeback is issued under */
	struct inode *inode;		/* inode being written out */

	/* foreign inode detection, see wbc_detach_inode() */
	int wb_id;			/* current wb id */
	int wb_lcand_id;		/* last foreign candidate wb id */
	int wb_tcand_id;		/* this foreign candidate wb id */
	size_t wb_bytes;		/* bytes written by current wb */
	size_t wb_lcand_bytes;		/* bytes written by last candidate */
	size_t wb_tcand_bytes;		/* bytes written by this candidate */
#endif
};

/*
 * A wb_domain represents a domain that wb's (bdi_writeback's) belong to
 * and are measured against each other in.  There always is one global
 * domain, global_wb_domain, that every wb in the system is a member of.
 * This allows measuring the relative bandwidth of each wb to distribute
 * dirtyable memory accordingly.
 */
struct wb_domain {
	spinlock_t lock;

	/*
	 * Scale the writeback cache size proportional to the relative
	 * writeout speed.
	 *
	 * We do this by keeping a floating proportion between BDIs, based
	 * on page writeback completions [end_page_writeback()]. Those
	 * devices that write out pages fastest will get the larger share,
	 * while the slower will get a smaller share.
	 *
	 * We use page writeout completions because we are interested in
	 * getting rid of dirty pages. Having them written out is the
	 * primary goal.
	 *
	 * We introduce a concept of time, a period over which we measure
	 * these events, because demand can/will vary over time. The length
	 * of this period itself is measured in page writeback completions.
	 */
	struct fprop_global completions;
	struct timer_list period_timer;	/* timer for aging of completions */
	unsigned long period_time;

	/*
	 * The dirtyable memory and dirty threshold could be suddenly
	 * knocked down by a large amount (eg. on the startup of KVM in a
	 * swapless system). This may throw the system into deep dirty
	 * exceeded state and throttle heavy/light dirtiers alike. To
	 * retain good responsiveness, maintain global_dirty_limit for
	 * tracking slowly down to the knocked down dirty threshold.
	 *
	 * Both fields are protected by ->lock.
	 */
	unsigned long dirty_limit_tstamp;
	unsigned long dirty_limit;
};

#include <linux/writeback_api.h>

#endif		/* WRITEBACK_H */
