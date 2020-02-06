// SPDX-License-Identifier: GPL-2.0-or-later
/* FS-Cache statistics
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "internal.h"

/*
 * operation counters
 */
atomic_t fscache_n_op_pend;
atomic_t fscache_n_op_run;
atomic_t fscache_n_op_enqueue;
atomic_t fscache_n_op_deferred_release;
atomic_t fscache_n_op_initialised;
atomic_t fscache_n_op_release;
atomic_t fscache_n_op_gc;
atomic_t fscache_n_op_cancelled;
atomic_t fscache_n_op_rejected;

atomic_t fscache_n_acquires;
atomic_t fscache_n_acquires_null;
atomic_t fscache_n_acquires_no_cache;
atomic_t fscache_n_acquires_ok;
atomic_t fscache_n_acquires_nobufs;
atomic_t fscache_n_acquires_oom;

atomic_t fscache_n_invalidates;
atomic_t fscache_n_invalidates_run;

atomic_t fscache_n_updates;
atomic_t fscache_n_updates_null;
atomic_t fscache_n_updates_run;

atomic_t fscache_n_relinquishes;
atomic_t fscache_n_relinquishes_null;
atomic_t fscache_n_relinquishes_retire;

atomic_t fscache_n_cookie_index;
atomic_t fscache_n_cookie_data;
atomic_t fscache_n_cookie_special;

atomic_t fscache_n_object_alloc;
atomic_t fscache_n_object_no_alloc;
atomic_t fscache_n_object_lookups;
atomic_t fscache_n_object_lookups_negative;
atomic_t fscache_n_object_lookups_positive;
atomic_t fscache_n_object_lookups_timed_out;
atomic_t fscache_n_object_created;
atomic_t fscache_n_object_avail;
atomic_t fscache_n_object_dead;

atomic_t fscache_n_cop_alloc_object;
atomic_t fscache_n_cop_lookup_object;
atomic_t fscache_n_cop_lookup_complete;
atomic_t fscache_n_cop_grab_object;
atomic_t fscache_n_cop_invalidate_object;
atomic_t fscache_n_cop_update_object;
atomic_t fscache_n_cop_drop_object;
atomic_t fscache_n_cop_put_object;
atomic_t fscache_n_cop_sync_cache;
atomic_t fscache_n_cop_attr_changed;

atomic_t fscache_n_cache_no_space_reject;
atomic_t fscache_n_cache_stale_objects;
atomic_t fscache_n_cache_retired_objects;
atomic_t fscache_n_cache_culled_objects;

/*
 * display the general statistics
 */
int fscache_stats_show(struct seq_file *m, void *v)
{
	seq_puts(m, "FS-Cache statistics\n");

	seq_printf(m, "Cookies: idx=%u dat=%u spc=%u\n",
		   atomic_read(&fscache_n_cookie_index),
		   atomic_read(&fscache_n_cookie_data),
		   atomic_read(&fscache_n_cookie_special));

	seq_printf(m, "Objects: alc=%u nal=%u avl=%u ded=%u\n",
		   atomic_read(&fscache_n_object_alloc),
		   atomic_read(&fscache_n_object_no_alloc),
		   atomic_read(&fscache_n_object_avail),
		   atomic_read(&fscache_n_object_dead));

	seq_printf(m, "Acquire: n=%u nul=%u noc=%u ok=%u nbf=%u"
		   " oom=%u\n",
		   atomic_read(&fscache_n_acquires),
		   atomic_read(&fscache_n_acquires_null),
		   atomic_read(&fscache_n_acquires_no_cache),
		   atomic_read(&fscache_n_acquires_ok),
		   atomic_read(&fscache_n_acquires_nobufs),
		   atomic_read(&fscache_n_acquires_oom));

	seq_printf(m, "Lookups: n=%u neg=%u pos=%u crt=%u tmo=%u\n",
		   atomic_read(&fscache_n_object_lookups),
		   atomic_read(&fscache_n_object_lookups_negative),
		   atomic_read(&fscache_n_object_lookups_positive),
		   atomic_read(&fscache_n_object_created),
		   atomic_read(&fscache_n_object_lookups_timed_out));

	seq_printf(m, "Invals : n=%u run=%u\n",
		   atomic_read(&fscache_n_invalidates),
		   atomic_read(&fscache_n_invalidates_run));

	seq_printf(m, "Updates: n=%u nul=%u run=%u\n",
		   atomic_read(&fscache_n_updates),
		   atomic_read(&fscache_n_updates_null),
		   atomic_read(&fscache_n_updates_run));

	seq_printf(m, "Relinqs: n=%u nul=%u rtr=%u\n",
		   atomic_read(&fscache_n_relinquishes),
		   atomic_read(&fscache_n_relinquishes_null),
		   atomic_read(&fscache_n_relinquishes_retire));

	seq_printf(m, "Ops    : pend=%u run=%u enq=%u can=%u rej=%u\n",
		   atomic_read(&fscache_n_op_pend),
		   atomic_read(&fscache_n_op_run),
		   atomic_read(&fscache_n_op_enqueue),
		   atomic_read(&fscache_n_op_cancelled),
		   atomic_read(&fscache_n_op_rejected));
	seq_printf(m, "Ops    : ini=%u dfr=%u rel=%u gc=%u\n",
		   atomic_read(&fscache_n_op_initialised),
		   atomic_read(&fscache_n_op_deferred_release),
		   atomic_read(&fscache_n_op_release),
		   atomic_read(&fscache_n_op_gc));

	seq_printf(m, "CacheOp: alo=%d luo=%d luc=%d gro=%d\n",
		   atomic_read(&fscache_n_cop_alloc_object),
		   atomic_read(&fscache_n_cop_lookup_object),
		   atomic_read(&fscache_n_cop_lookup_complete),
		   atomic_read(&fscache_n_cop_grab_object));
	seq_printf(m, "CacheOp: inv=%d upo=%d dro=%d pto=%d atc=%d syn=%d\n",
		   atomic_read(&fscache_n_cop_invalidate_object),
		   atomic_read(&fscache_n_cop_update_object),
		   atomic_read(&fscache_n_cop_drop_object),
		   atomic_read(&fscache_n_cop_put_object),
		   atomic_read(&fscache_n_cop_attr_changed),
		   atomic_read(&fscache_n_cop_sync_cache));
	seq_printf(m, "CacheEv: nsp=%d stl=%d rtr=%d cul=%d\n",
		   atomic_read(&fscache_n_cache_no_space_reject),
		   atomic_read(&fscache_n_cache_stale_objects),
		   atomic_read(&fscache_n_cache_retired_objects),
		   atomic_read(&fscache_n_cache_culled_objects));
	netfs_stats_show(m);
	return 0;
}
