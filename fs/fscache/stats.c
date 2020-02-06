// SPDX-License-Identifier: GPL-2.0-or-later
/* FS-Cache statistics
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netfs.h>
#include "internal.h"

/*
 * operation counters
 */
atomic_t fscache_n_acquires;
atomic_t fscache_n_acquires_null;
atomic_t fscache_n_acquires_no_cache;
atomic_t fscache_n_acquires_ok;
atomic_t fscache_n_acquires_oom;

atomic_t fscache_n_invalidates;

atomic_t fscache_n_updates;
atomic_t fscache_n_updates_run;

atomic_t fscache_n_relinquishes;
atomic_t fscache_n_relinquishes_retire;

atomic_t fscache_n_resizes;
atomic_t fscache_n_resizes_null;

atomic_t fscache_n_cookie_index;
atomic_t fscache_n_cookie_data;
atomic_t fscache_n_cookie_special;

atomic_t fscache_n_object_alloc;
atomic_t fscache_n_object_no_alloc;
atomic_t fscache_n_object_lookups;
atomic_t fscache_n_object_lookups_negative;
atomic_t fscache_n_object_lookups_positive;
atomic_t fscache_n_object_creates;
atomic_t fscache_n_object_avail;
atomic_t fscache_n_object_dead;

atomic_t fscache_n_cop_alloc_object;
atomic_t fscache_n_cop_lookup_object;
atomic_t fscache_n_cop_create_object;
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

atomic_t fscache_n_dispatch_count;
atomic_t fscache_n_dispatch_deferred;
atomic_t fscache_n_dispatch_inline;
atomic_t fscache_n_dispatch_in_pool;

atomic_t fscache_n_read;
EXPORT_SYMBOL(fscache_n_read);
atomic_t fscache_n_write;
EXPORT_SYMBOL(fscache_n_write);

/*
 * display the general statistics
 */
static int fscache_stats_show(struct seq_file *m, void *v)
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

	seq_printf(m, "Acquire: n=%u nul=%u noc=%u ok=%u oom=%u\n",
		   atomic_read(&fscache_n_acquires),
		   atomic_read(&fscache_n_acquires_null),
		   atomic_read(&fscache_n_acquires_no_cache),
		   atomic_read(&fscache_n_acquires_ok),
		   atomic_read(&fscache_n_acquires_oom));

	seq_printf(m, "Lookups: n=%u neg=%u pos=%u crt=%u\n",
		   atomic_read(&fscache_n_object_lookups),
		   atomic_read(&fscache_n_object_lookups_negative),
		   atomic_read(&fscache_n_object_lookups_positive),
		   atomic_read(&fscache_n_object_creates));

	seq_printf(m, "Invals : n=%u\n",
		   atomic_read(&fscache_n_invalidates));

	seq_printf(m, "Updates: n=%u rsz=%u rsn=%u\n",
		   atomic_read(&fscache_n_updates),
		   atomic_read(&fscache_n_resizes),
		   atomic_read(&fscache_n_resizes_null));

	seq_printf(m, "Relinqs: n=%u rtr=%u\n",
		   atomic_read(&fscache_n_relinquishes),
		   atomic_read(&fscache_n_relinquishes_retire));

	seq_printf(m, "CacheOp: alo=%d luo=%d\n",
		   atomic_read(&fscache_n_cop_alloc_object),
		   atomic_read(&fscache_n_cop_lookup_object));
	seq_printf(m, "CacheOp: inv=%d dro=%d pto=%d atc=%d syn=%d\n",
		   atomic_read(&fscache_n_cop_invalidate_object),
		   atomic_read(&fscache_n_cop_drop_object),
		   atomic_read(&fscache_n_cop_put_object),
		   atomic_read(&fscache_n_cop_attr_changed),
		   atomic_read(&fscache_n_cop_sync_cache));
	seq_printf(m, "CacheEv: nsp=%d stl=%d rtr=%d cul=%d\n",
		   atomic_read(&fscache_n_cache_no_space_reject),
		   atomic_read(&fscache_n_cache_stale_objects),
		   atomic_read(&fscache_n_cache_retired_objects),
		   atomic_read(&fscache_n_cache_culled_objects));

	seq_printf(m, "Disp   : n=%u il=%u df=%u pl=%u\n",
		   atomic_read(&fscache_n_dispatch_count),
		   atomic_read(&fscache_n_dispatch_inline),
		   atomic_read(&fscache_n_dispatch_deferred),
		   atomic_read(&fscache_n_dispatch_in_pool));

	seq_printf(m, "IO     : rd=%u wr=%u\n",
		   atomic_read(&fscache_n_read),
		   atomic_read(&fscache_n_write));

	netfs_stats_show(m);
	return 0;
}

int __init fscache_proc_stats_init(void)
{
	if (!proc_create_single("fs/fscache/stats", S_IFREG | 0444, NULL,
			fscache_stats_show))
		return -ENOMEM;
	return 0;
}
