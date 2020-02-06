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
atomic_t fscache_n_volumes;
atomic_t fscache_n_volumes_collision;
atomic_t fscache_n_volumes_nomem;
atomic_t fscache_n_cookies;

atomic_t fscache_n_retrievals;
atomic_t fscache_n_retrievals_ok;
atomic_t fscache_n_retrievals_wait;
atomic_t fscache_n_retrievals_nodata;
atomic_t fscache_n_retrievals_nobufs;
atomic_t fscache_n_retrievals_intr;
atomic_t fscache_n_retrievals_nomem;
atomic_t fscache_n_retrievals_object_dead;
atomic_t fscache_n_retrieval_ops;
atomic_t fscache_n_retrieval_op_waits;

atomic_t fscache_n_stores;
atomic_t fscache_n_stores_ok;
atomic_t fscache_n_stores_again;
atomic_t fscache_n_stores_nobufs;
atomic_t fscache_n_stores_intr;
atomic_t fscache_n_stores_oom;
atomic_t fscache_n_store_ops;
atomic_t fscache_n_stores_object_dead;
atomic_t fscache_n_store_op_waits;

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
atomic_t fscache_n_relinquishes_dropped;

atomic_t fscache_n_resizes;
atomic_t fscache_n_resizes_null;

atomic_t fscache_n_read;
EXPORT_SYMBOL(fscache_n_read);
atomic_t fscache_n_write;
EXPORT_SYMBOL(fscache_n_write);

/*
 * display the general statistics
 */
int fscache_stats_show(struct seq_file *m, void *v)
{
	seq_puts(m, "FS-Cache statistics\n");
	seq_printf(m, "Cookies: n=%d v=%d vcol=%u voom=%u\n",
		   atomic_read(&fscache_n_cookies),
		   atomic_read(&fscache_n_volumes),
		   atomic_read(&fscache_n_volumes_collision),
		   atomic_read(&fscache_n_volumes_nomem)
		   );

	seq_printf(m, "Acquire: n=%u nul=%u noc=%u ok=%u nbf=%u"
		   " oom=%u\n",
		   atomic_read(&fscache_n_acquires),
		   atomic_read(&fscache_n_acquires_null),
		   atomic_read(&fscache_n_acquires_no_cache),
		   atomic_read(&fscache_n_acquires_ok),
		   atomic_read(&fscache_n_acquires_nobufs),
		   atomic_read(&fscache_n_acquires_oom));

	seq_printf(m, "Invals : n=%u run=%u\n",
		   atomic_read(&fscache_n_invalidates),
		   atomic_read(&fscache_n_invalidates_run));

	seq_printf(m, "Updates: n=%u nul=%u run=%u\n",
		   atomic_read(&fscache_n_updates),
		   atomic_read(&fscache_n_updates_null),
		   atomic_read(&fscache_n_updates_run));

	seq_printf(m, "Relinqs: n=%u rtr=%u drop=%u\n",
		   atomic_read(&fscache_n_relinquishes),
		   atomic_read(&fscache_n_relinquishes_retire),
		   atomic_read(&fscache_n_relinquishes_dropped));

	seq_printf(m, "IO     : rd=%u wr=%u\n",
		   atomic_read(&fscache_n_read),
		   atomic_read(&fscache_n_write));

	netfs_stats_show(m);
	return 0;
}
