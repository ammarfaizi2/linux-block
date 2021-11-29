#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>

#include <linux/err.h>

#include "util/cpumap.h"
#include "util/ftrace.h"
#include "util/debug.h"
#include "util/bpf_counter.h"

#include "util/bpf_skel/func_latency.skel.h"

static struct func_latency_bpf *skel;

int perf_ftrace__latency_prepare_bpf(struct perf_ftrace *ftrace)
{
	int err;
	struct filter_entry *func;
	struct bpf_link *begin_link, *end_link;

	if (!list_is_singular(&ftrace->filters)) {
		pr_err("ERROR: %s target function(s).\n",
		       list_empty(&ftrace->filters) ? "No" : "Too many");
		return -1;
	}

	func = list_first_entry(&ftrace->filters, struct filter_entry, list);

	skel = func_latency_bpf__open();
	if (!skel) {
		pr_err("Failed to open func latency skeleton\n");
		return -1;
	}

	set_max_rlimit();

	err = func_latency_bpf__load(skel);
	if (err) {
		pr_err("Failed to load func latency skeleton\n");
		goto out;
	}

	begin_link = bpf_program__attach_kprobe(skel->progs.func_begin,
						 false, func->name);
	if (IS_ERR(begin_link)) {
		pr_err("Failed to attach fentry program\n");
		err = PTR_ERR(begin_link);
		goto out;
	}

	end_link = bpf_program__attach_kprobe(skel->progs.func_end,
					      true, func->name);
	if (IS_ERR(end_link)) {
		pr_err("Failed to attach fexit program\n");
		err = PTR_ERR(end_link);
		bpf_link__destroy(begin_link);
		goto out;
	}

	/* XXX: we don't actually use this fd - just for poll() */
	return open("/dev/null", O_RDONLY);

out:
	return err;
}

int perf_ftrace__latency_start_bpf(struct perf_ftrace *ftrace __maybe_unused)
{
	skel->bss->enabled = 1;
	return 0;
}

int perf_ftrace__latency_stop_bpf(struct perf_ftrace *ftrace __maybe_unused)
{
	skel->bss->enabled = 0;
	return 0;
}

int perf_ftrace__latency_read_bpf(struct perf_ftrace *ftrace __maybe_unused,
				  int buckets[])
{
	int i, fd, err;
	u32 idx;
	u64 *hist;
	int ncpus = cpu__max_cpu();

	fd = bpf_map__fd(skel->maps.latency);

	hist = calloc(ncpus, sizeof(*hist));
	if (hist == NULL)
		return -ENOMEM;

	for (idx = 0; idx < NUM_BUCKET; idx++) {
		err = bpf_map_lookup_elem(fd, &idx, hist);
		if (err) {
			buckets[idx] = 0;
			continue;
		}

		for (i = 0; i < ncpus; i++)
			buckets[idx] += hist[i];
	}

	free(hist);
	return 0;
}

int perf_ftrace__latency_cleanup_bpf(struct perf_ftrace *ftrace __maybe_unused)
{
	func_latency_bpf__destroy(skel);
	return 0;
}
