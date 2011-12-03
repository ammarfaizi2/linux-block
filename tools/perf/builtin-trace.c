#include "builtin.h"
#include "perf.h"

#include "util/util.h"
#include "util/cache.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"

#include "util/parse-options.h"
#include "util/trace-event.h"

#include "util/debug.h"
#include "util/evlist.h"
#include "util/evsel.h"
#include "util/tool.h"

#include <sys/types.h>
#include <sys/prctl.h>
#include <semaphore.h>
#include <pthread.h>
#include <math.h>
#include <limits.h>

#include <linux/list.h>
#include <linux/hash.h>

struct perf_trace {
	struct perf_tool	tool;
	struct perf_record_opts opts;
};

static void process_sys_enter(struct perf_sample *sample,
			      struct event *event)
{
	printf("sys_enter %llu\n",
	       raw_field_value(event, "id", sample->raw_data));
}

static void process_sys_exit(struct perf_sample *sample,
			     struct event *event)
{
	printf("sys_exit %llu\n",
	       raw_field_value(event, "id", sample->raw_data));
}

static void process_raw_event(struct perf_sample *sample)
{
	int type = trace_parse_common_type(sample->raw_data);
	struct event *event = trace_find_event(type);

	if (!strcmp(event->name, "sys_enter"))
		process_sys_enter(sample, event);
	else if (!strcmp(event->name, "sys_exit"))
		process_sys_exit(sample, event);
}

static int trace__process_sample(struct perf_tool *tool __used,
				 union perf_event *event,
				 struct perf_sample *sample,
				 struct perf_evsel *evsel __used,
				 struct machine *machine)
{
	struct thread *thread = machine__findnew_thread(machine, sample->tid);

	if (thread == NULL) {
		pr_debug("problem processing %d event, skipping it.\n",
			event->header.type);
		return -1;
	}

	process_raw_event(sample);

	return 0;
}

static int strace(struct perf_trace *tr, const char *argv[])
{
	const char *tracepoints[] = {
		"raw_syscalls:sys_enter",
		"raw_syscalls:sys_exit",
	};
	struct perf_evlist *evlist = perf_evlist__new(NULL, NULL);
	int err = -1;

	if (evlist == NULL) {
		pr_debug("Not enough memory to create evlist\n");
		goto out;
	}

	err = perf_evlist__create_maps(evlist, tr->opts.target_pid,
				       tr->opts.target_tid, tr->opts.cpu_list);
	if (err < 0) {
		pr_debug("Not enough memory to create thread/cpu maps\n");
		goto out_delete_evlist;
	}

	err = perf_evlist__add_tracepoints_array(evlist, tracepoints);
	if (err < 0) {
		pr_debug("Not enough memory to add tracepoints to evlist\n");
		goto out_delete_evlist;
	}

	err = perf_evlist__prepare_workload(evlist, &tr->opts, argv);
	if (err < 0) {
		pr_debug("Couldn't run the workload!\n");
		goto out_delete_evlist;
	}

	/*
	 * So that we don't have to worry about event reordering at this stage
	 * in 'trace' development. Later we'll refactor the perf_session
	 * sample ordering code and use here.
	 */
	err = sched__isolate_on_first_possible_cpu(evlist->workload.pid);
	if (err < 0) {
		pr_debug("sched__isolate_on_first_possible_cpu: %s\n",
			 strerror(errno));
		goto out_delete_evlist;
	}

	perf_evlist__config_attrs(evlist, &tr->opts);

	err = perf_evlist__open(evlist, tr->opts.group);
	if (err < 0) {
		pr_debug("Problems in perf_evlist__open: %s\n", strerror(errno));
		goto out_delete_evlist;
	}

	err = perf_evlist__mmap(evlist, tr->opts.mmap_pages, false);
	if (err < 0) {
		pr_debug("Problems in perf_evlist__mmap: %s\n", strerror(errno));
		goto out_delete_evlist;
	}

	perf_evlist__enable(evlist);

	perf_evlist__start_workload(evlist);

	perf_evlist__munmap(evlist);
out_delete_evlist:
	perf_evlist__delete(evlist);
out:
	return err;
}

int cmd_trace(int argc, const char **argv, const char *prefix __used)
{
	struct perf_trace trace = {
		.tool = {
			.sample		 = trace__process_sample,
			.comm		 = perf_event__process_comm,
			.ordered_samples = true,
		},
		.opts = {
			.target_pid = -1,
			.target_tid = -1,
			.mmap_pages = 1024,
			.sample_id_all_avail = true,
		},
	};
	const char * const trace_usage[] = {
		"trace [options] command",
		NULL
	};
	const struct option options[] = {
	OPT_INCR('v', "verbose", &verbose,
		 "be more verbose (show counter open errors, etc)"),
	OPT_END()
	};

	argc = parse_options(argc, argv, options, trace_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc)
		usage_with_options(trace_usage, options);

	return strace(&trace, argv);
}
