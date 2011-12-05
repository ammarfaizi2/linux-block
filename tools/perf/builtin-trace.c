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

typedef void (*strace_handler_t)(struct perf_sample *sample,
				 struct event *event);

static void strace__sys_enter(struct perf_sample *sample,
			      struct event *event)
{
	printf("sys_enter %llu\n",
	       raw_field_value(event, "id", sample->raw_data));
}

static void strace__sys_exit(struct perf_sample *sample,
			     struct event *event)
{
	printf("sys_enter %llu\n",
	       raw_field_value(event, "id", sample->raw_data));
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

	return 0;
}

static size_t perf_evlist__fprintf(struct perf_evlist *evlist,
				   FILE *fp, const char *fmt, ...)
{
	struct perf_evsel *evsel;
	bool first = true;
	va_list ap;
	int printed;

	va_start(ap, fmt);
	printed = vfprintf(fp, fmt, ap);
	va_end(ap);

	list_for_each_entry(evsel, &evlist->entries, node) {
		if (!first)
			printed += fprintf(fp, ", ");
		else
			first = false;
		printed += fprintf(fp, "%s", event_name(evsel));
		fflush(fp);
	}

	return printed;
}

static int strace(struct perf_trace *tr, const char *argv[])
{
	const char *tracepoints[] = {
		"raw_syscalls:sys_enter",
		"raw_syscalls:sys_exit",
	};
	const struct perf_evsel_str_handler handlers[] = {
		{ "raw_syscalls:sys_enter", strace__sys_enter, },
		{ "raw_syscalls:sys_exit",  strace__sys_exit,  },
	};
	struct perf_evlist *evlist = perf_evlist__new(NULL, NULL);
	struct perf_evsel *evsel;
	struct perf_sample sample;
	u64 total_events = 0, sample_type;
	strace_handler_t handler;
	int i, sample_size, err = -1;

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

	err = perf_evlist__set_tracepoints_handlers_array(evlist, handlers);
	if (err < 0) {
		pr_debug("Couldn't associate handlers to tracepoints!\n");
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

	sample_type = perf_evlist__sample_type(evlist);
	sample_size = __perf_evsel__sample_size(sample_type);

	perf_evlist__enable(evlist);

	perf_evlist__fprintf(evlist, stdout, "nr_entries: %d\n", evlist->nr_entries); fputc('\n', stdout);

	perf_evlist__start_workload(evlist);

	verbose = 10;

	while (1) {
		u64 before = total_events;

		for (i = 0; i < evlist->nr_mmaps; i++) {
			union perf_event *event;

			while ((event = perf_evlist__mmap_read(evlist, i)) != NULL) {
				const u32 type = event->header.type;

				++total_events;

				err = perf_event__parse_sample(event, sample_type,
							       sample_size, true,
							       &sample, false);
				if (err < 0) {
					pr_debug("Couldn't parse sample, skipping it...\n");
					continue;
				}

				switch (type) {
				case PERF_RECORD_SAMPLE:
					break;
				case PERF_RECORD_EXIT:
					if ((pid_t)event->fork.pid == evlist->workload.pid)
						goto workload_exit;
					/* Fall thru */
				default:
					perf_event__fprintf(event, stdout);
					continue;
				}

				evsel = perf_evlist__id2evsel(evlist, sample.id);

				if (evsel == NULL) {
					pr_debug("evsel for id %" PRIu64 "not found, skipping event...\n",
						 sample.id);
					continue;
				}

				if (evsel->handler.data == NULL) {
					int t = trace_parse_common_type(sample.raw_data);

					fprintf(stderr, "t=%d\n", t); fflush(stderr);
					evsel->handler.data = trace_find_event(t);
				}

				handler = evsel->handler.func;
				pr_info("%" PRIu64" %d ", sample.time, sample.cpu);
				handler(&sample, evsel->handler.data);
				fflush(stdout);
			}
		}

		/*
		 * PERF_RECORD_{!SAMPLE} events don't honour
		 * perf_event_attr.wakeup_events, just PERF_EVENT_SAMPLE does.
		 */
		if (total_events == before && false)
			poll(evlist->pollfd, evlist->nr_fds, -1);
	}
workload_exit:
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
			.sample	 = trace__process_sample,
			.comm	 = perf_event__process_comm,
		},
		.opts = {
			.target_pid = -1,
			.target_tid = -1,
			.mmap_pages = 1024,
			.no_delay   = true,
			.freq	    = 1000,
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
