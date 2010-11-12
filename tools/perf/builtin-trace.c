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
#include "util/session.h"

#include <sys/types.h>
#include <sys/prctl.h>
#include <semaphore.h>
#include <pthread.h>
#include <math.h>
#include <limits.h>

#include <linux/list.h>
#include <linux/hash.h>

static struct perf_session *session;

static void process_sys_enter(void *data,
			      struct event *event __used,
			      int cpu __used,
			      u64 timestamp __used,
			      struct thread *thread __used)
{
	printf("sys_enter %llu\n", raw_field_value(event, "id", data));
}

static void process_sys_exit(void *data,
			     struct event *event __used,
			     int cpu __used,
			     u64 timestamp __used,
			     struct thread *thread __used)
{
	printf("sys_exit %llu\n", raw_field_value(event, "id", data));
}

static void
process_raw_event(void *data, int cpu, u64 timestamp, struct thread *thread)
{
	struct event *event;
	int type;

	type = trace_parse_common_type(data);
	event = trace_find_event(type);

	if (!strcmp(event->name, "sys_enter"))
		process_sys_enter(data, event, cpu, timestamp, thread);
	if (!strcmp(event->name, "sys_exit"))
		process_sys_exit(data, event, cpu, timestamp, thread);
}

static int process_sample_event(union perf_event *self, struct perf_sample *sample __used, struct perf_evsel *evsel __used, struct perf_session *s)
{
	struct perf_sample data;
	struct thread *thread;

	bzero(&data, sizeof(data));
	perf_event__parse_sample(self, s->sample_type, s->sample_id_all, &data);

	thread = perf_session__findnew(s, data.tid);
	if (thread == NULL) {
		pr_debug("problem processing %d event, skipping it.\n",
			self->header.type);
		return -1;
	}

	process_raw_event(data.raw_data, data.cpu, data.time, thread);

	return 0;
}

static struct perf_event_ops eops = {
	.sample			= process_sample_event,
	.comm			= perf_event__process_comm,
	.ordered_samples	= true,
};

static char const *input_name = "perf.data";

static int read_events(void)
{
	session = perf_session__new(input_name, O_RDONLY, 0, false, &eops);
	if (!session)
		die("Initializing perf session failed\n");

	return perf_session__process_events(session, &eops);
}

static void __cmd_report(void)
{
	read_events();
}

static const char * const report_usage[] = {
	"perf trace report [<options>]",
	NULL
};

static const struct option report_options[] = {
	OPT_END()
};

static const char * const trace_usage[] = {
	"perf trace [<options>] {record|report}",
	NULL
};

static const struct option trace_options[] = {
	OPT_END()
};

static const char *record_args[] = {
	"record",
	"-R",
	"-f",
	"-m", "1024",
	"-c", "1",
	"-e", "raw_syscalls:sys_enter:r",
	"-e", "raw_syscalls:sys_exit:r",
};

static int __cmd_record(int argc, const char **argv)
{
	unsigned int rec_argc, i, j;
	const char **rec_argv;

	rec_argc = ARRAY_SIZE(record_args) + argc - 1;
	rec_argv = calloc(rec_argc + 1, sizeof(char *));

	for (i = 0; i < ARRAY_SIZE(record_args); i++)
		rec_argv[i] = strdup(record_args[i]);

	for (j = 1; j < (unsigned int)argc; j++, i++)
		rec_argv[i] = argv[j];

	BUG_ON(i != rec_argc);

	return cmd_record(i, rec_argv, NULL);
}

static void cmd_trace_report(int argc, const char **argv)
{
	parse_options(argc, argv, report_options, report_usage, 0);
	__cmd_report();
}

int cmd_trace(int argc, const char **argv, const char *prefix __used)
{
	int ret;

	argc = parse_options(argc, argv, trace_options, trace_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc)
		usage_with_options(trace_usage, trace_options);

	if (!strncmp(argv[0], "rec", 3)) {
		ret = __cmd_record(argc, argv);
		if (!ret)
			cmd_trace_report(argc, argv);
		return ret;
	} else if (!strncmp(argv[0], "report", 6)) {
		cmd_trace_report(argc, argv);
	} else {
		usage_with_options(trace_usage, trace_options);
	}
	return 0;
}
