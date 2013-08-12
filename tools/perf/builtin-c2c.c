#include "builtin.h"
#include "cache.h"

#include "util/evlist.h"
#include "util/parse-options.h"
#include "util/session.h"
#include "util/tool.h"

#include <linux/compiler.h>
#include <linux/kernel.h>

struct perf_c2c {
	struct perf_tool tool;
};

static int perf_sample__fprintf(struct perf_sample *sample,
				struct perf_evsel *evsel,
				struct addr_location *al, FILE *fp)
{
	return fprintf(fp, "%25.25s: %5d %5d 0x%016" PRIx64 " 0x016%" PRIx64 " %5" PRIu64 " 0x%06" PRIx64 " %s:%s\n",
		       perf_evsel__name(evsel),
		       sample->pid, sample->tid, sample->ip, sample->addr,
		       sample->weight, sample->data_src,
		       al->map ? (al->map->dso ? al->map->dso->long_name : "???") : "???",
		       al->sym ? al->sym->name : "???");
}

static int perf_c2c__process_load(struct perf_evsel *evsel,
				  struct perf_sample *sample,
				  struct addr_location *al)
{
	perf_sample__fprintf(sample, evsel, al, stdout);
	return 0;
}

static int perf_c2c__process_store(struct perf_evsel *evsel,
				   struct perf_sample *sample,
				   struct addr_location *al)
{
	perf_sample__fprintf(sample, evsel, al, stdout);
	return 0;
}

static const struct perf_evsel_str_handler handlers[] = {
	{ "cpu/mem-loads,ldlat=30/pp", perf_c2c__process_load, },
	{ "cpu/mem-stores/pp",	       perf_c2c__process_store, },
};

typedef int (*sample_handler)(struct perf_evsel *evsel,
			      struct perf_sample *sample,
			      struct addr_location *al);

static int perf_c2c__process_sample(struct perf_tool *tool __maybe_unused,
				    union perf_event *event,
				    struct perf_sample *sample,
				    struct perf_evsel *evsel,
				    struct machine *machine)
{
	struct addr_location al;
	int err = 0;

	if (perf_event__preprocess_sample(event, machine, &al, sample) < 0) {
		pr_err("problem processing %d event, skipping it.\n",
		       event->header.type);
		return -1;
	}

	if (evsel->handler.func != NULL) {
		sample_handler f = evsel->handler.func;
		err = f(evsel, sample, &al);
	}

	return err;
}

static int perf_c2c__read_events(struct perf_c2c *c2c)
{
	int err = -1;
	struct perf_session *session;

	session = perf_session__new(input_name, O_RDONLY, 0, false, &c2c->tool);
	if (session == NULL) {
		pr_debug("No memory for session\n");
		goto out;
	}

	if (perf_evlist__set_handlers(session->evlist, handlers))
		goto out_delete;

	err = perf_session__process_events(session, &c2c->tool);
	if (err)
		pr_err("Failed to process events, error %d", err);

out_delete:
	perf_session__delete(session);
out:
	return err;
}

static int perf_c2c__report(struct perf_c2c *c2c)
{
	setup_pager();
	return perf_c2c__read_events(c2c);
}

static int perf_c2c__record(int argc, const char **argv)
{
	unsigned int rec_argc, i, j;
	const char **rec_argv;
	const char * const record_args[] = {
		"record",
		/* "--phys-addr", */
		"-W",
		"-d",
		"-a",
	};

	rec_argc = ARRAY_SIZE(record_args) + 2 * ARRAY_SIZE(handlers) + argc - 1;
	rec_argv = calloc(rec_argc + 1, sizeof(char *));

	if (rec_argv == NULL)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(record_args); i++)
		rec_argv[i] = strdup(record_args[i]);

	for (j = 0; j < ARRAY_SIZE(handlers); j++) {
		rec_argv[i++] = strdup("-e");
		rec_argv[i++] = strdup(handlers[j].name);
	}

	for (j = 1; j < (unsigned int)argc; j++, i++)
		rec_argv[i] = argv[j];

	BUG_ON(i != rec_argc);

	return cmd_record(i, rec_argv, NULL);
}

int cmd_c2c(int argc, const char **argv, const char *prefix __maybe_unused)
{
	struct perf_c2c c2c = {
		.tool = {
			.sample		 = perf_c2c__process_sample,
			.comm		 = perf_event__process_comm,
			.exit		 = perf_event__process_exit,
			.fork		 = perf_event__process_fork,
			.lost		 = perf_event__process_lost,
			.ordered_samples = true,
		},
	};
	const struct option c2c_options[] = {
	OPT_END()
	};
	const char * const c2c_usage[] = {
		"perf c2c {record|report}",
		NULL
	};

	argc = parse_options(argc, argv, c2c_options, c2c_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc)
		usage_with_options(c2c_usage, c2c_options);

	if (!strncmp(argv[0], "rec", 3)) {
		return perf_c2c__record(argc, argv);
	} else if (!strncmp(argv[0], "rep", 3)) {
		return perf_c2c__report(&c2c);
	} else {
		usage_with_options(c2c_usage, c2c_options);
	}

	return 0;
}
