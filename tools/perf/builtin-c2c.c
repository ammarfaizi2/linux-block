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
	bool		 raw_records;
};

enum { OP, LVL, SNP, LCK, TLB };

static int perf_c2c__scnprintf_data_src(char *bf, size_t size, uint64_t val)
{
#define PREFIX       "["
#define SUFFIX       "]"
#define ELLIPSIS     "..."
	static const struct {
		uint64_t   bit;
		int64_t    field;
		const char *name;
	} decode_bits[] = {
	{ PERF_MEM_OP_LOAD,       OP,  "LOAD"     },
	{ PERF_MEM_OP_STORE,      OP,  "STORE"    },
	{ PERF_MEM_OP_NA,         OP,  "OP_NA"    },
	{ PERF_MEM_LVL_LFB,       LVL, "LFB"      },
	{ PERF_MEM_LVL_L1,        LVL, "L1"       },
	{ PERF_MEM_LVL_L2,        LVL, "L2"       },
	{ PERF_MEM_LVL_L3,        LVL, "LCL_LLC"  },
	{ PERF_MEM_LVL_LOC_RAM,   LVL, "LCL_RAM"  },
	{ PERF_MEM_LVL_REM_RAM1,  LVL, "RMT_RAM"  },
	{ PERF_MEM_LVL_REM_RAM2,  LVL, "RMT_RAM"  },
	{ PERF_MEM_LVL_REM_CCE1,  LVL, "RMT_LLC"  },
	{ PERF_MEM_LVL_REM_CCE2,  LVL, "RMT_LLC"  },
	{ PERF_MEM_LVL_IO,        LVL, "I/O"	  },
	{ PERF_MEM_LVL_UNC,       LVL, "UNCACHED" },
	{ PERF_MEM_LVL_NA,        LVL, "N"        },
	{ PERF_MEM_LVL_HIT,       LVL, "HIT"      },
	{ PERF_MEM_LVL_MISS,      LVL, "MISS"     },
	{ PERF_MEM_SNOOP_NONE,    SNP, "SNP NONE" },
	{ PERF_MEM_SNOOP_HIT,     SNP, "SNP HIT"  },
	{ PERF_MEM_SNOOP_MISS,    SNP, "SNP MISS" },
	{ PERF_MEM_SNOOP_HITM,    SNP, "SNP HITM" },
	{ PERF_MEM_SNOOP_NA,      SNP, "SNP NA"   },
	{ PERF_MEM_LOCK_LOCKED,   LCK, "LOCKED"   },
	{ PERF_MEM_LOCK_NA,       LCK, "LOCK_NA"  },
	};
	union perf_mem_data_src dsrc = { .val = val, };
	int printed = scnprintf(bf, size, PREFIX);
	size_t i;
	bool first_present = true;

	for (i = 0; i < ARRAY_SIZE(decode_bits); i++) {
		int bitval;

		switch (decode_bits[i].field) {
		case OP:  bitval = decode_bits[i].bit & dsrc.mem_op;    break;
		case LVL: bitval = decode_bits[i].bit & dsrc.mem_lvl;   break;
		case SNP: bitval = decode_bits[i].bit & dsrc.mem_snoop; break;
		case LCK: bitval = decode_bits[i].bit & dsrc.mem_lock;  break;
		case TLB: bitval = decode_bits[i].bit & dsrc.mem_dtlb;  break;
		default: bitval = 0;					break;
		}

		if (!bitval)
			continue;

		if (strlen(decode_bits[i].name) + !!i > size - printed - sizeof(SUFFIX)) {
			sprintf(bf + size - sizeof(SUFFIX) - sizeof(ELLIPSIS) + 1, ELLIPSIS);
			printed = size - sizeof(SUFFIX);
			break;
		}

		printed += scnprintf(bf + printed, size - printed, "%s%s",
				     first_present ? "" : ",", decode_bits[i].name);
		first_present = false;
	}

	printed += scnprintf(bf + printed, size - printed, SUFFIX);
	return printed;
}

static int perf_c2c__fprintf_header(FILE *fp)
{
	int printed = fprintf(fp, "%c %-16s  %6s  %6s  %4s  %18s  %18s  %18s  %6s  %-10s %-60s %s\n", 
			      'T', 
			      "Status",                                            
			      "Pid", 
			      "Tid", 
			      "CPU",                  
			      "Inst Adrs",               
			      "Virt Data Adrs",      
			      "Phys Data Adrs",
			      "Cycles",               
			      "Source", 
			      "  Decoded Source",
			      "ObJect:Symbol");
	return printed + fprintf(fp, "%-*.*s\n", printed, printed, graph_dotted_line);
}

static int perf_sample__fprintf(struct perf_sample *sample, char tag,
				const char *reason, struct addr_location *al, FILE *fp)
{
	char data_src[61];

	perf_c2c__scnprintf_data_src(data_src, sizeof(data_src), sample->data_src);

	return fprintf(fp, "%c %-16s  %6d  %6d  %4d  %#18" PRIx64 "  %#18" PRIx64 "  %#18" PRIx64 "  %6" PRIu64 "  %#10" PRIx64 " %-60.60s %s:%s\n", 
		       tag, 
		       reason ?: "valid record",
		       sample->pid, 
		       sample->tid, 
		       sample->cpu, 
		       sample->ip, 
		       sample->addr,
		       0UL,
		       sample->weight, 
		       sample->data_src, 
		       data_src, 
		       al->map ? (al->map->dso ? al->map->dso->long_name : "???") : "???",
		       al->sym ? al->sym->name : "???");
}

static int perf_c2c__process_load_store(struct perf_c2c *c2c,
					struct perf_sample *sample,
					struct addr_location *al)
{
	if (c2c->raw_records)
		perf_sample__fprintf(sample, ' ', "raw input", al, stdout);

	return 0;
}

static const struct perf_evsel_str_handler handlers[] = {
	{ "cpu/mem-loads,ldlat=30/pp", perf_c2c__process_load_store, },
	{ "cpu/mem-stores/pp",	       perf_c2c__process_load_store, },
};

typedef int (*sample_handler)(struct perf_c2c *c2c,
			      struct perf_sample *sample,
			      struct addr_location *al);

static int perf_c2c__process_sample(struct perf_tool *tool,
				    union perf_event *event,
				    struct perf_sample *sample,
				    struct perf_evsel *evsel,
				    struct machine *machine)
{
	struct perf_c2c *c2c = container_of(tool, struct perf_c2c, tool);
	struct addr_location al;
	int err = 0;

	if (perf_event__preprocess_sample(event, machine, &al, sample) < 0) {
		pr_err("problem processing %d event, skipping it.\n",
		       event->header.type);
		return -1;
	}

	if (evsel->handler.func != NULL) {
		sample_handler f = evsel->handler.func;
		err = f(c2c, sample, &al);
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

	if (c2c->raw_records)
		perf_c2c__fprintf_header(stdout);

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
	OPT_BOOLEAN('r', "raw_records", &c2c.raw_records, "dump raw events"),
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
