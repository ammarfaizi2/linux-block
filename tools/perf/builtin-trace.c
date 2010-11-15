#include "builtin.h"
#include "perf.h"

#include "util/util.h"
#include "util/cache.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"
#include "util/color.h"
#include "util/strlist.h"

#include "util/parse-options.h"
#include "util/trace-event.h"

#include "util/debug.h"
#include "util/debugfs.h"
#include "util/session.h"

#include <sys/types.h>
#include <sys/prctl.h>
#include <semaphore.h>
#include <pthread.h>
#include <math.h>
#include <limits.h>
#include <libaudit.h>

#include <linux/list.h>
#include <linux/hash.h>

static struct perf_session *session;
static char const *input_name = "perf.data";
static bool pagefaults = false;
static bool followchilds = true;

struct syscall_desc {
	const char	*name;
	char		*entry_arg[6];
	char		*entry_fmt[6];
	char		*exit_fmt;
	unsigned int	argc;
	char		*subsystem;
};

#define MAX_SYSCALLS		1024

static struct syscall_desc syscall_desc[MAX_SYSCALLS];

#define MAX_FDS			1024

struct thread_data {
	u64			entry_time;
	char			*entry_str;
	bool			entry_pending;
	unsigned int		last_syscall;

	int			open_syscall;
	char			*open_filename;
	char			*fd_name[MAX_FDS];
};

#define MAX_PID			65536

static struct thread_data thread_data[MAX_PID];

static bool			print_syscalls_flag;

static void print_syscalls(void)
{
	struct syscall_desc *sdesc;
	unsigned int i, j;

	if (!print_syscalls_flag)
		return;

	for (i = 0; i < MAX_SYSCALLS; i++) {
		sdesc = syscall_desc + i;

		printf("%20s (%d): ", sdesc->name, sdesc->argc);

		for (j = 0; j < sdesc->argc; j++) {
			printf("%s ", sdesc->entry_fmt[j]);
		}
		printf("\n");
	}
}

static void parse_syscalls(void)
{
	const char *dbgfs_path = debugfs_find_mountpoint();
	int i, fd, fmtcnt, machine = audit_detect_machine();
	char fmt_path[MAXPATHLEN];
	char last, *p, *b, *buf = malloc(65536);
	struct syscall_desc *sdesc;
	size_t len;

	for (i = 0; i < MAX_SYSCALLS; i++) {
		sdesc = syscall_desc + i;

		sdesc->name = audit_syscall_to_name(i, machine);
		if (!sdesc->name)
			break;
		if (!strcmp(sdesc->name, "arch_prctl"))
			sdesc->name = "prctl";

		if (!dbgfs_path || !buf)
			continue;

		snprintf(fmt_path, MAXPATHLEN,
			 "%s/tracing/events/syscalls/sys_enter_%s/format",
			 dbgfs_path, sdesc->name);

		fd = open(fmt_path, O_RDONLY);
		if (fd < 0)
			continue;
		len = read(fd, buf, 65536);
		close(fd);
		buf[len] = 0;

		for (p = buf; p < buf + len; p++) {
			if (strncmp(p, "print fmt:", 10))
			    continue;
			for (; *p != '\"'; p++);
			fmtcnt = 0;
			p++;
			while (p < buf + len) {
				for (b = p; *p != ':' && *p != '\"'; p++);
				last = *p;
				*p++ = 0;
				sdesc->entry_arg[fmtcnt] = strdup(b);

				if (last == '\"')
					break;

				for (b = p; *p != ',' && *p !='\"'; p++);
				last = *p;
				*p++ = 0;
				sdesc->entry_fmt[fmtcnt++] = strdup(b);
				if (last == '\"')
					break;
			}
			sdesc->argc = fmtcnt;
			break;
		}
	}
	if (buf)
		free(buf);
}

static void process_sys_enter(void *data,
			      struct event *event __used,
			      int cpu __used,
			      u64 timestamp __used,
			      struct thread *thread)
{
	unsigned int id = (unsigned int) raw_field_value(event, "id", data);
	unsigned int pid = thread->pid;
	unsigned long *args = raw_field_ptr(event, "args", data);
	struct thread_data *tdata = thread_data + pid;
	struct syscall_desc *sdesc = syscall_desc + id;
	char *tmp;
	unsigned int i;

	if (id >= MAX_SYSCALLS)
		return;

	if (!sdesc->name)
		return;

	tdata->last_syscall = id;

	if (!tdata->entry_str) {
		tdata->entry_str = malloc(1024);
		if (!tdata->entry_str)
			return;
	}
	tmp = tdata->entry_str;

	tdata->entry_time = timestamp;
	tmp += sprintf(tmp, "%s(", sdesc->name);

	tdata->open_syscall = 0;
	if (!strcmp(sdesc->name, "open")) {
		tdata->open_syscall = 1;
		printf("open_syscall\n");
	}

	if (!sdesc->entry_arg[0]) {
		for (i = 0; i < 6; i++) {
			if (i)
				tmp += sprintf(tmp, ", ");
			tmp += sprintf(tmp, "0x%lx", args[i]);
		}
	} else {
		for (i = 0; i < sdesc->argc; i++) {
			char *arg_name = sdesc->entry_arg[i];

			if (i)
				tmp += sprintf(tmp, ",");

			if (!strcmp(arg_name, "fd")) {
				int fd;

				fd = args[i];
				if (fd < MAX_FDS && tdata->fd_name[fd])
					tmp += sprintf(tmp, "%d:<%s>", fd, tdata->fd_name[fd]);
				else
					tmp += sprintf(tmp, "%d:<...>", fd);
			} else
				tmp += sprintf(tmp, "%s: 0x%lx", arg_name, args[i]);
		}
	}
	tmp += sprintf(tmp, ")");
	tdata->entry_pending = true;
}

static void process_sys_exit(void *data,
			     struct event *event __used,
			     int cpu __used,
			     u64 timestamp __used,
			     struct thread *thread __used)
{
	unsigned int id = (unsigned int) raw_field_value(event, "id", data);
	unsigned int pid = thread->pid;
	unsigned long res = (unsigned long) raw_field_value(event, "ret", data);
	struct thread_data *tdata = thread_data + pid;
	struct syscall_desc *sdesc = syscall_desc + id;
	int open_syscall;
	double duration;
	u64 t = 0;

	if (id >= MAX_SYSCALLS)
		return;
	if (!sdesc->name)
		return;

	open_syscall = 0;
	if (!strcmp(sdesc->name, "open")) {
		int fd = res;

		open_syscall = 1;
		if (fd < MAX_FDS) {
			tdata->fd_name[fd] = tdata->open_filename;
			tdata->open_filename = NULL;
		}
	}

	if (tdata->entry_time)
		t = timestamp - tdata->entry_time;

	duration = (double)t / 1000000.0;
	if (followchilds)
		printf("%s/%d ", thread->comm, pid);
	printf("(");
	if (duration >= 1.0)
		color_fprintf(stdout, PERF_COLOR_RED, "%.3f ms", duration);
	else if (duration >= 0.01)
		color_fprintf(stdout, PERF_COLOR_YELLOW, "%.3f ms", duration);
	else
		color_fprintf(stdout, PERF_COLOR_NORMAL, "%.3f ms", duration);
	printf("): ");

	if (tdata->entry_pending) {
		printf("%-70s", tdata->entry_str);
		tdata->entry_pending = false;
	} else {
		printf(" ... [");
		color_fprintf(stdout, PERF_COLOR_YELLOW, "continued");
		printf("]: %s()", sdesc->name);
	}
	printf(" => 0x%lx\n", res);
}

static void vfs_getname(void *data,
			struct event *event __used,
			int cpu __used,
			u64 timestamp __used,
			struct thread *thread __used)
{
	char *filename = raw_field_ptr(event, "filename", data);
	unsigned int pid = thread->pid;
	struct thread_data *tdata = thread_data + pid;
	unsigned int id = tdata->last_syscall;
	struct syscall_desc *sdesc = syscall_desc + id;

	if (id >= MAX_SYSCALLS || !sdesc->name)
		return;

	if (tdata->open_syscall)
		tdata->open_filename = strdup(filename);

	if (tdata->entry_pending) {
		strcat(thread_data[pid].entry_str, " (fpath: ");
		strcat(thread_data[pid].entry_str, filename);
		strcat(thread_data[pid].entry_str, ") ");
	} else {
		if (followchilds)
			printf("%s/%d", thread->comm, pid);
		printf(" => %s(%s)\n", sdesc->name, filename);
	}
}

static int my_event__preprocess_sample(union perf_event *self,
			     struct addr_location *al, struct perf_sample *data, unsigned long ip)
{
	struct thread *thread;

	perf_event__parse_sample(self, session->sample_type, session->sample_id_all, data);

	thread = perf_session__findnew(session, self->ip.pid);
	if (thread == NULL)
		return -1;

//	map_groups__fprintf(&thread->mg, 1, stdout);
	/*
	 * Have we already created the kernel maps for the host machine?
	 *
	 * This should have happened earlier, when we processed the kernel MMAP
	 * events, but for older perf.data files there was no such thing, so do
	 * it now.
	 */
	if (session->host_machine.vmlinux_maps[MAP__FUNCTION] == NULL)
		machine__create_kernel_maps(&session->host_machine);

	thread__find_addr_map(thread, session, PERF_RECORD_MISC_USER, MAP__FUNCTION,
			      self->ip.pid, ip, al);
	if (!al->map) {
		thread__find_addr_map(thread, session, PERF_RECORD_MISC_KERNEL, MAP__FUNCTION,
			      self->ip.pid, ip, al);
	}

	al->sym = NULL;
	al->cpu = data->cpu;
	al->cpumode = PERF_RECORD_MISC_USER;

	if (al->map) {
		al->addr = al->map->map_ip(al->map, ip);
		al->sym = map__find_symbol(al->map, al->addr, NULL);
	} else {
		const unsigned int unresolved_col_width = BITS_PER_LONG / 4;

		if (hists__col_len(&session->hists, HISTC_DSO) < unresolved_col_width &&
		    !symbol_conf.col_width_list_str && !symbol_conf.field_sep &&
		    !symbol_conf.dso_list)
			hists__set_col_len(&session->hists, HISTC_DSO,
					   unresolved_col_width);
	}

	return 0;
}

static void pagefault_enter(union perf_event *self,
			    void *data,
			    struct event *event __used,
			    int cpu __used,
			    u64 timestamp __used,
			    struct thread *thread)
{
	unsigned long address		= raw_field_value(event, "address", data);
	unsigned long error_code	= raw_field_value(event, "error_code", data);
	unsigned long ip		= raw_field_value(event, "ip", data);
	struct perf_sample sdata = { .period = 1, };
	struct addr_location al;
	unsigned int pid = thread->pid;
	char *sym;

	al.map = NULL;
	my_event__preprocess_sample(self, &al, &sdata, ip);

	if (!thread)
		die("thread not found\n");

	sym = NULL;
	if (al.map && al.sym)
		sym = al.sym->name;

	if (thread_data[pid].entry_pending) {
		thread_data[pid].entry_pending = false;
		if (followchilds)
			printf("%s/%d", thread->comm, pid);
		printf(" %s ... [", thread_data[pid].entry_str);
		color_fprintf(stdout, PERF_COLOR_YELLOW, "unfinished");
		printf("]\n");
	}
	if (followchilds)
		printf("%s/%d", thread->comm, pid);
	color_fprintf(stdout, PERF_COLOR_NORMAL, "     #PF: [");
	color_fprintf(stdout, PERF_COLOR_GREEN, "%30s", sym, address, error_code);
	color_fprintf(stdout, PERF_COLOR_NORMAL, "]: => %016lx (", address);
	if (error_code & 2)
		color_fprintf(stdout, PERF_COLOR_RED, "W");
	else
		color_fprintf(stdout, PERF_COLOR_GREEN, "R");
	if (error_code & 4)
		color_fprintf(stdout, PERF_COLOR_NORMAL, ".U");
	else
		color_fprintf(stdout, PERF_COLOR_NORMAL, ".K");
	color_fprintf(stdout, PERF_COLOR_NORMAL, ")");
}

static void pagefault_exit(void *data __used,
			   struct event *event __used,
			   int cpu __used,
			   u64 timestamp __used,
			   struct thread *thread __used)
{
	color_fprintf(stdout, PERF_COLOR_NORMAL, "\n");
}

static void
process_raw_event(union perf_event *self, void *data, int cpu, u64 timestamp, struct thread *thread)
{
	struct event *event;
	int type;

	type = trace_parse_common_type(data);
	event = trace_find_event(type);

	if (!strcmp(event->name, "sys_enter"))
		process_sys_enter(data, event, cpu, timestamp, thread);
	if (!strcmp(event->name, "sys_exit"))
		process_sys_exit(data, event, cpu, timestamp, thread);
	if (!strcmp(event->name, "mm_pagefault_start"))
		pagefault_enter(self, data, event, cpu, timestamp, thread);
	if (!strcmp(event->name, "mm_pagefault_end"))
		pagefault_exit(data, event, cpu, timestamp, thread);
	if (!strcmp(event->name, "vfs_getname"))
		vfs_getname(data, event, cpu, timestamp, thread);
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

	process_raw_event(self, data.raw_data, data.cpu, data.time, thread);

	return 0;
}

static struct perf_event_ops eops = {
	.sample			= process_sample_event,
	.comm			= perf_event__process_comm,
	.mmap			= perf_event__process_mmap,
	.exit			= perf_event__process_task,
	.fork			= perf_event__process_task,
	.ordered_samples	= true,
};

static int read_events(void)
{
	session = perf_session__new_nowarn(input_name, O_RDONLY, 0, false, &eops);
	if (!session) {
		fprintf(stderr, "\n No perf.data file yet - to create it run: 'perf trace record <command>'\n\n");
		exit(0);
	}

	return perf_session__process_events(session, &eops);
}

static void __cmd_report(void)
{
	setup_pager();
	if (symbol__init() < 0)
		die("symbol initialization failure");

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
	OPT_BOOLEAN('p', "pagefaults", &pagefaults, "record pagefaults"),
	OPT_BOOLEAN('f', "follow", &followchilds, "follow childs"),
	OPT_BOOLEAN('P', "print-syscalls", &print_syscalls_flag, "print syscall names and arguments"),
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
	"-e", "vfs:vfs_getname:r",
};

static const char *record_args_pf[] = {
	"-e", "kmem:mm_pagefault_start:r",
	"-e", "kmem:mm_pagefault_end:r"
};

static int __cmd_record(int argc, const char **argv)
{
	unsigned int rec_argc, i, j;
	const char **rec_argv;

	rec_argc = ARRAY_SIZE(record_args) + argc;
	if (pagefaults)
		rec_argc += ARRAY_SIZE(record_args_pf);
	if (!followchilds)
		rec_argc++;

	rec_argv = calloc(rec_argc + 1, sizeof(char *));

	for (i = 0; i < ARRAY_SIZE(record_args); i++)
		rec_argv[i] = strdup(record_args[i]);

	if (pagefaults) {
		for (j = 0; j < ARRAY_SIZE(record_args_pf); j++, i++)
			rec_argv[i] = strdup(record_args_pf[j]);
	}
	if (!followchilds)
		rec_argv[i++] = strdup("-i");

	for (j = 0; j < (unsigned int)argc; j++, i++)
		rec_argv[i] = argv[j];

	BUG_ON(i != rec_argc);

	return cmd_record(i, rec_argv, NULL);
}

int cmd_trace(int argc, const char **argv, const char *prefix __used)
{
	int ret;

	parse_syscalls();
	print_syscalls();

	argc = parse_options(argc, argv, trace_options, trace_usage, PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc) {
		if (!argc)
			usage_with_options(trace_usage, trace_options);

		ret = __cmd_record(argc, argv);
		if (!ret)
			__cmd_report();
		return ret;
	} else {
		__cmd_report();
	}
	return 0;
}
