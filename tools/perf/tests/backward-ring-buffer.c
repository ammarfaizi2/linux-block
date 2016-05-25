/*
 * Test backward bit in event attribute, read ring buffer from end to
 * beginning
 */

#include <perf.h>
#include <evlist.h>
#include <sys/prctl.h>
#include "tests.h"
#include "debug.h"

#define NR_ITERS 111

static void testcase(void)
{
	int i;

	for (i = 0; i < NR_ITERS; i++) {
		char proc_name[10];

		snprintf(proc_name, sizeof(proc_name), "p:%d\n", i);
		prctl(PR_SET_NAME, proc_name);
	}
}

static int count_samples(struct perf_evlist *evlist, int *sample_count,
			 int *comm_count)
{
	int i;

	for (i = 0; i < evlist->nr_mmaps; i++) {
		union perf_event *event;

		if (evlist->backward)
			perf_evlist__mmap_read_catchup(evlist, i);
		while ((event = perf_evlist__mmap_read(evlist, i)) != NULL) {
			const u32 type = event->header.type;

			switch (type) {
			case PERF_RECORD_SAMPLE:
				if (sample_count)
					(*sample_count)++;
				break;
			case PERF_RECORD_COMM:
				if (comm_count)
					(*comm_count)++;
				break;
			default:
				pr_err("Unexpected record of type %d\n", type);
				return TEST_FAIL;
			}
		}
	}
	return TEST_OK;
}

static int do_test(struct perf_evlist *evlist,
		   struct perf_evlist *aux_evlist,
		   int mmap_pages,
		   int *enter_sample_count,
		   int *exit_sample_count,
		   int *comm_count)
{
	int err;
	char sbuf[STRERR_BUFSIZE];

	err = perf_evlist__mmap(evlist, mmap_pages, false);
	if (err < 0) {
		pr_debug("perf_evlist__mmap: %s\n",
			 strerror_r(errno, sbuf, sizeof(sbuf)));
		return TEST_FAIL;
	}

	err = perf_evlist__mmap(aux_evlist, mmap_pages, true);
	if (err < 0) {
		pr_debug("perf_evlist__mmap for aux_evlist: %s\n",
			 strerror_r(errno, sbuf, sizeof(sbuf)));
		return TEST_FAIL;
	}

	perf_evlist__enable(evlist);
	testcase();
	perf_evlist__disable(evlist);

	err = count_samples(aux_evlist, exit_sample_count, comm_count);
	if (err)
		goto errout;
	err = count_samples(evlist, enter_sample_count, NULL);
	if (err)
		goto errout;
errout:
	perf_evlist__munmap(evlist);
	perf_evlist__munmap(aux_evlist);
	return err;
}


int test__backward_ring_buffer(int subtest __maybe_unused)
{
	int ret = TEST_SKIP, err;
	int enter_sample_count = 0, exit_sample_count = 0, comm_count = 0;
	char pid[16], sbuf[STRERR_BUFSIZE];
	struct perf_evlist *evlist, *aux_evlist = NULL;
	struct perf_evsel *evsel __maybe_unused;
	struct parse_events_error parse_error;
	struct record_opts opts = {
		.target = {
			.uid = UINT_MAX,
			.uses_mmap = true,
		},
		.freq	      = 0,
		.mmap_pages   = 256,
		.default_interval = 1,
	};

	snprintf(pid, sizeof(pid), "%d", getpid());
	pid[sizeof(pid) - 1] = '\0';
	opts.target.tid = opts.target.pid = pid;

	evlist = perf_evlist__new();
	if (!evlist) {
		pr_debug("No ehough memory to create evlist\n");
		return TEST_FAIL;
	}

	err = perf_evlist__create_maps(evlist, &opts.target);
	if (err < 0) {
		pr_debug("Not enough memory to create thread/cpu maps\n");
		goto out_delete_evlist;
	}

	bzero(&parse_error, sizeof(parse_error));
	err = parse_events(evlist, "syscalls:sys_enter_prctl", &parse_error);
	if (err) {
		pr_debug("Failed to parse tracepoint event, try use root\n");
		ret = TEST_SKIP;
		goto out_delete_evlist;
	}

	/*
	 * Set backward bit, ring buffer should be writing from end. Record
	 * it in aux evlist
	 */
	perf_evlist__last(evlist)->overwrite = true;
	perf_evlist__last(evlist)->attr.write_backward = 1;

	err = parse_events(evlist, "syscalls:sys_exit_prctl", &parse_error);
	if (err) {
		pr_debug("Failed to parse tracepoint event, try use root\n");
		ret = TEST_SKIP;
		goto out_delete_evlist;
	}
	/* Don't set backward bit for exit event. Record it in main evlist */

	perf_evlist__config(evlist, &opts, NULL);

	err = perf_evlist__open(evlist);
	if (err < 0) {
		pr_debug("perf_evlist__open: %s\n",
			 strerror_r(errno, sbuf, sizeof(sbuf)));
		goto out_delete_evlist;
	}

	aux_evlist = perf_evlist__new_aux(evlist);
	if (!aux_evlist) {
		pr_debug("perf_evlist__new_aux failed\n");
		goto out_delete_evlist;
	}
	aux_evlist->backward = true;

	ret = TEST_FAIL;
	err = do_test(evlist, aux_evlist, opts.mmap_pages,
		      &enter_sample_count, &exit_sample_count,
		      &comm_count);
	if (err != TEST_OK)
		goto out_delete_evlist;

	if (enter_sample_count != exit_sample_count) {
		pr_err("Unexpected counter: enter_sample_count=%d, exit_sample_count=%d\n",
		       enter_sample_count, exit_sample_count);
		goto out_delete_evlist;
	}

	if ((exit_sample_count != NR_ITERS) || (comm_count != NR_ITERS)) {
		pr_err("Unexpected counter: exit_sample_count=%d, comm_count=%d\n",
		       exit_sample_count, comm_count);
		goto out_delete_evlist;
	}

	err = do_test(evlist, aux_evlist, 1, NULL, NULL, NULL);
	if (err != TEST_OK)
		goto out_delete_evlist;

	ret = TEST_OK;
out_delete_evlist:
	if (aux_evlist)
		perf_evlist__delete(aux_evlist);
	perf_evlist__delete(evlist);
	return ret;
}
