// SPDX-License-Identifier: GPL-2.0
#include <unistd.h>
#include <sched.h>
#include <cpumap.h>

#include <perf/core.h>
#include <perf/threadmap.h>
#include <perf/evsel.h>

#include "pmu.h"
#include "debug.h"
#include "tests/tests.h"
#include "arch-tests.h"

static int run_test(struct perf_evsel *evsel)
{
	int n;
	volatile int tmp = 0;
	u64 delta, i, loops = 1000;
	struct perf_counts_values counts = { .val = 0 };

	for (n = 0; n < 6; n++) {
		u64 stamp, now;

		perf_evsel__read(evsel, 0, 0, &counts);
		stamp = counts.val;

		for (i = 0; i < loops; i++)
			tmp++;

		perf_evsel__read(evsel, 0, 0, &counts);
		now = counts.val;
		loops *= 10;

		delta = now - stamp;
		pr_debug("%14d: %14llu\n", n, (long long)delta);

		if (!delta)
			break;
	}
	return delta ? 0 : -1;
}

static struct perf_pmu *pmu_for_cpu(int cpu)
{
	int acpu, idx;
	struct perf_pmu *pmu = NULL;

	while ((pmu = perf_pmu__scan(pmu)) != NULL) {
		if (pmu->is_uncore)
			continue;
		perf_cpu_map__for_each_cpu(acpu, idx, pmu->cpus)
			if (acpu == cpu)
				return pmu;
	}
	return NULL;
}

static bool pmu_is_homogeneous(void)
{
	int core_cnt = 0;
	struct perf_pmu *pmu = NULL;

	while ((pmu = perf_pmu__scan(pmu)) != NULL) {
		if (!pmu->is_uncore && !perf_cpu_map__empty(pmu->cpus))
			core_cnt++;
	}
	return core_cnt == 1;
}

static int libperf_print(enum libperf_print_level level,
			 const char *fmt, va_list ap)
{
	(void)level;
	return vfprintf(stderr, fmt, ap);
}

static struct perf_evsel *perf_init(struct perf_event_attr *attr)
{
	int err;
	struct perf_thread_map *threads;
	struct perf_evsel *evsel;
	struct perf_event_mmap_page *pc;

	libperf_init(libperf_print);

	threads = perf_thread_map__new_dummy();
	if (!threads) {
		pr_err("failed to create threads\n");
		return NULL;
	}

	perf_thread_map__set_pid(threads, 0, 0);

	evsel = perf_evsel__new(attr);
	if (!evsel) {
		pr_err("failed to create evsel\n");
		goto out_thread;
	}

	err = perf_evsel__open(evsel, NULL, threads);
	if (err) {
		pr_err("failed to open evsel\n");
		goto out_open;
	}

	if (perf_evsel__mmap(evsel, 0)) {
		pr_err("failed to mmap evsel\n");
		goto out_mmap;
	}

	pc = perf_evsel__mmap_base(evsel, 0, 0);
	if (!pc->cap_user_rdpmc) {
		pr_err("userspace access not enabled\n");
		goto out_mmap;
	}

	return evsel;

out_mmap:
	perf_evsel__close(evsel);
out_open:
	perf_evsel__delete(evsel);
out_thread:
	perf_thread_map__put(threads);
	return NULL;
}

int test__rd_pinned(struct test __maybe_unused *test,
		    int __maybe_unused subtest)
{
	int cpu, cputmp, ret = -1;
	struct perf_evsel *evsel;
	struct perf_event_attr attr = {
		.config = 0x8, /* Instruction count */
		.config1 = 0, /* 32-bit counter */
		.exclude_kernel = 1,
	};
	cpu_set_t cpu_set;
	struct perf_pmu *pmu;

	if (pmu_is_homogeneous())
		return TEST_SKIP;

	cpu = sched_getcpu();
	pmu = pmu_for_cpu(cpu);
	if (!pmu)
		return -1;
	attr.type = pmu->type;

	CPU_ZERO(&cpu_set);
	perf_cpu_map__for_each_cpu(cpu, cputmp, pmu->cpus)
		CPU_SET(cpu, &cpu_set);
	if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) < 0)
		pr_err("Could not set affinity\n");

	evsel = perf_init(&attr);
	if (!evsel)
		return -1;

	perf_cpu_map__for_each_cpu(cpu, cputmp, pmu->cpus) {
		CPU_ZERO(&cpu_set);
		CPU_SET(cpu, &cpu_set);
		if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) < 0)
			pr_err("Could not set affinity\n");

		pr_debug("Running on CPU %d\n", cpu);

		ret = run_test(evsel);
		if (ret)
			break;
	}

	perf_evsel__close(evsel);
	perf_evsel__delete(evsel);
	return ret;
}

static int test__rd_counter_size(struct test __maybe_unused *test,
				 int config1)
{
	int ret;
	struct perf_evsel *evsel;
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_INSTRUCTIONS,
		.config1 = config1,
		.exclude_kernel = 1,
	};

	if (!pmu_is_homogeneous())
		return TEST_SKIP;

	evsel = perf_init(&attr);
	if (!evsel)
		return -1;

	ret = run_test(evsel);

	perf_evsel__close(evsel);
	perf_evsel__delete(evsel);
	return ret;
}

int test__rd_64bit(struct test __maybe_unused *test,
		   int __maybe_unused subtest)
{
	return test__rd_counter_size(test, 0x3);
}

int test__rd_32bit(struct test __maybe_unused *test,
		   int __maybe_unused subtest)
{
	return test__rd_counter_size(test, 0x2);
}
