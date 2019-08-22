// SPDX-License-Identifier: GPL-2.0
#include <asm/bug.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/types.h>
#include <linux/perf_event.h>
#include <linux/string.h>
#include <internal/lib.h>
#include <cpumap.h>

#include "pmu.h"
#include "perf-sys.h"
#include "debug.h"
#include "tests/tests.h"
#include "cloexec.h"
#include "arch-tests.h"

/*
 * ARMv8 ARM reserves the following encoding for system registers:
 * (Ref: ARMv8 ARM, Section: "System instruction class encoding overview",
 *  C5.2, version:ARM DDI 0487A.f)
 *      [20-19] : Op0
 *      [18-16] : Op1
 *      [15-12] : CRn
 *      [11-8]  : CRm
 *      [7-5]   : Op2
 */
#define Op0_shift       19
#define Op0_mask        0x3
#define Op1_shift       16
#define Op1_mask        0x7
#define CRn_shift       12
#define CRn_mask        0xf
#define CRm_shift       8
#define CRm_mask        0xf
#define Op2_shift       5
#define Op2_mask        0x7

#define __stringify(x)	#x

#define read_sysreg(r) ({						\
	u64 __val;							\
	asm volatile("mrs %0, " __stringify(r) : "=r" (__val));		\
	__val;								\
})

#define PMEVCNTR_READ_CASE(idx)					\
	case idx:						\
		return read_sysreg(pmevcntr##idx##_el0)

#define PMEVCNTR_CASES(readwrite)		\
	PMEVCNTR_READ_CASE(0);			\
	PMEVCNTR_READ_CASE(1);			\
	PMEVCNTR_READ_CASE(2);			\
	PMEVCNTR_READ_CASE(3);			\
	PMEVCNTR_READ_CASE(4);			\
	PMEVCNTR_READ_CASE(5);			\
	PMEVCNTR_READ_CASE(6);			\
	PMEVCNTR_READ_CASE(7);			\
	PMEVCNTR_READ_CASE(8);			\
	PMEVCNTR_READ_CASE(9);			\
	PMEVCNTR_READ_CASE(10);			\
	PMEVCNTR_READ_CASE(11);			\
	PMEVCNTR_READ_CASE(12);			\
	PMEVCNTR_READ_CASE(13);			\
	PMEVCNTR_READ_CASE(14);			\
	PMEVCNTR_READ_CASE(15);			\
	PMEVCNTR_READ_CASE(16);			\
	PMEVCNTR_READ_CASE(17);			\
	PMEVCNTR_READ_CASE(18);			\
	PMEVCNTR_READ_CASE(19);			\
	PMEVCNTR_READ_CASE(20);			\
	PMEVCNTR_READ_CASE(21);			\
	PMEVCNTR_READ_CASE(22);			\
	PMEVCNTR_READ_CASE(23);			\
	PMEVCNTR_READ_CASE(24);			\
	PMEVCNTR_READ_CASE(25);			\
	PMEVCNTR_READ_CASE(26);			\
	PMEVCNTR_READ_CASE(27);			\
	PMEVCNTR_READ_CASE(28);			\
	PMEVCNTR_READ_CASE(29);			\
	PMEVCNTR_READ_CASE(30)

/*
 * Read a value direct from PMEVCNTR<idx>
 */
static u64 read_evcnt_direct(int idx)
{
	switch (idx) {
	PMEVCNTR_CASES(READ);
	case 31:
		return read_sysreg(pmccntr_el0);
	default:
		WARN_ON(1);
	}

	return 0;
}

static int mmap_read_check_user_access(void *addr, bool cnt64)
{
	struct perf_event_mmap_page *pc = addr;

	if (!pc->cap_user_rdpmc) {
		pr_err("Userspace access not enabled.\n");
		return -1;
	}

	if (!pc->index) {
		pr_err("No event index.\n");
		return -1;
	}

	if (!cnt64 && pc->pmc_width != 32) {
		pr_err("Unexpected counter width - %d, expected 32.\n", pc->pmc_width);
		return -1;
	}
	if (cnt64 && pc->pmc_width != 64) {
		pr_err("Unexpected counter width - %d, expected 64.\n", pc->pmc_width);
		return -1;
	}

	return 0;
}

static u64 mmap_read_self(void *addr)
{
	struct perf_event_mmap_page *pc = addr;
	u32 seq, idx, time_mult = 0, time_shift = 0;
	u64 count, cyc = 0, time_offset = 0, enabled, running, delta;

	do {
		seq = READ_ONCE(pc->lock);
		barrier();

		enabled = READ_ONCE(pc->time_enabled);
		running = READ_ONCE(pc->time_running);

		if (enabled != running) {
			cyc = read_sysreg(cntvct_el0);
			time_mult = READ_ONCE(pc->time_mult);
			time_shift = READ_ONCE(pc->time_shift);
			time_offset = READ_ONCE(pc->time_offset);
		}

		idx = READ_ONCE(pc->index);
		count = READ_ONCE(pc->offset);
		if (idx) {
			u64 evcnt = read_evcnt_direct(idx - 1);
			u16 width = READ_ONCE(pc->pmc_width);

			evcnt <<= 64 - width;
			evcnt >>= 64 - width;
			count += evcnt;
		}
		barrier();
	} while (READ_ONCE(pc->lock) != seq);

	if (enabled != running) {
		u64 quot, rem;

		quot = (cyc >> time_shift);
		rem = cyc & (((u64)1 << time_shift) - 1);
		delta = time_offset + quot * time_mult +
			((rem * time_mult) >> time_shift);

		enabled += delta;
		if (idx)
			running += delta;

		quot = count / running;
		rem = count % running;
		count = quot * enabled + (rem * enabled) / running;
	}

	return count;
}

static int run_test(void *addr)
{
	int n;
	volatile int tmp = 0;
	u64 delta, i, loops = 1000;

	for (n = 0; n < 6; n++) {
		u64 stamp, now;

		stamp = mmap_read_self(addr);

		for (i = 0; i < loops; i++)
			tmp++;

		now = mmap_read_self(addr);
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

static int __test__rd_pinned(void)
{
	int cpu, cputmp, ret = -1;
	int fd;
	void *addr;
	struct perf_event_attr attr = {
		.config = 0x8, /* Instruction count */
		.config1 = 0, /* 32-bit counter */
		.exclude_kernel = 1,
	};
	char sbuf[STRERR_BUFSIZE];
	cpu_set_t cpu_set;
	struct perf_pmu *pmu;

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

	fd = sys_perf_event_open(&attr, 0, -1, -1,
				 perf_event_open_cloexec_flag());
	if (fd < 0) {
		pr_err("Error: sys_perf_event_open() syscall returned with %d (%s)\n", fd,
		       str_error_r(errno, sbuf, sizeof(sbuf)));
		return -1;
	}

	addr = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == (void *)(-1)) {
		pr_err("Error: mmap() syscall returned with (%s)\n",
		       str_error_r(errno, sbuf, sizeof(sbuf)));
		goto out_close;
	}

	if (mmap_read_check_user_access(addr, false))
		goto out_close;

	perf_cpu_map__for_each_cpu(cpu, cputmp, pmu->cpus) {
		CPU_ZERO(&cpu_set);
		CPU_SET(cpu, &cpu_set);
		if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) < 0)
			pr_err("Could not set affinity\n");

		pr_debug("Running on CPU %d\n", cpu);

		ret = run_test(addr);
		if (ret)
			break;
	}

	munmap(addr, page_size);
	pr_debug("   ");

out_close:
	close(fd);
	return ret;
}

static int __test__rd_pmevcntr(u64 config, bool cnt64)
{
	int ret = -1;
	int fd;
	void *addr;
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = config,
		.config1 = cnt64,
		.exclude_kernel = 1,
	};
	char sbuf[STRERR_BUFSIZE];

	fd = sys_perf_event_open(&attr, 0, -1, -1,
				 perf_event_open_cloexec_flag());
	if (fd < 0) {
		pr_err("Error: sys_perf_event_open() syscall returned with %d (%s)\n", fd,
		       str_error_r(errno, sbuf, sizeof(sbuf)));
		return -1;
	}

	addr = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == (void *)(-1)) {
		pr_err("Error: mmap() syscall returned with (%s)\n",
		       str_error_r(errno, sbuf, sizeof(sbuf)));
		goto out_close;
	}

	if (mmap_read_check_user_access(addr, cnt64))
		goto out_close;

	ret = run_test(addr);

	munmap(addr, page_size);
	pr_debug("   ");

out_close:
	close(fd);
	return ret;
}

int test__rd_pinned(struct test __maybe_unused *test,
		       int __maybe_unused subtest)
{
	int status = 0;
	int wret = 0;
	int ret = 0;
	int pid;

	pid = fork();
	if (pid < 0)
		return -1;

	if (!pid) {
		ret = __test__rd_pinned();
		exit(ret);
	}

	wret = waitpid(pid, &status, 0);
	if (wret < 0)
		return -1;

	if (WIFSIGNALED(status)) {
		pr_err("Error: the child process was interrupted by a signal\n");
		return -1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status)) {
		pr_err("Error: the child process exited with: %d\n",
		       WEXITSTATUS(status));
		return -1;
	}

	return 0;
}

int test__rd_pmevcntr(struct test __maybe_unused *test,
		     int __maybe_unused subtest)
{
	int status = 0;
	int wret = 0;
	int ret = 0;
	int pid;

	if (!pmu_is_homogeneous())
		return TEST_SKIP;

	pid = fork();
	if (pid < 0)
		return -1;

	if (!pid) {
		ret = __test__rd_pmevcntr(PERF_COUNT_HW_INSTRUCTIONS, 0);
		exit(ret);
	}

	wret = waitpid(pid, &status, 0);
	if (wret < 0)
		return -1;

	if (WIFSIGNALED(status)) {
		pr_err("Error: the child process was interrupted by a signal\n");
		return -1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status)) {
		pr_err("Error: the child process exited with: %d\n",
		       WEXITSTATUS(status));
		return -1;
	}

	return 0;
}

int test__rd_pmccntr(struct test __maybe_unused *test,
		     int __maybe_unused subtest)
{
	int status = 0;
	int wret = 0;
	int ret = 0;
	int pid;

	if (!pmu_is_homogeneous())
		return TEST_SKIP;

	pid = fork();
	if (pid < 0)
		return -1;

	if (!pid) {
		ret = __test__rd_pmevcntr(PERF_COUNT_HW_CPU_CYCLES, 1);
		exit(ret);
	}

	wret = waitpid(pid, &status, 0);
	if (wret < 0)
		return -1;

	if (WIFSIGNALED(status)) {
		pr_err("Error: the child process was interrupted by a signal\n");
		return -1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status)) {
		pr_err("Error: the child process exited with: %d\n",
		       WEXITSTATUS(status));
		return -1;
	}

	return 0;
}
