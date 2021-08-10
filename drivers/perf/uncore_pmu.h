/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __UNCORE_PMU_H__
#define __UNCORE_PMU_H__

#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/types.h>

#define to_uncore_pmu(p)	(container_of(p, struct uncore_pmu, pmu))

struct device;

struct uncore_pmu {
	struct pmu pmu;
	struct device *dev;
	/* associated_cpus: All CPUs associated with the PMU */
	cpumask_t associated_cpus;
	/* CPU used for counting */
	int on_cpu;
	struct hlist_node node;
	unsigned int irq;
	int num_counters;
};

int uncore_pmu_event_init(struct perf_event *event);

int uncore_pmu_register(struct uncore_pmu *uncore_pmu, const char *name);
int uncore_pmu_unregister(struct uncore_pmu *uncore_pmu);

#endif /* __UNCORE_PMU_H__ */
