// SPDX-License-Identifier: GPL-2.0-only
/*
 * HiSilicon SoC Hardware event counters support
 *
 * Copyright (C) 2017 HiSilicon Limited
 * Author: Anurup M <anurup.m@huawei.com>
 *         Shaokun Zhang <zhangshaokun@hisilicon.com>
 *
 * This code is based on the uncore PMUs like arm-cci and arm-ccn.
 */
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/interrupt.h>

#include <asm/cputype.h>
#include <asm/local64.h>

#include "hisi_uncore_pmu.h"

#define HISI_GET_EVENTID(ev) (ev->hw.config_base & 0xff)
#define HISI_MAX_PERIOD(nr) (GENMASK_ULL((nr) - 1, 0))

/*
 * PMU format attributes
 */
ssize_t hisi_format_sysfs_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dev_ext_attribute *eattr;

	eattr = container_of(attr, struct dev_ext_attribute, attr);

	return sysfs_emit(buf, "%s\n", (char *)eattr->var);
}
EXPORT_SYMBOL_GPL(hisi_format_sysfs_show);

/*
 * PMU event attributes
 */
ssize_t hisi_event_sysfs_show(struct device *dev,
			      struct device_attribute *attr, char *page)
{
	struct dev_ext_attribute *eattr;

	eattr = container_of(attr, struct dev_ext_attribute, attr);

	return sysfs_emit(page, "config=0x%lx\n", (unsigned long)eattr->var);
}
EXPORT_SYMBOL_GPL(hisi_event_sysfs_show);


int hisi_uncore_pmu_get_event_idx(struct perf_event *event)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(event->pmu);
	unsigned long *used_mask = hisi_pmu->pmu_events.used_mask;
	u32 num_counters = hisi_pmu->pmu.num_counters;
	int idx;

	idx = find_first_zero_bit(used_mask, num_counters);
	if (idx == num_counters)
		return -EAGAIN;

	set_bit(idx, used_mask);

	return idx;
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_get_event_idx);

ssize_t hisi_uncore_pmu_identifier_attr_show(struct device *dev,
					     struct device_attribute *attr,
					     char *page)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(dev_get_drvdata(dev));

	return sysfs_emit(page, "0x%08x\n", hisi_pmu->identifier);
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_identifier_attr_show);

static void hisi_uncore_pmu_clear_event_idx(struct hisi_pmu *hisi_pmu, int idx)
{
	clear_bit(idx, hisi_pmu->pmu_events.used_mask);
}

static irqreturn_t hisi_uncore_pmu_isr(int irq, void *data)
{
	struct hisi_pmu *hisi_pmu = data;
	struct perf_event *event;
	unsigned long overflown;
	int idx;

	overflown = hisi_pmu->ops->get_int_status(hisi_pmu);
	if (!overflown)
		return IRQ_NONE;

	/*
	 * Find the counter index which overflowed if the bit was set
	 * and handle it.
	 */
	for_each_set_bit(idx, &overflown, hisi_pmu->pmu.num_counters) {
		/* Write 1 to clear the IRQ status flag */
		hisi_pmu->ops->clear_int_status(hisi_pmu, idx);
		/* Get the corresponding event struct */
		event = hisi_pmu->pmu_events.hw_events[idx];
		if (!event)
			continue;

		hisi_uncore_pmu_event_update(event);
		hisi_uncore_pmu_set_event_period(event);
	}

	return IRQ_HANDLED;
}

/*
 * The Super CPU Cluster (SCCL) and CPU Cluster (CCL) IDs can be
 * determined from the MPIDR_EL1, but the encoding varies by CPU:
 *
 * - For MT variants of TSV110:
 *   SCCL is Aff2[7:3], CCL is Aff2[2:0]
 *
 * - For other MT parts:
 *   SCCL is Aff3[7:0], CCL is Aff2[7:0]
 *
 * - For non-MT parts:
 *   SCCL is Aff2[7:0], CCL is Aff1[7:0]
 */
static void hisi_read_sccl_and_ccl_id(int cpu, int *scclp, int *cclp)
{
	u64 mpidr = cpu_logical_map(cpu);
	int aff3 = MPIDR_AFFINITY_LEVEL(mpidr, 3);
	int aff2 = MPIDR_AFFINITY_LEVEL(mpidr, 2);
	int aff1 = MPIDR_AFFINITY_LEVEL(mpidr, 1);
	bool mt = mpidr & MPIDR_MT_BITMASK;
	int sccl, ccl;

	/* This assumes all CPUs are the same part number */
	if (mt && read_cpuid_part_number() == HISI_CPU_PART_TSV110) {
		sccl = aff2 >> 3;
		ccl = aff2 & 0x7;
	} else if (mt) {
		sccl = aff3;
		ccl = aff2;
	} else {
		sccl = aff2;
		ccl = aff1;
	}

	if (scclp)
		*scclp = sccl;
	if (cclp)
		*cclp = ccl;
}

/*
 * Check whether the CPU is associated with this uncore PMU
 */
static bool hisi_pmu_check_associated_cpu(int cpu, struct hisi_pmu *hisi_pmu)
{
	int sccl_id, ccl_id;

	if (hisi_pmu->ccl_id == -1) {
		/* If CCL_ID is -1, the PMU only shares the same SCCL */
		hisi_read_sccl_and_ccl_id(cpu, &sccl_id, NULL);

		return sccl_id == hisi_pmu->sccl_id;
	}

	hisi_read_sccl_and_ccl_id(cpu, &sccl_id, &ccl_id);

	return sccl_id == hisi_pmu->sccl_id && ccl_id == hisi_pmu->ccl_id;
}

/*
 * Check which CPUs are associated with this uncore PMU
 */
static void hisi_pmu_set_associated_cpus(struct hisi_pmu *hisi_pmu)
{
	int cpu;

	for_each_possible_cpu(cpu)
		if (hisi_pmu_check_associated_cpu(cpu, hisi_pmu))
			cpumask_set_cpu(cpu, &hisi_pmu->pmu.associated_cpus);
}

int hisi_uncore_pmu_init_irq(struct hisi_pmu *hisi_pmu,
			     struct platform_device *pdev)
{
	int irq, ret;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	ret = devm_request_irq(&pdev->dev, irq, hisi_uncore_pmu_isr,
			       IRQF_NOBALANCING | IRQF_NO_THREAD,
			       dev_name(&pdev->dev), hisi_pmu);
	if (ret < 0) {
		dev_err(&pdev->dev,
			"Fail to request IRQ: %d ret: %d.\n", irq, ret);
		return ret;
	}

	hisi_pmu->pmu.irq = irq;

	hisi_pmu_set_associated_cpus(hisi_pmu);
	return 0;
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_init_irq);

int hisi_uncore_pmu_event_init(struct perf_event *event)
{
	struct hisi_pmu *hisi_pmu;
	int ret;

	ret = uncore_pmu_event_init(event);
	if (ret)
		return ret;

	hisi_pmu = to_hisi_pmu(event->pmu);
	if (event->attr.config > hisi_pmu->check_event)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_event_init);

/*
 * Set the counter to count the event that we're interested in,
 * and enable interrupt and counter.
 */
static void hisi_uncore_pmu_enable_event(struct perf_event *event)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	hisi_pmu->ops->write_evtype(hisi_pmu, hwc->idx,
				    HISI_GET_EVENTID(event));

	if (hisi_pmu->ops->enable_filter)
		hisi_pmu->ops->enable_filter(event);

	hisi_pmu->ops->enable_counter_int(hisi_pmu, hwc);
	hisi_pmu->ops->enable_counter(hisi_pmu, hwc);
}

/*
 * Disable counter and interrupt.
 */
static void hisi_uncore_pmu_disable_event(struct perf_event *event)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	hisi_pmu->ops->disable_counter(hisi_pmu, hwc);
	hisi_pmu->ops->disable_counter_int(hisi_pmu, hwc);

	if (hisi_pmu->ops->disable_filter)
		hisi_pmu->ops->disable_filter(event);
}

void hisi_uncore_pmu_set_event_period(struct perf_event *event)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	/*
	 * The HiSilicon PMU counters support 32 bits or 48 bits, depending on
	 * the PMU. We reduce it to 2^(counter_bits - 1) to account for the
	 * extreme interrupt latency. So we could hopefully handle the overflow
	 * interrupt before another 2^(counter_bits - 1) events occur and the
	 * counter overtakes its previous value.
	 */
	u64 val = BIT_ULL(hisi_pmu->counter_bits - 1);

	local64_set(&hwc->prev_count, val);
	/* Write start value to the hardware event counter */
	hisi_pmu->ops->write_counter(hisi_pmu, hwc, val);
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_set_event_period);

void hisi_uncore_pmu_event_update(struct perf_event *event)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u64 delta, prev_raw_count, new_raw_count;

	do {
		/* Read the count from the counter register */
		new_raw_count = hisi_pmu->ops->read_counter(hisi_pmu, hwc);
		prev_raw_count = local64_read(&hwc->prev_count);
	} while (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
				 new_raw_count) != prev_raw_count);
	/*
	 * compute the delta
	 */
	delta = (new_raw_count - prev_raw_count) &
		HISI_MAX_PERIOD(hisi_pmu->counter_bits);
	local64_add(delta, &event->count);
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_event_update);

void hisi_uncore_pmu_start(struct perf_event *event, int flags)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	if (WARN_ON_ONCE(!(hwc->state & PERF_HES_STOPPED)))
		return;

	WARN_ON_ONCE(!(hwc->state & PERF_HES_UPTODATE));
	hwc->state = 0;
	hisi_uncore_pmu_set_event_period(event);

	if (flags & PERF_EF_RELOAD) {
		u64 prev_raw_count =  local64_read(&hwc->prev_count);

		hisi_pmu->ops->write_counter(hisi_pmu, hwc, prev_raw_count);
	}

	hisi_uncore_pmu_enable_event(event);
	perf_event_update_userpage(event);
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_start);

void hisi_uncore_pmu_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;

	hisi_uncore_pmu_disable_event(event);
	WARN_ON_ONCE(hwc->state & PERF_HES_STOPPED);
	hwc->state |= PERF_HES_STOPPED;

	if (hwc->state & PERF_HES_UPTODATE)
		return;

	/* Read hardware counter and update the perf counter statistics */
	hisi_uncore_pmu_event_update(event);
	hwc->state |= PERF_HES_UPTODATE;
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_stop);

int hisi_uncore_pmu_add(struct perf_event *event, int flags)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx;

	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;

	/* Get an available counter index for counting */
	idx = hisi_pmu->ops->get_event_idx(event);
	if (idx < 0)
		return idx;

	event->hw.idx = idx;
	hisi_pmu->pmu_events.hw_events[idx] = event;

	if (flags & PERF_EF_START)
		hisi_uncore_pmu_start(event, PERF_EF_RELOAD);

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_add);

void hisi_uncore_pmu_del(struct perf_event *event, int flags)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	hisi_uncore_pmu_stop(event, PERF_EF_UPDATE);
	hisi_uncore_pmu_clear_event_idx(hisi_pmu, hwc->idx);
	perf_event_update_userpage(event);
	hisi_pmu->pmu_events.hw_events[hwc->idx] = NULL;
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_del);

void hisi_uncore_pmu_read(struct perf_event *event)
{
	/* Read hardware counter and update the perf counter statistics */
	hisi_uncore_pmu_event_update(event);
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_read);

void hisi_uncore_pmu_enable(struct pmu *pmu)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(pmu);
	int enabled = bitmap_weight(hisi_pmu->pmu_events.used_mask,
				    hisi_pmu->pmu.num_counters);

	if (!enabled)
		return;

	hisi_pmu->ops->start_counters(hisi_pmu);
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_enable);

void hisi_uncore_pmu_disable(struct pmu *pmu)
{
	struct hisi_pmu *hisi_pmu = to_hisi_pmu(pmu);

	hisi_pmu->ops->stop_counters(hisi_pmu);
}
EXPORT_SYMBOL_GPL(hisi_uncore_pmu_disable);

MODULE_LICENSE("GPL v2");
