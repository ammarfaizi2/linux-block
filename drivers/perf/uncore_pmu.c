// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/types.h>

#include "uncore_pmu.h"

/*
 * sysfs cpumask attributes. For uncore PMU, we only have a single CPU to show
 */
static ssize_t cpumask_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct uncore_pmu *uncore_pmu = to_uncore_pmu(dev_get_drvdata(dev));

	return sysfs_emit(buf, "%d\n", uncore_pmu->on_cpu);
}

static struct device_attribute uncore_pmu_cpumask_attr =
	__ATTR_RO(cpumask);

static struct attribute *uncore_pmu_cpumask_attrs[] = {
	&uncore_pmu_cpumask_attr.attr,
	NULL
};

static const struct attribute_group uncore_pmu_cpumask_group = {
	.attrs = uncore_pmu_cpumask_attrs,
};

static const struct attribute_group *uncore_pmu_attr_grps[] = {
	&uncore_pmu_cpumask_group,
	NULL
};

static bool validate_event_group(struct perf_event *event)
{
	struct perf_event *sibling, *leader = event->group_leader;
	struct uncore_pmu *uncore_pmu = to_uncore_pmu(event->pmu);
	/* Include count for the event */
	int counters = 1;

	if (!is_software_event(leader)) {
		/*
		 * We must NOT create groups containing mixed PMUs, although
		 * software events are acceptable
		 */
		if (leader->pmu != event->pmu)
			return false;

		/* Increment counter for the leader */
		if (leader != event)
			counters++;
	}

	for_each_sibling_event(sibling, event->group_leader) {
		if (is_software_event(sibling))
			continue;
		if (sibling->pmu != event->pmu)
			return false;
		/* Increment counter for each sibling */
		counters++;
	}

	/* The group can not count events more than the counters in the HW */
	return counters <= uncore_pmu->num_counters;
}

int uncore_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct uncore_pmu *uncore_pmu = to_uncore_pmu(event->pmu);

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* We don't support sampling */
	if (is_sampling_event(event)) {
		dev_dbg(uncore_pmu->pmu.dev, "Can't support sampling events\n");
		return -EOPNOTSUPP;
	}

	/* We cannot support task bound events */
	if (event->cpu < 0 || event->attach_state & PERF_ATTACH_TASK) {
		dev_dbg(uncore_pmu->pmu.dev, "Can't support per-task counters\n");
		return -EINVAL;
	}

	if (has_branch_stack(event)) {
		dev_dbg(uncore_pmu->pmu.dev, "Can't support filtering\n");
		return -EINVAL;
	}

	if (!cpumask_test_cpu(event->cpu, &uncore_pmu->associated_cpus)) {
		dev_dbg(uncore_pmu->pmu.dev,
			 "Requested cpu is not associated with the DSU\n");
		return -EINVAL;
	}

	/*
	 * Validate if the events in group does not exceed the
	 * available counters in hardware.
	 */
	if (!validate_event_group(event))
		return -EINVAL;

	/*
	 * Choose the current active CPU to read the events. We don't want
	 * to migrate the event contexts, irq handling etc to the requested
	 * CPU. As long as the requested CPU is within the same DSU, we
	 * are fine.
	 */
	event->cpu = uncore_pmu->on_cpu;

	/*
	 * We don't assign an index until we actually place the event onto
	 * hardware. Use -1 to signify that we haven't decided where to put it
	 * yet.
	 */
	hwc->idx		= -1;
	hwc->config_base	= event->attr.config;

	return 0;
}
EXPORT_SYMBOL_GPL(uncore_pmu_event_init);

static int uncore_pmu_online_cpu(unsigned int cpu, struct hlist_node *node)
{
	struct uncore_pmu *uncore_pmu = hlist_entry_safe(node, struct uncore_pmu,
						     node);

	if (!cpumask_test_cpu(cpu, &uncore_pmu->associated_cpus))
		return 0;

	/* If another CPU is already managing this PMU, simply return. */
	if (uncore_pmu->on_cpu != -1)
		return 0;

	/* Use this CPU in cpumask for event counting */
	uncore_pmu->on_cpu = cpu;

	/* Overflow interrupt also should use the same CPU */
	WARN_ON(irq_set_affinity(uncore_pmu->irq, cpumask_of(cpu)));

	return 0;
}

static int uncore_pmu_offline_cpu(unsigned int cpu, struct hlist_node *node)
{
	struct uncore_pmu *uncore_pmu = hlist_entry_safe(node, struct uncore_pmu,
						     node);
	cpumask_t pmu_online_cpus;
	unsigned int target;

	if (!cpumask_test_cpu(cpu, &uncore_pmu->associated_cpus))
		return 0;

	/* Nothing to do if this CPU doesn't own the PMU */
	if (uncore_pmu->on_cpu != cpu)
		return 0;

	/* Give up ownership of the PMU */
	uncore_pmu->on_cpu = -1;

	/* Choose a new CPU to migrate ownership of the PMU to */
	cpumask_and(&pmu_online_cpus, &uncore_pmu->associated_cpus,
		    cpu_online_mask);
	target = cpumask_any_but(&pmu_online_cpus, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&uncore_pmu->pmu, cpu, target);
	/* Use this CPU for event counting */
	uncore_pmu->on_cpu = target;
	if (uncore_pmu->irq)
		WARN_ON(irq_set_affinity(uncore_pmu->irq, cpumask_of(target)));

	return 0;
}

static int uncore_cpuhp;

int uncore_pmu_register(struct uncore_pmu *uncore_pmu, const char *name)
{
	int ret;

	if (cpumask_empty(&uncore_pmu->associated_cpus))
		cpumask_copy(&uncore_pmu->associated_cpus, cpu_possible_mask);

	uncore_pmu->on_cpu = -1;

	ret = cpuhp_state_add_instance(uncore_cpuhp, &uncore_pmu->node);
	if (ret) {
		dev_err(uncore_pmu->dev, "Error %d registering hotplug\n", ret);
		return ret;
	}

	uncore_pmu->pmu.attr_update = uncore_pmu_attr_grps;

	ret = perf_pmu_register(&uncore_pmu->pmu, name, -1);
	if (ret) {
		dev_err(uncore_pmu->dev, "PMU register failed!\n");
		cpuhp_state_remove_instance_nocalls(
			uncore_cpuhp, &uncore_pmu->node);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(uncore_pmu_register);

int uncore_pmu_unregister(struct uncore_pmu *uncore_pmu)
{
	perf_pmu_unregister(&uncore_pmu->pmu);
	cpuhp_state_remove_instance_nocalls(uncore_cpuhp, &uncore_pmu->node);
	return 0;
}
EXPORT_SYMBOL_GPL(uncore_pmu_unregister);

static int __init uncore_pmu_module_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN,
				      "perf uncore",
				      uncore_pmu_online_cpu,
				      uncore_pmu_offline_cpu);
	if (ret < 0) {
		pr_err("Uncore PMU: Error setup hotplug, ret = %d\n", ret);
		return ret;
	}

	uncore_cpuhp = ret;

	return 0;
}
module_init(uncore_pmu_module_init);

static void __exit uncore_pmu_module_exit(void)
{
	cpuhp_remove_multi_state(uncore_cpuhp);
}
module_exit(uncore_pmu_module_exit);

MODULE_LICENSE("GPL v2");
