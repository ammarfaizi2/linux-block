// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple SoC CPU cluster performance state driver
 *
 * Copyright The Asahi Linux Contributors
 *
 * Based on scpi-cpufreq.c
 */

#define DEBUG

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/pm_opp.h>
#include <linux/slab.h>

#define APPLE_CLUSTER_PSTATE    0x20
#define APPLE_CLUSTER_PSTATE_BUSY	BIT(31)
#define APPLE_CLUSTER_PSTATE_SET	BIT(25)
#define APPLE_CLUSTER_PSTATE_DESIRED2	GENMASK(15, 12)
#define APPLE_CLUSTER_PSTATE_DESIRED1	GENMASK(3, 0)

struct apple_cpu_priv {
	struct device *cpu_dev;
	void __iomem *reg_base;
};

struct apple_soc_cpufreq_priv {
	struct device *dev;
	void __iomem *reg_base;
};

#define to_apple_cluster_clk(_hw) container_of(_hw, struct apple_cluster_clk, hw)

#define APPLE_CLUSTER_SWITCH_TIMEOUT 100

static unsigned int apple_soc_cpufreq_get_rate(unsigned int cpu)
{
	struct cpufreq_policy *policy = cpufreq_cpu_get_raw(cpu);
	struct apple_cpu_priv *priv = policy->driver_data;
	u64 reg = readq_relaxed(priv->reg_base + APPLE_CLUSTER_PSTATE);
	unsigned int pstate = FIELD_GET(APPLE_CLUSTER_PSTATE_DESIRED1, reg);
	unsigned int i;

	for (i = 0; policy->freq_table[i].frequency != CPUFREQ_TABLE_END; i++)
		if (policy->freq_table[i].driver_data == pstate)
			return policy->freq_table[i].frequency;

	dev_err(priv->cpu_dev, "could not find frequency for pstate %d\n", pstate);
	return 0;
}

static int apple_soc_cpufreq_set_target(struct cpufreq_policy *policy, unsigned int index)
{
	struct apple_cpu_priv *priv = policy->driver_data;
	unsigned int pstate = policy->freq_table[index].driver_data;
	u64 reg;

	if (readq_poll_timeout(priv->reg_base + APPLE_CLUSTER_PSTATE, reg,
			       !(reg & APPLE_CLUSTER_PSTATE_BUSY), 2,
			       APPLE_CLUSTER_SWITCH_TIMEOUT)) {
		return -EIO;
	}

	reg &= ~(APPLE_CLUSTER_PSTATE_DESIRED1 | APPLE_CLUSTER_PSTATE_DESIRED2);
	reg |= FIELD_PREP(APPLE_CLUSTER_PSTATE_DESIRED1, pstate);
	reg |= FIELD_PREP(APPLE_CLUSTER_PSTATE_DESIRED2, pstate);
	reg |= APPLE_CLUSTER_PSTATE_SET;

	writeq_relaxed(reg, priv->reg_base + APPLE_CLUSTER_PSTATE);

	return 0;
}

static unsigned int apple_soc_cpufreq_fast_switch(struct cpufreq_policy *policy,
						  unsigned int target_freq)
{
	if (apple_soc_cpufreq_set_target(policy, policy->cached_resolved_idx) < 0)
		return 0;

	return policy->freq_table[policy->cached_resolved_idx].frequency;
}


static int apple_soc_cpufreq_find_cluster(struct cpufreq_policy *policy, void __iomem **reg_base)
{
	struct of_phandle_args args;
	struct device_node *cpu_np;
	char name[32];
	int cpu, ret;
	int index;

	cpu_np = of_cpu_device_node_get(policy->cpu);
	if (!cpu_np)
		return -EINVAL;

	ret = of_parse_phandle_with_args(cpu_np, "apple,freq-domain",
					 "#freq-domain-cells", 0, &args);
	of_node_put(cpu_np);
	if (ret)
		return ret;

	index = args.args[0];

	snprintf(name, sizeof(name), "cluster%d", index);
	ret = of_property_match_string(args.np, "reg-names", name);
	if (ret < 0)
		return ret;

	*reg_base = of_iomap(args.np, ret);
        if (IS_ERR(*reg_base))
                return PTR_ERR(*reg_base);

	for_each_possible_cpu(cpu) {
		cpu_np = of_cpu_device_node_get(cpu);
		if (!cpu_np)
			continue;

		ret = of_parse_phandle_with_args(cpu_np, "apple,freq-domain",
						 "#freq-domain-cells", 0,
						 &args);
		of_node_put(cpu_np);
		if (ret < 0)
			continue;

		if (index == args.args[0])
			cpumask_set_cpu(cpu, policy->cpus);
	}

	return 0;
}


static int apple_soc_cpufreq_init(struct cpufreq_policy *policy)
{
	int ret, i;
	unsigned int transition_latency;
	void __iomem *reg_base;
	struct device *cpu_dev;
	struct apple_cpu_priv *priv;
	struct cpufreq_frequency_table *freq_table;

	cpu_dev = get_cpu_device(policy->cpu);
	if (!cpu_dev) {
		pr_err("failed to get cpu%d device\n", policy->cpu);
		return -ENODEV;
	}

	ret = dev_pm_opp_of_add_table(cpu_dev);
	if (ret < 0) {
		dev_err(cpu_dev, "%s: failed to add OPP table: %d\n",
			__func__, ret);
	}

	ret = apple_soc_cpufreq_find_cluster(policy, &reg_base);
	if (ret) {
		dev_err(cpu_dev, "%s: failed to get cluster info: %d\n",
			__func__, ret);
		return ret;
	}

	ret = dev_pm_opp_set_sharing_cpus(cpu_dev, policy->cpus);
	if (ret) {
		dev_err(cpu_dev, "%s: failed to mark OPPs as shared: %d\n",
			__func__, ret);
		goto out_iounmap;
	}

	ret = dev_pm_opp_get_opp_count(cpu_dev);
	if (ret <= 0) {
		dev_dbg(cpu_dev, "OPP table is not ready, deferring probe\n");
		ret = -EPROBE_DEFER;
		goto out_free_opp;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		ret = -ENOMEM;
		goto out_free_opp;
	}

	ret = dev_pm_opp_init_cpufreq_table(cpu_dev, &freq_table);
	if (ret) {
		dev_err(cpu_dev, "failed to init cpufreq table: %d\n", ret);
		goto out_free_priv;
	}

	/* Get OPP levels (p-state indexes) and stash them in driver_data */
	for (i = 0; freq_table[i].frequency != CPUFREQ_TABLE_END; i++) {
		unsigned long rate = freq_table[i].frequency * 1000;
		struct dev_pm_opp *opp = dev_pm_opp_find_freq_floor(cpu_dev, &rate);

		if (IS_ERR(opp)) {
			ret = PTR_ERR(opp);
			goto out_free_cpufreq_table;
		}
		freq_table[i].driver_data = dev_pm_opp_get_level(opp);
		dev_pm_opp_put(opp);
	}

	priv->cpu_dev = cpu_dev;
	priv->reg_base = reg_base;
	policy->driver_data = priv;
	policy->freq_table = freq_table;

	transition_latency = dev_pm_opp_get_max_transition_latency(cpu_dev);
	if (!transition_latency)
		transition_latency = CPUFREQ_ETERNAL;

	policy->cpuinfo.transition_latency = transition_latency;
	policy->dvfs_possible_from_any_cpu = true;
	policy->fast_switch_possible = true;

	return 0;

out_free_cpufreq_table:
	dev_pm_opp_free_cpufreq_table(cpu_dev, &freq_table);
out_free_priv:
	kfree(priv);
out_free_opp:
	dev_pm_opp_remove_all_dynamic(cpu_dev);
out_iounmap:
	iounmap(reg_base);
	return ret;
}

static int apple_soc_cpufreq_exit(struct cpufreq_policy *policy)
{
	struct apple_cpu_priv *priv = policy->driver_data;

	dev_pm_opp_free_cpufreq_table(priv->cpu_dev, &policy->freq_table);
	dev_pm_opp_remove_all_dynamic(priv->cpu_dev);
	iounmap(priv->reg_base);
	kfree(priv);

	return 0;
}

static struct cpufreq_driver apple_soc_cpufreq_driver = {
	.name	= "apple-cpufreq",
	.flags	= CPUFREQ_HAVE_GOVERNOR_PER_POLICY |
		  CPUFREQ_NEED_INITIAL_FREQ_CHECK |
		  CPUFREQ_IS_COOLING_DEV,
	.verify	= cpufreq_generic_frequency_table_verify,
	.attr	= cpufreq_generic_attr,
	.get	= apple_soc_cpufreq_get_rate,
	.init	= apple_soc_cpufreq_init,
	.exit	= apple_soc_cpufreq_exit,
	.target_index	= apple_soc_cpufreq_set_target,
	.fast_switch	= apple_soc_cpufreq_fast_switch,
	.register_em	= cpufreq_register_em_with_opp,
};

static int apple_soc_cpufreq_probe(struct platform_device *pdev)
{
	int ret;

	ret = cpufreq_register_driver(&apple_soc_cpufreq_driver);
	if (ret)
		dev_err_probe(&pdev->dev, ret, "registering cpufreq failed\n");
	return ret;
}

static int apple_soc_cpufreq_remove(struct platform_device *pdev)
{
	cpufreq_unregister_driver(&apple_soc_cpufreq_driver);
	return 0;
}

static const struct of_device_id apple_soc_cpufreq_of_match[] = {
	{ .compatible = "apple,cluster-cpufreq" },
	{}
};
MODULE_DEVICE_TABLE(of, apple_soc_cpufreq_of_match);

static struct platform_driver apple_soc_cpufreq_plat_driver = {
	.probe		= apple_soc_cpufreq_probe,
	.remove		= apple_soc_cpufreq_remove,
	.driver = {
		.name	= "apple-soc-cpufreq",
		.of_match_table = apple_soc_cpufreq_of_match,
	},
};
module_platform_driver(apple_soc_cpufreq_plat_driver);

MODULE_AUTHOR("Hector Martin <marcan@marcan.st>");
MODULE_DESCRIPTION("CPU cluster p-state driver for Apple SoCs");
MODULE_LICENSE("GPL");
