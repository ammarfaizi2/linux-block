// SPDX-License-Identifier: GPL-2.0

#include "messages.h"
#include "ctree.h"
#include "fs.h"
#include "accessors.h"

void __btrfs_set_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag,
			     const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info,
				"setting incompat feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

void __btrfs_clear_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag,
			       const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info,
				"clearing incompat feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

void __btrfs_set_fs_compat_ro(struct btrfs_fs_info *fs_info, u64 flag,
			      const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info,
				"setting compat-ro feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

void __btrfs_clear_fs_compat_ro(struct btrfs_fs_info *fs_info, u64 flag,
				const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info,
				"clearing compat-ro feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

/*
 * The user can't use the taskset pattern because ',' is used as
 * the mount option delimiter. They can use the same taskset pattern,
 * but replace the ',' with '.' and we will replace it back to
 * ',', so the cpulist_parse() can recognize it.
 *
 * For example, in taskset cmd, they do:
 * taskset -c 1,4,7 /bin/ls
 *
 * The equivalent CPU mask for the btrfs mount option will be:
 * wq_cpu_set=1.4.7
 *
 * Mark these as __cold to avoid the code bloat from overoptimizing
 * the loop.
 */
__cold static void cpulist_dot_to_comma(char *set)
{
	while (*set) {
		if (*set == '.')
			*set = ',';
		set++;
	}
}

__cold static void cpulist_comma_to_dot(char *set)
{
	while (*set) {
		if (*set == ',')
			*set = '.';
		set++;
	}
}

void btrfs_destroy_cpu_set(struct btrfs_cpu_set *cpu_set)
{
	if (!cpu_set)
		return;

	free_cpumask_var(cpu_set->mask);
	kfree(cpu_set->mask_str);
	kfree(cpu_set);
}

/*
 * Only called from btrfs_parse_cpu_set().
 */
static struct btrfs_cpu_set *btrfs_alloc_cpu_set(void)
{
	struct btrfs_cpu_set *cpu_set;

	cpu_set = kmalloc(sizeof(*cpu_set), GFP_KERNEL);
	if (!cpu_set)
		return NULL;

	if (!alloc_cpumask_var(&cpu_set->mask, GFP_KERNEL)) {
		kfree(cpu_set);
		return NULL;
	}

	cpu_set->mask_str = NULL;
	return cpu_set;
}

int btrfs_parse_cpu_set(struct btrfs_cpu_set **cpu_set_p, const char *mask_str)
{
	struct btrfs_cpu_set *cpu_set;
	int ret;

	cpu_set = btrfs_alloc_cpu_set();
	if (!cpu_set)
		return -ENOMEM;

	cpu_set->mask_str = kstrdup(mask_str, GFP_KERNEL);
	if (!cpu_set->mask_str) {
		ret = -ENOMEM;
		goto out_fail;
	}

	cpulist_dot_to_comma(cpu_set->mask_str);
	ret = cpulist_parse(cpu_set->mask_str, cpu_set->mask);
	if (ret)
		goto out_fail;

	if (cpumask_empty(cpu_set->mask)) {
		ret = -EINVAL;
		goto out_fail;
	}

	cpulist_comma_to_dot(cpu_set->mask_str);
	*cpu_set_p = cpu_set;
	return 0;

out_fail:
	btrfs_destroy_cpu_set(cpu_set);
	return ret;
}
