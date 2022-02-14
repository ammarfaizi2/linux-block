/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_CPUMASK_TYPES_H
#define __LINUX_CPUMASK_TYPES_H

/*
 * Cpumasks provide a bitmap suitable for representing the
 * set of CPU's in a system, one bit position per CPU number.  In general,
 * only nr_cpu_ids (<= NR_CPUS) bits are valid.
 */
#include <linux/threads.h>
#include <linux/bitops_types.h>

/* Don't assign or return these: may not be this big! */
typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

/*
 * cpumask_var_t: struct cpumask for stack usage.
 *
 * Oh, the wicked games we play!  In order to make kernel coding a
 * little more difficult, we typedef cpumask_var_t to an array or a
 * pointer: doing &mask on an array is a noop, so it still works.
 *
 * ie.
 *	cpumask_var_t tmpmask;
 *	if (!alloc_cpumask_var(&tmpmask, GFP_KERNEL))
 *		return -ENOMEM;
 *
 *	  ... use 'tmpmask' like a normal struct cpumask * ...
 *
 *	free_cpumask_var(tmpmask);
 *
 *
 * However, one notable exception is there. alloc_cpumask_var() allocates
 * only nr_cpumask_bits bits (in the other hand, real cpumask_t always has
 * NR_CPUS bits). Therefore you don't have to dereference cpumask_var_t.
 *
 *	cpumask_var_t tmpmask;
 *	if (!alloc_cpumask_var(&tmpmask, GFP_KERNEL))
 *		return -ENOMEM;
 *
 *	var = *tmpmask;
 *
 * This code makes NR_CPUS length memcopy and brings to a memory corruption.
 * cpumask_copy() provide safe copy functionality.
 *
 * Note that there is another evil here: If you define a cpumask_var_t
 * as a percpu variable then the way to obtain the address of the cpumask
 * structure differently influences what this_cpu_* operation needs to be
 * used. Please use this_cpu_cpumask_var_t in those cases. The direct use
 * of this_cpu_ptr() or this_cpu_read() will lead to failures when the
 * other type of cpumask_var_t implementation is configured.
 *
 * Please also note that __cpumask_var_read_mostly can be used to declare
 * a cpumask_var_t variable itself (not its content) as read mostly.
 */
#ifdef CONFIG_CPUMASK_OFFSTACK
typedef struct cpumask *cpumask_var_t;
#else
typedef struct cpumask cpumask_var_t[1];
#endif

/*
 * The following particular system cpumasks and operations manage
 * possible, present, active and online cpus.
 *
 *     cpu_possible_mask- has bit 'cpu' set iff cpu is populatable
 *     cpu_present_mask - has bit 'cpu' set iff cpu is populated
 *     cpu_online_mask  - has bit 'cpu' set iff cpu available to scheduler
 *     cpu_active_mask  - has bit 'cpu' set iff cpu available to migration
 *
 *  If !CONFIG_HOTPLUG_CPU, present == possible, and active == online.
 *
 *  The cpu_possible_mask is fixed at boot time, as the set of CPU id's
 *  that it is possible might ever be plugged in at anytime during the
 *  life of that system boot.  The cpu_present_mask is dynamic(*),
 *  representing which CPUs are currently plugged in.  And
 *  cpu_online_mask is the dynamic subset of cpu_present_mask,
 *  indicating those CPUs available for scheduling.
 *
 *  If HOTPLUG is enabled, then cpu_possible_mask is forced to have
 *  all NR_CPUS bits set, otherwise it is just the set of CPUs that
 *  ACPI reports present at boot.
 *
 *  If HOTPLUG is enabled, then cpu_present_mask varies dynamically,
 *  depending on what ACPI reports as currently plugged in, otherwise
 *  cpu_present_mask is just a copy of cpu_possible_mask.
 *
 *  (*) Well, cpu_present_mask is dynamic in the hotplug case.  If not
 *      hotplug, it's a copy of cpu_possible_mask, hence fixed at boot.
 *
 * Subtleties:
 * 1) UP arch's (NR_CPUS == 1, CONFIG_SMP not defined) hardcode
 *    assumption that their single CPU is online.  The UP
 *    cpu_{online,possible,present}_masks are placebos.  Changing them
 *    will have no useful affect on the following num_*_cpus()
 *    and cpu_*() macros in the UP case.  This ugliness is a UP
 *    optimization - don't waste any instructions or memory references
 *    asking if you're online or how many CPUs there are if there is
 *    only one CPU.
 */

extern struct cpumask __cpu_possible_mask;
extern struct cpumask __cpu_online_mask;
extern struct cpumask __cpu_present_mask;
extern struct cpumask __cpu_active_mask;
extern struct cpumask __cpu_dying_mask;
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)
#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)
#define cpu_dying_mask    ((const struct cpumask *)&__cpu_dying_mask)

/**
 * to_cpumask - convert an NR_CPUS bitmap to a struct cpumask *
 * @bitmap: the bitmap
 *
 * There are a few places where cpumask_var_t isn't appropriate and
 * static cpumasks must be used (eg. very early boot), yet we don't
 * expose the definition of 'struct cpumask'.
 *
 * This does the conversion, and can be used as a constant initializer.
 */
#define to_cpumask(bitmap)						\
	((struct cpumask *)(1 ? (bitmap)				\
			    : (void *)sizeof(__check_is_bitmap(bitmap))))

static inline int __check_is_bitmap(const unsigned long *bitmap)
{
	return 1;
}

/* It's common to want to use cpu_all_mask in struct member initializers,
 * so it has to refer to an address rather than a pointer. */
extern const DECLARE_BITMAP(cpu_all_bits, NR_CPUS);
#define cpu_all_mask to_cpumask(cpu_all_bits)

/* First bits of cpu_bit_bitmap are in fact unset. */
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])

#endif /* __LINUX_CPUMASK_TYPES_H */
