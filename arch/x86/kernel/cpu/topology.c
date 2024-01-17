// SPDX-License-Identifier: GPL-2.0-only
/*
 * CPU/APIC topology
 *
 * The APIC IDs describe the system topology in multiple domain levels.
 * The CPUID topology parser provides the information which part of the
 * APIC ID is associated to the individual levels:
 *
 * [PACKAGE][DIEGRP][DIE][TILE][MODULE][CORE][THREAD]
 *
 * The root space contains the package (socket) IDs.
 *
 * Not enumerated levels consume 0 bits space, but conceptually they are
 * always represented. If e.g. only CORE and THREAD levels are enumerated
 * then the DIE, MODULE and TILE have the same physical ID as the PACKAGE.
 *
 * If SMT is not supported, then the THREAD domain is still used. It then
 * has the same physical ID as the CORE domain and is the only child of
 * the core domain.
 *
 * This allows a unified view on the system independent of the enumerated
 * domain levels without requiring any conditionals in the code.
 */
#define pr_fmt(fmt) "CPU topo: " fmt
#include <linux/cpu.h>

#include <xen/xen.h>

#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/mpspec.h>
#include <asm/smp.h>

#include "cpu.h"

/*
 * Map cpu index to physical APIC ID
 */
DEFINE_EARLY_PER_CPU_READ_MOSTLY(u32, x86_cpu_to_apicid, BAD_APICID);
DEFINE_EARLY_PER_CPU_READ_MOSTLY(u32, x86_cpu_to_acpiid, CPU_ACPIID_INVALID);
EXPORT_EARLY_PER_CPU_SYMBOL(x86_cpu_to_apicid);
EXPORT_EARLY_PER_CPU_SYMBOL(x86_cpu_to_acpiid);

/* Bitmap of physically present CPUs. */
DECLARE_BITMAP(phys_cpu_present_map, MAX_LOCAL_APIC) __read_mostly;

/* Used for CPU number allocation and parallel CPU bringup */
u32 cpuid_to_apicid[] __ro_after_init = { [0 ... NR_CPUS - 1] = BAD_APICID, };

/* Bitmaps to mark registered APICs at each topology domain */
static struct { DECLARE_BITMAP(map, MAX_LOCAL_APIC); } apic_maps[TOPO_MAX_DOMAIN] __ro_after_init;

/*
 * Keep track of assigned, disabled and rejected CPUs. Present assigned
 * with 1 as CPU #0 is reserved for the boot CPU.
 */
static struct {
	unsigned int		nr_assigned_cpus;
	unsigned int		nr_disabled_cpus;
	unsigned int		nr_rejected_cpus;
	u32			boot_cpu_apic_id;
	u32			real_bsp_apic_id;
} topo_info __ro_after_init = {
	.nr_assigned_cpus	= 1,
	.boot_cpu_apic_id	= BAD_APICID,
	.real_bsp_apic_id	= BAD_APICID,
};

#define domain_weight(_dom)	bitmap_weight(apic_maps[_dom].map, MAX_LOCAL_APIC)

bool arch_match_cpu_phys_id(int cpu, u64 phys_id)
{
	return phys_id == (u64)cpuid_to_apicid[cpu];
}

#ifdef CONFIG_SMP
static void cpu_mark_primary_thread(unsigned int cpu, unsigned int apicid)
{
	/* Isolate the SMT bit(s) in the APICID and check for 0 */
	u32 mask = (1U << (fls(smp_num_siblings) - 1)) - 1;

	if (smp_num_siblings == 1 || !(apicid & mask))
		cpumask_set_cpu(cpu, &__cpu_primary_thread_mask);
}

/*
 * Due to the utter mess of CPUID evaluation smp_num_siblings is not valid
 * during early boot. Initialize the primary thread mask before SMP
 * bringup.
 */
static int __init smp_init_primary_thread_mask(void)
{
	unsigned int cpu;

	/*
	 * XEN/PV provides either none or useless topology information.
	 * Pretend that all vCPUs are primary threads.
	 */
	if (xen_pv_domain()) {
		cpumask_copy(&__cpu_primary_thread_mask, cpu_possible_mask);
		return 0;
	}

	for (cpu = 0; cpu < topo_info.nr_assigned_cpus; cpu++)
		cpu_mark_primary_thread(cpu, cpuid_to_apicid[cpu]);
	return 0;
}
early_initcall(smp_init_primary_thread_mask);
#else
static inline void cpu_mark_primary_thread(unsigned int cpu, unsigned int apicid) { }
#endif

/*
 * Convert the APIC ID to a domain level ID by masking out the low bits
 * below the domain level @dom.
 */
static inline u32 topo_apicid(u32 apicid, enum x86_topology_domains dom)
{
	if (dom == TOPO_SMT_DOMAIN)
		return apicid;
	return apicid & (UINT_MAX << x86_topo_system.dom_shifts[dom - 1]);
}

static int topo_lookup_cpuid(u32 apic_id)
{
	int i;

	/* CPU# to APICID mapping is persistent once it is established */
	for (i = 0; i < topo_info.nr_assigned_cpus; i++) {
		if (cpuid_to_apicid[i] == apic_id)
			return i;
	}
	return -ENODEV;
}

static __init int topo_assign_cpunr(u32 apic_id)
{
	int cpu = topo_lookup_cpuid(apic_id);

	if (cpu >= 0)
		return cpu;

	return topo_info.nr_assigned_cpus++;
}

static void topo_set_cpuids(unsigned int cpu, u32 apic_id, u32 acpi_id)
{
#if defined(CONFIG_SMP) || defined(CONFIG_X86_64)
	early_per_cpu(x86_cpu_to_apicid, cpu) = apic_id;
	early_per_cpu(x86_cpu_to_acpiid, cpu) = acpi_id;
#endif
	set_cpu_possible(cpu, true);
	set_cpu_present(cpu, true);

	if (system_state != SYSTEM_BOOTING)
		cpu_mark_primary_thread(cpu, apic_id);
}

static __init bool check_for_real_bsp(u32 apic_id)
{
	u32 bsp_apicid;

	/*
	 * There is no real good way to detect whether this a kdump()
	 * kernel, but except on the Voyager SMP monstrosity which is not
	 * longer supported, the real BSP APIC ID is the first one which is
	 * enumerated by firmware. That allows to detect whether the boot
	 * CPU is the real BSP. If it is not, then do not register the APIC
	 * because sending INIT to the real BSP would reset the whole
	 * system.
	 *
	 * The first APIC ID which is enumerated by firmware is detectable
	 * because the boot CPU APIC ID is registered before that without
	 * invoking this code.
	 */
	if (topo_info.real_bsp_apic_id != BAD_APICID)
		return false;

	if (apic_id == topo_info.boot_cpu_apic_id) {
		topo_info.real_bsp_apic_id = apic_id;
		return false;
	}

	pr_warn("Boot CPU APIC ID not the first enumerated APIC ID: %x > %x\n",
		topo_info.boot_cpu_apic_id, bsp_apicid);
	pr_warn("Crash kernel detected. Disabling real BSP to prevent machine INIT\n");

	topo_info.real_bsp_apic_id = bsp_apicid;
	return true;
}

static __init void topo_register_apic(u32 apic_id, u32 acpi_id, bool present)
{
	int cpu, dom;

	if (present) {
		/*
		 * Prevent double registration, which is valid in case of
		 * the boot CPU APIC because that is registered before the
		 * enumeration of the APICs via firmware parsers or VM
		 * guest mechanisms.
		 */
		if (test_and_set_bit(apic_id, phys_cpu_present_map))
			return;

		if (apic_id == topo_info.boot_cpu_apic_id)
			cpu = 0;
		else
			cpu = topo_assign_cpunr(apic_id);

		cpuid_to_apicid[cpu] = apic_id;
		topo_set_cpuids(cpu, apic_id, acpi_id);
	} else {
		topo_info.nr_disabled_cpus++;
	}

	/* Register present and possible CPUs in the domain maps */
	for (dom = TOPO_SMT_DOMAIN; dom < TOPO_MAX_DOMAIN; dom++)
		set_bit(topo_apicid(apic_id, dom), apic_maps[dom].map);
}

/**
 * topology_register_apic - Register an APIC in early topology maps
 * @apic_id:	The APIC ID to set up
 * @acpi_id:	The ACPI ID associated to the APIC
 * @present:	True if the corresponding CPU is present
 */
void __init topology_register_apic(u32 apic_id, u32 acpi_id, bool present)
{
	if (apic_id >= MAX_LOCAL_APIC) {
		pr_err_once("APIC ID %x exceeds kernel limit of: %x\n", apic_id, MAX_LOCAL_APIC - 1);
		topo_info.nr_rejected_cpus++;
		return;
	}

	/* CPU numbers exhausted? */
	if (topo_info.nr_assigned_cpus >= nr_cpu_ids) {
		pr_warn_once("CPU limit of %d reached. Ignoring further CPUs\n", nr_cpu_ids);
		topo_info.nr_rejected_cpus++;
		return;
	}

	if (check_for_real_bsp(apic_id))
		return;

	topo_register_apic(apic_id, acpi_id, present);
}

/**
 * topology_register_boot_apic - Register the boot CPU APIC
 * @apic_id:	The APIC ID to set up
 *
 * Separate so CPU #0 can be assigned
 */
void __init topology_register_boot_apic(u32 apic_id)
{
	WARN_ON_ONCE(topo_info.boot_cpu_apic_id != BAD_APICID);

	topo_info.boot_cpu_apic_id = apic_id;
	topo_register_apic(apic_id, CPU_ACPIID_INVALID, true);
}

#ifdef CONFIG_ACPI_HOTPLUG_CPU
/**
 * topology_hotplug_apic - Handle a physical hotplugged APIC after boot
 * @apic_id:	The APIC ID to set up
 * @acpi_id:	The ACPI ID associated to the APIC
 */
int topology_hotplug_apic(u32 apic_id, u32 acpi_id)
{
	int cpu;

	if (apic_id >= MAX_LOCAL_APIC)
		return -EINVAL;

	/* Reject if the APIC ID was not registered during enumeration. */
	if (!test_bit(apic_id, apic_maps[TOPO_SMT_DOMAIN].map))
		return -ENODEV;

	cpu = topo_lookup_cpuid(apic_id);
	if (cpu < 0)
		return -ENOSPC;

	set_bit(apic_id, phys_cpu_present_map);
	topo_set_cpuids(cpu, apic_id, acpi_id);
	return cpu;
}

/**
 * topology_hotunplug_apic - Remove a physical hotplugged APIC after boot
 * @cpu:	The CPU number for which the APIC ID is removed
 */
void topology_hotunplug_apic(unsigned int cpu)
{
	u32 apic_id = cpuid_to_apicid[cpu];

	if (apic_id == BAD_APICID)
		return;

	per_cpu(x86_cpu_to_apicid, cpu) = BAD_APICID;
	clear_bit(apic_id, phys_cpu_present_map);
	set_cpu_present(cpu, false);
}
#endif

#ifdef CONFIG_SMP
static unsigned int max_possible_cpus __initdata = NR_CPUS;

/**
 * topology_apply_cmdline_limits_early - Apply topology command line limits early
 *
 * Ensure that command line limits are in effect before firmware parsing
 * takes place.
 */
void __init topology_apply_cmdline_limits_early(void)
{
	unsigned int possible = nr_cpu_ids;

	/* 'maxcpus=0' 'nosmp' 'nolapic' 'disableapic' 'noapic' */
	if (!setup_max_cpus || ioapic_is_disabled || apic_is_disabled)
		possible = 1;

	/* 'possible_cpus=N' */
	possible = min_t(unsigned int, max_possible_cpus, possible);

	if (possible < nr_cpu_ids) {
		pr_info("Limiting to %u possible CPUs\n", possible);
		set_nr_cpu_ids(possible);
	}
}

static __init bool restrict_to_up(void)
{
	if (!smp_found_config || ioapic_is_disabled)
		return true;
	/*
	 * XEN PV is special as it does not advertise the local APIC
	 * properly, but provides a fake topology for it so that the
	 * infrastructure works. So don't apply the restrictions vs. APIC
	 * here.
	 */
	if (xen_pv_domain())
		return false;

	return apic_is_disabled;
}

void __init topology_init_possible_cpus(void)
{
	unsigned int assigned = topo_info.nr_assigned_cpus;
	unsigned int disabled = topo_info.nr_disabled_cpus;
	unsigned int cnta, cntb, cpu, allowed = 1;
	unsigned int total = assigned + disabled;
	u32 apicid;

	if (!restrict_to_up()) {
		if (WARN_ON_ONCE(assigned > nr_cpu_ids)) {
			disabled += assigned - nr_cpu_ids;
			assigned = nr_cpu_ids;
		}
		allowed = min_t(unsigned int, total, nr_cpu_ids);
	}

	if (total > allowed)
		pr_warn("%u possible CPUs exceed the limit of %u\n", total, allowed);

	assigned = min_t(unsigned int, allowed, assigned);
	disabled = allowed - assigned;

	topo_info.nr_assigned_cpus = assigned;
	topo_info.nr_disabled_cpus = disabled;

	total_cpus = allowed;
	set_nr_cpu_ids(allowed);

	cnta = domain_weight(TOPO_PKG_DOMAIN);
	cntb = domain_weight(TOPO_DIE_DOMAIN);
	__max_logical_packages = cnta;
	__max_dies_per_package = 1U << (get_count_order(cntb) - get_count_order(cnta));

	pr_info("Max. logical packages: %3u\n", cnta);
	pr_info("Max. logical dies:     %3u\n", cntb);
	pr_info("Max. dies per package: %3u\n", __max_dies_per_package);

	cnta = domain_weight(TOPO_CORE_DOMAIN);
	cntb = domain_weight(TOPO_SMT_DOMAIN);
	smp_num_siblings = 1U << (get_count_order(cntb) - get_count_order(cnta));
	pr_info("Max. threads per core: %3u\n", smp_num_siblings);

	pr_info("Allowing %u present CPUs plus %u hotplug CPUs\n", assigned, disabled);
	if (topo_info.nr_rejected_cpus)
		pr_info("Rejected CPUs %u\n", topo_info.nr_rejected_cpus);

	init_cpu_present(cpumask_of(0));
	init_cpu_possible(cpumask_of(0));

	for (apicid = 0; disabled; disabled--, apicid++) {
		apicid = find_next_andnot_bit(apic_maps[TOPO_SMT_DOMAIN].map, phys_cpu_present_map,
					      MAX_LOCAL_APIC, apicid);
		if (apicid >= MAX_LOCAL_APIC)
			break;
		cpuid_to_apicid[topo_info.nr_assigned_cpus++] = apicid;
	}

	for (cpu = 0; cpu < allowed; cpu++) {
		apicid = cpuid_to_apicid[cpu];

		/*
		 * In case of a kdump() kernel, don't mark the real BSP in
		 * the present and possible maps. Sending INIT to it resets
		 * the machine.
		 */
		if (apicid != BAD_APICID && apicid == topo_info.real_bsp_apic_id)
			continue;

		set_cpu_possible(cpu, true);

		if (apicid == BAD_APICID)
			continue;

		set_cpu_present(cpu, test_bit(apicid, phys_cpu_present_map));
	}
}

/*
 * Late SMP disable after sizing CPU masks when APIC/IOAPIC setup failed.
 */
void __init topology_reset_possible_cpus_up(void)
{
	init_cpu_present(cpumask_of(0));
	init_cpu_possible(cpumask_of(0));

	bitmap_zero(phys_cpu_present_map, MAX_LOCAL_APIC);
	if (topo_info.boot_cpu_apic_id != BAD_APICID)
		set_bit(topo_info.boot_cpu_apic_id, phys_cpu_present_map);
}

static int __init setup_possible_cpus(char *str)
{
	get_option(&str, &max_possible_cpus);
	return 0;
}
early_param("possible_cpus", setup_possible_cpus);
#endif
