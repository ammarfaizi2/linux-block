// SPDX-License-Identifier: GPL-2.0
/*
 * APIC driver for "bigsmp" xAPIC machines with more than 8 virtual CPUs.
 *
 * Drives the local APIC in "clustered mode".
 */
#include <linux/cpumask.h>
#include <linux/dmi.h>
#include <linux/smp.h>

#include <asm/apic.h>
#include <asm/io_apic.h>

#include "local.h"

static unsigned bigsmp_get_apic_id(unsigned long x)
{
	return (x >> 24) & 0xFF;
}

static int bigsmp_apic_id_registered(void)
{
	return 1;
}

static bool bigsmp_check_apicid_used(physid_mask_t *map, int apicid)
{
	return false;
}

/*
 * bigsmp enables physical destination mode
 * and doesn't use LDR and DFR
 */
static void bigsmp_init_apic_ldr(void)
{
}

static void bigsmp_setup_apic_routing(void)
{
	printk(KERN_INFO
		"Enabling APIC mode:  Physflat.  Using %d I/O APICs\n",
		nr_ioapics);
}

static void bigsmp_ioapic_phys_id_map(physid_mask_t *phys_map, physid_mask_t *retmap)
{
	/* For clustered we don't have a good way to do this yet - hack */
	physids_promote(0xFFL, retmap);
}

static int bigsmp_phys_pkg_id(int cpuid_apic, int index_msb)
{
	return cpuid_apic >> index_msb;
}

static void bigsmp_send_IPI_allbutself(int vector)
{
	default_send_IPI_mask_allbutself_phys(cpu_online_mask, vector);
}

static void bigsmp_send_IPI_all(int vector)
{
	default_send_IPI_mask_sequence_phys(cpu_online_mask, vector);
}

static int dmi_bigsmp; /* can be set by dmi scanners */

static int hp_ht_bigsmp(const struct dmi_system_id *d)
{
	printk(KERN_NOTICE "%s detected: force use of apic=bigsmp\n", d->ident);
	dmi_bigsmp = 1;

	return 0;
}


static const struct dmi_system_id bigsmp_dmi_table[] = {
	{ hp_ht_bigsmp, "HP ProLiant DL760 G2",
		{	DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
			DMI_MATCH(DMI_BIOS_VERSION, "P44-"),
		}
	},

	{ hp_ht_bigsmp, "HP ProLiant DL740",
		{	DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
			DMI_MATCH(DMI_BIOS_VERSION, "P47-"),
		}
	},
	{ } /* NULL entry stops DMI scanning */
};

static int probe_bigsmp(void)
{
	return dmi_check_system(bigsmp_dmi_table);
}

static struct apic apic_bigsmp __ro_after_init = {

	.name				= "bigsmp",
	.probe				= probe_bigsmp,
	.apic_id_valid			= default_apic_id_valid,
	.apic_id_registered		= bigsmp_apic_id_registered,

	.delivery_mode			= APIC_DELIVERY_MODE_FIXED,
	.dest_mode_logical		= false,

	.disable_esr			= 1,

	.check_apicid_used		= bigsmp_check_apicid_used,
	.init_apic_ldr			= bigsmp_init_apic_ldr,
	.ioapic_phys_id_map		= bigsmp_ioapic_phys_id_map,
	.setup_apic_routing		= bigsmp_setup_apic_routing,
	.cpu_present_to_apicid		= default_cpu_present_to_apicid,
	.apicid_to_cpu_present		= physid_set_mask_of_physid,
	.phys_pkg_id			= bigsmp_phys_pkg_id,

	.get_apic_id			= bigsmp_get_apic_id,
	.set_apic_id			= NULL,

	.calc_dest_apicid		= apic_default_calc_apicid,

	.send_IPI			= default_send_IPI_single_phys,
	.send_IPI_mask			= default_send_IPI_mask_sequence_phys,
	.send_IPI_mask_allbutself	= NULL,
	.send_IPI_allbutself		= bigsmp_send_IPI_allbutself,
	.send_IPI_all			= bigsmp_send_IPI_all,
	.send_IPI_self			= default_send_IPI_self,

	.read				= native_apic_mem_read,
	.write				= native_apic_mem_write,
	.eoi_write			= native_apic_mem_write,
	.icr_read			= native_apic_icr_read,
	.icr_write			= native_apic_icr_write,
	.wait_icr_idle			= native_apic_wait_icr_idle,
	.safe_wait_icr_idle		= native_safe_apic_wait_icr_idle,
};

bool __init apic_bigsmp_possible(bool cmdline_override)
{
	return apic == &apic_bigsmp || !cmdline_override;
}

void __init apic_bigsmp_force(void)
{
	if (apic != &apic_bigsmp) {
		apic = &apic_bigsmp;
		pr_info("Overriding APIC driver with bigsmp\n");
	}
}

apic_driver(apic_bigsmp);
