#include <linux/cache.h>
#include <linux/export.h>

#include <asm/cpuid.h>

/*
 * Nomenclature: cpuid() is the function executing the CPUID instruction and
 * cpuid_info is the information returned by the CPUID instruction.
 */
struct cpuid_leafs_info cpuid_info __ro_after_init;
EXPORT_SYMBOL(cpuid_info);

void cpuid_read_all_leafs(void)
{
}
