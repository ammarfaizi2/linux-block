#include <linux/cache.h>
#include <linux/export.h>

#include <asm/bug.h>
#include <asm/cpuid.h>

/*
 * Nomenclature: cpuid() is the function executing the CPUID instruction and
 * cpuid_info is the information returned by the CPUID instruction.
 */
struct cpuid_leafs_info cpuid_info __ro_after_init;
EXPORT_SYMBOL(cpuid_info);

void cpuid_read_leaf(unsigned int l)
{
        u32 *p;

	/* MAX leaf */
        if (l > cpuid_eax(l & 0xffff0000))
                return;

        switch (l) {
        case 0x0:       p = (u32 *)&cpuid_info.std.max_lvl;     break;
	case 0x1:	p = (u32 *)&cpuid_info.std.fms;		break;

        default:
                WARN_ON(1);
                return;
        }

        cpuid_count(l, 0, &p[0], &p[1], &p[2], &p[3]);
}

void cpuid_read_all_leafs(void)
{
	cpuid_read_leaf(0);
	cpuid_read_leaf(1);
}
