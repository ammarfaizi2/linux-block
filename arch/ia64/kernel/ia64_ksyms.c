/*
 * Architecture-specific kernel symbols
 *
 * Don't put any exports here unless it's defined in an assembler file.
 * All other exports should be put directly after the definition.
 */

#include <linux/module.h>

#ifdef CONFIG_VIRTUAL_MEM_MAP
#include <linux/bootmem.h>
EXPORT_SYMBOL(min_low_pfn);	/* defined by bootmem.c, but not exported by generic code */
EXPORT_SYMBOL(max_low_pfn);	/* defined by bootmem.c, but not exported by generic code */
#endif
