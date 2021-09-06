/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NUMA_TYPES_H
#define _LINUX_NUMA_TYPES_H

#ifdef CONFIG_NODES_SHIFT
#define NODES_SHIFT     CONFIG_NODES_SHIFT
#else
#define NODES_SHIFT     0
#endif

#define MAX_NUMNODES    (1 << NODES_SHIFT)

#define	NUMA_NO_NODE	(-1)

/* optionally keep NUMA memory info available post init */
#ifdef CONFIG_NUMA_KEEP_MEMINFO
#define __initdata_or_meminfo
#else
#define __initdata_or_meminfo __initdata
#endif

#endif /* _LINUX_NUMA_TYPES_H */
