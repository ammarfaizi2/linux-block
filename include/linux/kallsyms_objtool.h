/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KALLSYMS_OBJTOOL_H
#define _LINUX_KALLSYMS_OBJTOOL_H

#include <linux/types.h>

struct kallsyms_entry {
	u64 offset;
};

struct kallsyms_sym {
	char *name;
	u64 offset;
};

#ifdef CONFIG_KALLSYMS_FAST
extern void kallsyms_objtool_init(void);
#else
static inline void kallsyms_objtool_init(void) { }
#endif

#endif /* _LINUX_KALLSYMS_OBJTOOL_H */
