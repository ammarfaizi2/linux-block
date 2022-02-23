/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGTABLE_TYPES_H
#define _LINUX_PGTABLE_TYPES_H


#include <asm/pgtable_types.h>

#ifndef __ASSEMBLY__

#include <linux/pfn.h>

/*
 * Architecture PAGE_KERNEL_* fallbacks
 *
 * Some architectures don't define certain PAGE_KERNEL_* flags. This is either
 * because they really don't support them, or the port needs to be updated to
 * reflect the required functionality. Below are a set of relatively safe
 * fallbacks, as best effort, which we can count on in lieu of the architectures
 * not defining them on their own yet.
 */

#ifndef PAGE_KERNEL_RO
# define PAGE_KERNEL_RO PAGE_KERNEL
#endif

#ifndef PAGE_KERNEL_EXEC
# define PAGE_KERNEL_EXEC PAGE_KERNEL
#endif

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_PGTABLE_TYPES_H */
