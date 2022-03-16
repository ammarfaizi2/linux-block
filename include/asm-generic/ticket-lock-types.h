/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_GENERIC_TICKET_LOCK_TYPES_H
#define __ASM_GENERIC_TICKET_LOCK_TYPES_H

#include <linux/types.h>
typedef atomic_t arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED	ATOMIC_INIT(0)

#endif /* __ASM_GENERIC_TICKET_LOCK_TYPES_H */
