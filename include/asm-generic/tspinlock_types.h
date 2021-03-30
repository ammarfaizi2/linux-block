/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Ticket-based spinlock
 *
 * Copyright (C) 2021 Google, Inc
 *
 * Author: Palmer Dabbelt <palmerdabbelt@google.com>
 */
#ifndef __ASM_GENERIC_TSPINLOCK_TYPES_H
#define __ASM_GENERIC_TSPINLOCK_TYPES_H

#include <linux/atomic.h>

/*
 * We're aiming for the simplest possible lock that is still fair and correct.
 * In this case we just have two counters: one that contains the next ticket to
 * hand out, and one that contains the current ticket that is being served.
 * Keeping these as two distinct counters makes lock and unlock trivial, but
 * makes it impossible to produce a consistent view of the entire lock state.
 * See the implementation of every other function for more details.
 */
typedef struct tspinlock {
	atomic_t next;
	atomic_t curr;
} arch_spinlock_t;

#endif /* __ASM_GENERIC_TSPINLOCK_TYPES_H */
