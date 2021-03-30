/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_SPINLOCK_TYPES_H
#define __ASM_SPINLOCK_TYPES_H

#if !defined(__LINUX_SPINLOCK_TYPES_H) && !defined(__ASM_SPINLOCK_H)
# error "please don't include this file directly"
#endif

#if defined(CONFIG_QUEUED_SPINLOCKS)
#include <asm-generic/qspinlock_types.h>
#elif defined(CONFIG_TICKET_SPINLOCKS)
#include <asm-generic/tspinlock_types.h>
#endif

#include <asm-generic/qrwlock_types.h>

#endif
