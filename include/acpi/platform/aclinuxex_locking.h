/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: aclinuxex.h - Extra OS specific defines, etc. for Linux
 *
 * Copyright (C) 2000 - 2021, Intel Corp.
 *
 *****************************************************************************/

#ifndef __ACLINUXEX_LOCKING_H__
#define __ACLINUXEX_LOCKING_H__

#ifdef __KERNEL__

#include <acpi/acpi.h>
#include <linux/spinlock_api.h>
#include <acpi/platform/aclinuxex.h>

/*
 * When lockdep is enabled, the spin_lock_init() macro stringifies it's
 * argument and uses that as a name for the lock in debugging.
 * By executing spin_lock_init() in a macro the key changes from "lock" for
 * all locks to the name of the argument of acpi_os_create_lock(), which
 * prevents lockdep from reporting false positives for ACPICA locks.
 */
#define acpi_os_create_lock(__handle) \
	({ \
		spinlock_t *lock = ACPI_ALLOCATE(sizeof(*lock)); \
		if (lock) { \
			*(__handle) = lock; \
			spin_lock_init(*(__handle)); \
		} \
		lock ? AE_OK : AE_NO_MEMORY; \
	})


#define acpi_os_create_raw_lock(__handle) \
	({ \
		raw_spinlock_t *lock = ACPI_ALLOCATE(sizeof(*lock)); \
		if (lock) { \
			*(__handle) = lock; \
			raw_spin_lock_init(*(__handle)); \
		} \
		lock ? AE_OK : AE_NO_MEMORY; \
	})

static inline acpi_cpu_flags acpi_os_acquire_raw_lock(acpi_raw_spinlock lockp)
{
	acpi_cpu_flags flags;

	raw_spin_lock_irqsave(lockp, flags);
	return flags;
}

static inline void acpi_os_release_raw_lock(acpi_raw_spinlock lockp,
					    acpi_cpu_flags flags)
{
	raw_spin_unlock_irqrestore(lockp, flags);
}

static inline void acpi_os_delete_raw_lock(acpi_raw_spinlock handle)
{
	ACPI_FREE(handle);
}

/*
 * OSL interfaces added by Linux
 */

#endif				/* __KERNEL__ */

#endif				/* __ACLINUXEX_LOCKING_H__ */
