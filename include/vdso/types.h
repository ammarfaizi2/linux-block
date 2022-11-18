/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#ifndef __VDSO_TYPES_H
#define __VDSO_TYPES_H

#include <linux/types.h>

/**
 * type vdso_kernel_ulong - unsigned long type that matches kernel's unsigned long
 *
 * Data shared between userspace and the kernel must operate the same way in both 64-bit code and in
 * 32-bit compat code, over the same potentially 64-bit kernel. This type represents the size of an
 * unsigned long as used by kernel code. This isn't necessarily the same as an unsigned long as used
 * by userspace, however.
 *
 *                 +-------------------+-------------------+------------------+-------------------+
 *                 | 32-bit userspace  | 32-bit userspace  | 64-bit userspace | 64-bit userspace  |
 *                 | unsigned long     | vdso_kernel_ulong | unsigned long    | vdso_kernel_ulong |
 * +---------------+-------------------+-------------------+------------------+-------------------+
 * | 32-bit kernel | ✓ same size       | ✓ same size       |
 * | unsigned long |                   |                   |
 * +---------------+-------------------+-------------------+------------------+-------------------+
 * | 64-bit kernel | ✘ different size! | ✓ same size       | ✓ same size      | ✓ same size       |
 * | unsigned long |                   |                   |                  |                   |
 * +---------------+-------------------+-------------------+------------------+-------------------+
 */
#ifdef CONFIG_64BIT
typedef u64 vdso_kernel_ulong;
#else
typedef u32 vdso_kernel_ulong;
#endif

#endif /* __VDSO_TYPES_H */
