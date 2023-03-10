/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CHECKSUM_64_H
#define _ASM_X86_CHECKSUM_64_H

/*
 * Checksums for x86-64
 * Copyright 2002 by Andi Kleen, SuSE Labs
 * with some code from asm-x86/checksum.h
 */

/* Do not call this directly. Use the wrappers below */
extern __visible __wsum csum_partial_copy_generic(const void *src, void *dst, int len);

extern __wsum csum_and_copy_from_user(const void __user *src, void *dst, int len);
extern __wsum csum_and_copy_to_user(const void *src, void __user *dst, int len);
extern __wsum csum_partial_copy_nocheck(const void *src, void *dst, int len);

#endif /* _ASM_X86_CHECKSUM_64_H */
