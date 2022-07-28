/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#ifndef __ASM_VDSO_GETRANDOM_H
#define __ASM_VDSO_GETRANDOM_H

#ifndef __ASSEMBLY__

#include <asm/unistd.h>
#include <asm/vvar.h>

static __always_inline ssize_t
getrandom_syscall(void *buffer, size_t len, unsigned int flags)
{
	long ret;

	asm ("syscall" : "=a" (ret) :
	     "0" (__NR_getrandom), "D" (buffer), "S" (len), "d" (flags) :
	     "rcx", "r11", "memory");

	return ret;
}

static __always_inline void *
mmap_syscall(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	long ret;
	register long r10 asm("r10") = flags;
	register long r8 asm("r8") = fd;
	register long r9 asm("r9") = offset;

	asm ("syscall" : "=a" (ret) :
	     "0" (__NR_mmap), "D" (addr), "S" (len), "d" (prot),
	     "r" (r10), "r" (r8), "r" (r9) :
	     "rcx", "r11");

	return (void *)ret;
}

static __always_inline int
munmap_syscall(void *addr, size_t len)
{
	long ret;

	asm ("syscall" : "=a" (ret) :
	     "0" (__NR_munmap), "D" (addr), "S" (len) :
	     "rcx", "r11");

	return ret;
}

static __always_inline int
madvise_syscall(void *addr, size_t len, int advice)
{
	long ret;

	asm ("syscall" : "=a" (ret) :
	     "0" (__NR_madvise), "D" (addr), "S" (len), "d" (advice) :
	     "rcx", "r11");

	return ret;
}

#define __vdso_rng_data (VVAR(_vdso_rng_data))

static __always_inline const struct vdso_rng_data *__arch_get_vdso_rng_data(void)
{
	return &__vdso_rng_data;
}

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_VDSO_GETRANDOM_H */
