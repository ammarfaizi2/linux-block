// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#include <linux/kernel.h>
#include <linux/types.h>

#include "../../../../lib/vdso/getrandom.c"

ssize_t __vdso_getrandom(void *state, void *buffer, size_t len, unsigned int flags)
{
	return __cvdso_getrandom(state, buffer, len, flags);
}

ssize_t getrandom(void *, void *, size_t, unsigned int)
	__attribute__((weak, alias("__vdso_getrandom")));

void *__vdso_getrandom_alloc(size_t *num, size_t *size_per_each)
{
	return __cvdso_getrandom_alloc(num, size_per_each);
}

void *getrandom_alloc(size_t *, size_t *)
	__attribute__((weak, alias("__vdso_getrandom_alloc")));
