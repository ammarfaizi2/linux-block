/* Use ISO C++11 intrinsics to implement 16-bit atomic ops.
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _ASM_GENERIC_ISO_ATOMIC16_H
#define _ASM_GENERIC_ISO_ATOMIC16_H

/**
 * atomic_inc_short - increment of a short integer
 * @v: pointer to type int
 *
 * Atomically adds 1 to @v
 * Returns the new value of @v
 */
static __always_inline short int atomic_inc_short(short int *v)
{
	return __atomic_add_fetch(v, 1, __ATOMIC_SEQ_CST);
}

#endif /* _ASM_GENERIC_ISO_ATOMIC16_H */
