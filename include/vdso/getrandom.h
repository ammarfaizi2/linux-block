/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _VDSO_GETRANDOM_H
#define _VDSO_GETRANDOM_H

/**
 * struct vgetrandom_state - State used by vDSO getrandom() and allocated by vgetrandom_alloc().
 *
 * Currently empty, as the vDSO getrandom() function has not yet been implemented.
 */
struct vgetrandom_state { int placeholder; };

#endif /* _VDSO_GETRANDOM_H */
