/* Copyright (C) 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This file is provided under a dual BSD/GPLv2 license.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4 for a secure PRF
 * and HalfSipHash1-3/SipHash1-3 for an insecure PRF only suitable for
 * hashtables.
 */

#ifndef _LINUX_SIPHASH_TYPES_H
#define _LINUX_SIPHASH_TYPES_H

#include <linux/types.h>

#define SIPHASH_ALIGNMENT __alignof__(u64)

typedef struct {
	u64 key[2];
} siphash_key_t;

#define siphash_aligned_key_t siphash_key_t __aligned(16)

#endif /* _LINUX_SIPHASH_TYPES_H */
