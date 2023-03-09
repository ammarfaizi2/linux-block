/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CHECKSUM_64_H
#define _ASM_X86_CHECKSUM_64_H

/*
 * Checksums for x86-64
 * Copyright 2002 by Andi Kleen, SuSE Labs
 * with some code from asm-x86/checksum.h
 */

#include <linux/compiler.h>
#include <asm/byteorder.h>

/* Do not call this directly. Use the wrappers below */
extern __visible __wsum csum_partial_copy_generic(const void *src, void *dst, int len);

extern __wsum csum_and_copy_from_user(const void __user *src, void *dst, int len);
extern __wsum csum_and_copy_to_user(const void *src, void __user *dst, int len);
extern __wsum csum_partial_copy_nocheck(const void *src, void *dst, int len);

#define _HAVE_IP_COMPUTE_CSUM

/**
 * csum_ipv6_magic - Compute checksum of an IPv6 pseudo header.
 * @saddr: source address
 * @daddr: destination address
 * @len: length of packet
 * @proto: protocol of packet
 * @sum: initial sum (32bit unfolded) to be added in
 *
 * Computes an IPv6 pseudo header checksum. This sum is added the checksum
 * into UDP/TCP packets and contains some link layer information.
 * Returns the unfolded 32bit checksum.
 */

struct in6_addr;

#define _HAVE_ARCH_IPV6_CSUM 1
extern __sum16
csum_ipv6_magic(const struct in6_addr *saddr, const struct in6_addr *daddr,
		__u32 len, __u8 proto, __wsum sum);

#endif /* _ASM_X86_CHECKSUM_64_H */
