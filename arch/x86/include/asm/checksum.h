/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CHECKSUM_H
#define _ASM_X86_CHECKSUM_H
#ifdef CONFIG_GENERIC_CSUM
# include <asm-generic/checksum.h>
#else
# define  _HAVE_ARCH_COPY_AND_CSUM_FROM_USER 1
# define HAVE_CSUM_COPY_USER
# define _HAVE_ARCH_CSUM_AND_COPY

/**
 * csum_fold - Fold and invert a 32bit checksum.
 * sum: 32bit unfolded sum
 *
 * Fold a 32bit running checksum to 16bit and invert it. This is usually
 * the last step before putting a checksum into a packet.
 * Make sure not to mix with 64bit checksums.
 */
static inline __sum16 csum_fold(__wsum sum)
{
	asm("  addl %1,%0\n"
	    "  adcl $0xffff,%0"
	    : "=r" (sum)
	    : "r" ((__force u32)sum << 16),
	      "0" ((__force u32)sum & 0xffff0000));
	return (__force __sum16)(~(__force u32)sum >> 16);
}

# ifdef CONFIG_X86_32
#  include <asm/checksum_32.h>
# else
#  include <asm/checksum_64.h>
# endif
#endif
#endif
