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

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *
 *	By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *	Arnt Gulbrandsen.
 */

/**
 * ip_fast_csum - Compute the IPv4 header checksum efficiently.
 * iph: ipv4 header
 * ihl: length of header / 4
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;

	asm("  movl (%1), %0\n"
	    "  subl $4, %2\n"
	    "  jbe 2f\n"
	    "  addl 4(%1), %0\n"
	    "  adcl 8(%1), %0\n"
	    "  adcl 12(%1), %0\n"
	    "1: adcl 16(%1), %0\n"
	    "  lea 4(%1), %1\n"
	    "  decl %2\n"
	    "  jne	1b\n"
	    "  adcl $0, %0\n"
	    "  movl %0, %2\n"
	    "  shrl $16, %0\n"
	    "  addw %w2, %w0\n"
	    "  adcl $0, %0\n"
	    "  notl %0\n"
	    "2:"
	/* Since the input registers which are loaded with iph and ihl
	   are modified, we must also specify them as outputs, or gcc
	   will assume they contain their original values. */
	    : "=r" (sum), "=r" (iph), "=r" (ihl)
	    : "1" (iph), "2" (ihl)
	    : "memory");
	return (__force __sum16)sum;
}

# ifdef CONFIG_X86_32
#  include <asm/checksum_32.h>
# else
#  include <asm/checksum_64.h>
# endif
#endif
#endif
