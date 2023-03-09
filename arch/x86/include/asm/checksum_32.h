/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CHECKSUM_32_H
#define _ASM_X86_CHECKSUM_32_H

#include <linux/in6.h>
#include <linux/uaccess.h>

/*
 * the same as csum_partial, but copies from src while it
 * checksums, and handles user-space pointer exceptions correctly, when needed.
 *
 * here even more important to align src and dst on a 32-bit (or even
 * better 64-bit) boundary
 */

asmlinkage __wsum csum_partial_copy_generic(const void *src, void *dst, int len);

/*
 *	Note: when you get a NULL pointer exception here this means someone
 *	passed in an incorrect kernel address to one of these functions.
 *
 *	If you use these functions directly please don't forget the
 *	access_ok().
 */
static inline __wsum csum_partial_copy_nocheck(const void *src, void *dst, int len)
{
	return csum_partial_copy_generic(src, dst, len);
}

static inline __wsum csum_and_copy_from_user(const void __user *src,
					     void *dst, int len)
{
	__wsum ret;

	might_sleep();
	if (!user_access_begin(src, len))
		return 0;
	ret = csum_partial_copy_generic((__force void *)src, dst, len);
	user_access_end();

	return ret;
}

#define _HAVE_ARCH_IPV6_CSUM
static inline __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
				      const struct in6_addr *daddr,
				      __u32 len, __u8 proto, __wsum sum)
{
	asm("addl 0(%1), %0	;\n"
	    "adcl 4(%1), %0	;\n"
	    "adcl 8(%1), %0	;\n"
	    "adcl 12(%1), %0	;\n"
	    "adcl 0(%2), %0	;\n"
	    "adcl 4(%2), %0	;\n"
	    "adcl 8(%2), %0	;\n"
	    "adcl 12(%2), %0	;\n"
	    "adcl %3, %0	;\n"
	    "adcl %4, %0	;\n"
	    "adcl $0, %0	;\n"
	    : "=&r" (sum)
	    : "r" (saddr), "r" (daddr),
	      "r" (htonl(len)), "r" (htonl(proto)), "0" (sum)
	    : "memory");

	return csum_fold(sum);
}

/*
 *	Copy and checksum to user
 */
static inline __wsum csum_and_copy_to_user(const void *src,
					   void __user *dst,
					   int len)
{
	__wsum ret;

	might_sleep();
	if (!user_access_begin(dst, len))
		return 0;

	ret = csum_partial_copy_generic(src, (__force void *)dst, len);
	user_access_end();
	return ret;
}

#endif /* _ASM_X86_CHECKSUM_32_H */
