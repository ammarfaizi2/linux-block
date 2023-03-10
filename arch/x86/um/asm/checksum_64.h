/*
 * Licensed under the GPL
 */

#ifndef __UM_SYSDEP_CHECKSUM_H
#define __UM_SYSDEP_CHECKSUM_H

#define _HAVE_IP_COMPUTE_CSUM

struct in6_addr;

#define _HAVE_ARCH_IPV6_CSUM 1
extern __sum16
csum_ipv6_magic(const struct in6_addr *saddr, const struct in6_addr *daddr,
		__u32 len, __u8 proto, __wsum sum);

#endif
